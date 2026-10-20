#!/usr/bin/env bash
set -Eeuo pipefail

# One-file installer: creates the Python monitor, config, and systemd service.
SERVICE_NAME="login-monitor"
INSTALL_DIR="/opt/login-monitor"
PYTHON_PATH="${INSTALL_DIR}/login_monitor.py"
CONFIG_PATH="${INSTALL_DIR}/config.json"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Jalankan sebagai root: sudo bash login-monitor.sh"
  exit 1
fi

echo "=== Login Monitor VPS -> Telegram ==="
read -r -s -p "Telegram Bot Token: " BOT_TOKEN
printf '\n'
read -r -p "Chat ID / Group ID: " CHAT_ID
read -r -p "Topic ID (kosongkan jika tanpa topic): " TOPIC_ID

if [[ -z "${BOT_TOKEN}" || -z "${CHAT_ID}" ]]; then
  echo "Bot Token dan Chat ID wajib diisi."
  exit 1
fi
if [[ ! "${CHAT_ID}" =~ ^-?[0-9]+$ ]]; then
  echo "Chat ID harus berupa angka (contoh grup: -1001234567890)."
  exit 1
fi
if [[ -n "${TOPIC_ID}" && ! "${TOPIC_ID}" =~ ^[0-9]+$ ]]; then
  echo "Topic ID harus berupa angka atau dikosongkan."
  exit 1
fi

# Skip APT when runtime dependencies already exist. This prevents unrelated
# broken desktop-package dependencies from blocking installation on VPS.
export DEBIAN_FRONTEND=noninteractive
NEED_APT=0
command -v python3 >/dev/null 2>&1 || NEED_APT=1
python3 -c 'import venv' >/dev/null 2>&1 || NEED_APT=1
[[ -r /etc/ssl/certs/ca-certificates.crt ]] || NEED_APT=1

if [[ "${NEED_APT}" -eq 1 ]]; then
  echo "[INFO] Python/venv/CA certificate belum lengkap; mencoba memasang dependency..."
  apt-get update
  if ! apt-get install -y python3 python3-venv ca-certificates; then
    echo
    echo "[ERROR] APT gagal memasang dependency."
    echo "Perbaiki dependency Ubuntu terlebih dahulu dengan:"
    echo "  dpkg --configure -a"
    echo "  apt --fix-broken install"
    exit 1
  fi
else
  echo "[INFO] Python3, venv, dan CA certificates tersedia; melewati APT."
fi

install -d -m 0750 "${INSTALL_DIR}"
if [[ -f "${PYTHON_PATH}" ]]; then
  cp -a "${PYTHON_PATH}" "${PYTHON_PATH}.bak.$(date +%Y%m%d-%H%M%S)"
fi
if [[ -f "${CONFIG_PATH}" ]]; then
  cp -a "${CONFIG_PATH}" "${CONFIG_PATH}.bak.$(date +%Y%m%d-%H%M%S)"
fi

cat > "${PYTHON_PATH}" <<'PYTHON_EOF'
#!/usr/bin/env python3
"""Monitor SSH authentication and sudo events; notify Telegram."""
import os
import re
import time
import json
import html
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

BASE_DIR = Path("/opt/login-monitor")
CONFIG_FILE = BASE_DIR / "config.json"
POSITION_FILE = BASE_DIR / ".log_position"
AUTH_LOG = "/var/log/auth.log"
POLL_INTERVAL = 2


def load_config():
    with CONFIG_FILE.open(encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["bot_token"] = str(cfg.get("bot_token", "")).strip()
    cfg["chat_id"] = str(cfg.get("chat_id", "")).strip()
    topic = str(cfg.get("topic_id", "")).strip()
    cfg["topic_id"] = topic or None
    if not cfg["bot_token"] or not cfg["chat_id"]:
        raise ValueError("bot_token dan chat_id wajib diisi di config.json")
    return cfg


CONFIG = load_config()


def send_telegram(message):
    payload = {
        "chat_id": CONFIG["chat_id"],
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if CONFIG["topic_id"] is not None:
        payload["message_thread_id"] = int(CONFIG["topic_id"])
    url = f"https://api.telegram.org/bot{CONFIG['bot_token']}/sendMessage"
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode())
        if not result.get("ok"):
            print(f"[TELEGRAM ERR] {result}", flush=True)
        return result
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        print(f"[TELEGRAM ERR] {exc}", flush=True)
        return None


def parse_line(line):
    result = {"timestamp": None, "event_type": None}
    match = re.match(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if match:
        result["timestamp"] = f"{datetime.now().year}-{match.group(1)}"

    if "Failed password" in line:
        user_match = re.search(r"for\s+(?:invalid user\s+)?(\S+)", line)
        ip_match = re.search(r"from\s+(\S+)", line)
        port_match = re.search(r"port\s+(\d+)", line)
        user = user_match.group(1) if user_match else "?"
        if "for invalid user" in line:
            user = f"INVALID: {user}"
        result.update(event_type="failed", service="SSH", user=user,
                      ip=ip_match.group(1) if ip_match else "?",
                      port=port_match.group(1) if port_match else "?")
        return result

    if "Accepted" in line and "sshd" in line.lower():
        user_match = re.search(r"for\s+(\S+)", line)
        ip_match = re.search(r"from\s+(\S+)", line)
        port_match = re.search(r"port\s+(\d+)", line)
        method_match = re.search(r"Accepted\s+(\S+)", line)
        result.update(event_type="success", service="SSH",
                      user=user_match.group(1) if user_match else "?",
                      ip=ip_match.group(1) if ip_match else "?",
                      port=port_match.group(1) if port_match else "?",
                      method=method_match.group(1) if method_match else "?")
        return result

    if "sudo" in line and "COMMAND=" in line:
        user_match = re.search(r"\b(\w+)\s*:", line)
        cmd_match = re.search(r"COMMAND=(.*)", line)
        result.update(event_type="sudo", service="SUDO",
                      user=user_match.group(1) if user_match else "?",
                      command=cmd_match.group(1) if cmd_match else "?")
        return result

    if re.search(r"\bsu\b", line) and any(
        item in line for item in ("session opened", "session closed", "FAILED", "SUCCESS")
    ):
        user_match = re.search(r"by\s+(\S+)", line)
        result.update(event_type="su", service="SU",
                      user=user_match.group(1) if user_match else "?")
        return result
    return None


def safe(value, limit=200):
    return html.escape(str(value if value is not None else "?")[:limit])


def format_message(event):
    ts = safe(event.get("timestamp", "???"), 50)
    user = safe(event.get("user", "?"), 100)
    kind = event["event_type"]
    if kind == "failed":
        return (f"🚫 <b>SSH Login Failed</b>\n└ User: <code>{user}</code>\n"
                f"└ IP: <code>{safe(event.get('ip'))}</code>  Port: {safe(event.get('port'))}\n"
                f"└ Time: {ts}")
    if kind == "success":
        return (f"✅ <b>SSH Login Success</b>\n└ User: <code>{user}</code>\n"
                f"└ IP: <code>{safe(event.get('ip'))}</code>  Port: {safe(event.get('port'))}\n"
                f"└ Method: {safe(event.get('method'))}\n└ Time: {ts}")
    if kind == "sudo":
        return (f"⚡ <b>SUDO Command</b>\n└ User: <code>{user}</code>\n"
                f"└ Cmd: <code>{safe(event.get('command'))}</code>\n└ Time: {ts}")
    if kind == "su":
        return (f"🔐 <b>SU Access</b>\n└ User: <code>{user}</code>\n"
                f"└ Service: <code>SU</code>\n└ Time: {ts}")
    return None


def get_position():
    try:
        return int(POSITION_FILE.read_text().strip())
    except (OSError, ValueError):
        return 0


def save_position(position):
    POSITION_FILE.write_text(str(position))


def tail_log():
    last_pos = get_position()
    try:
        size = os.path.getsize(AUTH_LOG)
    except OSError:
        size = 0

    if last_pos == 0 or last_pos > size:
        try:
            with open(AUTH_LOG, "rb") as log_file:
                log_file.seek(0, os.SEEK_END)
                last_pos = log_file.tell()
            save_position(last_pos)
            send_telegram(
                "🟢 <b>Login Monitor Started</b>\n"
                f"└ Memantau: <code>{AUTH_LOG}</code>\n"
                "└ Event lama tidak dikirim ulang\n"
                f"└ Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            print(f"[INIT] Started at byte position {last_pos}", flush=True)
        except Exception as exc:
            print(f"[INIT ERR] {exc}", flush=True)
            last_pos = 0

    while True:
        try:
            size = os.path.getsize(AUTH_LOG)
            if size < last_pos:
                print("[INFO] Log rotated/truncated; resetting position", flush=True)
                last_pos = 0
            if size > last_pos:
                with open(AUTH_LOG, "rb") as log_file:
                    log_file.seek(last_pos)
                    data = log_file.read()
                    last_pos = log_file.tell()
                for line in data.decode("utf-8", errors="replace").splitlines():
                    event = parse_line(line)
                    if event:
                        message = format_message(event)
                        if message:
                            print(f"[EVENT] {event['event_type']} user={event.get('user', '?')}", flush=True)
                            send_telegram(message)
                            time.sleep(0.5)
                save_position(last_pos)
        except FileNotFoundError:
            print(f"[WARN] {AUTH_LOG} not found; waiting...", flush=True)
            time.sleep(5)
            continue
        except Exception as exc:
            print(f"[ERR] {exc}", flush=True)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    print("Login Monitor starting...", flush=True)
    tail_log()
PYTHON_EOF

export BOT_TOKEN CHAT_ID TOPIC_ID CONFIG_PATH
python3 - <<'PYCONFIG'
import json, os
config = {
    "bot_token": os.environ["BOT_TOKEN"],
    "chat_id": os.environ["CHAT_ID"],
    "topic_id": os.environ["TOPIC_ID"],
}
with open(os.environ["CONFIG_PATH"], "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
os.chmod(os.environ["CONFIG_PATH"], 0o600)
PYCONFIG
unset BOT_TOKEN CHAT_ID TOPIC_ID

chmod 0750 "${PYTHON_PATH}"
if [[ ! -x "${INSTALL_DIR}/venv/bin/python" ]]; then
  python3 -m venv "${INSTALL_DIR}/venv"
fi
"${INSTALL_DIR}/venv/bin/python" -m py_compile "${PYTHON_PATH}"

cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=Login Monitor Telegram Notifications
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python -u ${PYTHON_PATH}
Restart=always
RestartSec=3
KillSignal=SIGTERM
TimeoutStopSec=10
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "${SERVICE_PATH}"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}" 2>/dev/null || systemctl start "${SERVICE_NAME}"

echo
echo "=== Setup selesai ==="
echo "Python  : ${PYTHON_PATH} (dibuat otomatis)"
echo "Config  : ${CONFIG_PATH} (permission 600)"
echo "Service : ${SERVICE_NAME}"
echo
systemctl --no-pager --full status "${SERVICE_NAME}" || true
echo
echo "Perintah:"
echo "  systemctl status ${SERVICE_NAME}"
echo "  journalctl -u ${SERVICE_NAME} -f"
echo "  systemctl restart ${SERVICE_NAME}"
echo "  nano ${CONFIG_PATH}  # edit config, lalu restart service"
