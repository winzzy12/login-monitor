#!/usr/bin/env python3
"""
Login Monitor VPS — Kirim notifikasi login berhasil & gagal ke Telegram.
Tails /var/log/auth.log dan parse event SSH, sudo, login lokal.
"""

import os
import re
import time
import json
import sys
import subprocess
from datetime import datetime, timezone, timedelta

# === CONFIG ===
BOT_TOKEN = "BOT_TOKEN"
CHAT_ID = "ID_CHAT"
TOPIC_ID = TOPIC_ID  # message_thread_id
AUTH_LOG = "/var/log/auth.log"
POLL_INTERVAL = 2  # detik
INITIAL_BACKLOG = 30  # baca N baris terakhir saat start
TZ_OFFSET = timedelta(hours=7)  # WIB

# === TELEGRAM SEND ===
def send_telegram(text, parse_mode="HTML"):
    """Kirim pesan ke Telegram topic."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": parse_mode,
        "message_thread_id": TOPIC_ID,
        "disable_web_page_preview": True,
    }
    try:
        import urllib.request
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data,
            headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except Exception as e:
        print(f"[TELEGRAM ERR] {e}", flush=True)
        return None

# === PARSER ===
def parse_line(line):
    """Parse satu baris auth.log. Return dict atau None."""
    # Format umum syslog: "Mon DD HH:MM:SS hostname sshd[...]: ..."
    # Kita ekstrak timestamp dari baris

    result = {
        "raw": line.rstrip(),
        "timestamp": None,
        "event_type": None,  # "success", "failed", "sudo", "other"
    }

    # Ambil timestamp dari 3 kolom pertama (Mon DD HH:MM:SS)
    m = re.match(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if m:
        year = datetime.now().year
        result["timestamp"] = f"{year}-{m.group(1)}"

    # --- SSH Failed Password ---
    if "Failed password" in line:
        m_user = re.search(r"for\s+(\S+)", line)
        m_ip = re.search(r"from\s+(\S+)", line)
        m_port = re.search(r"port\s+(\d+)", line)
        result["event_type"] = "failed"
        result["service"] = "SSH"
        result["user"] = m_user.group(1) if m_user else "?"
        result["ip"] = m_ip.group(1) if m_ip else "?"
        result["port"] = m_port.group(1) if m_port else "?"
        return result

    # --- SSH Failed with invalid user ---
    if "Failed password for invalid user" in line:
        m_user = re.search(r"invalid user\s+(\S+)", line)
        m_ip = re.search(r"from\s+(\S+)", line)
        m_port = re.search(r"port\s+(\d+)", line)
        result["event_type"] = "failed"
        result["service"] = "SSH"
        result["user"] = f"INVALID: {m_user.group(1) if m_user else '?'}"
        result["ip"] = m_ip.group(1) if m_ip else "?"
        result["port"] = m_port.group(1) if m_port else "?"
        return result

    # --- SSH Accepted (publickey / password) ---
    if "Accepted" in line and ("sshd" in line.lower() or "ssh" in line.lower()):
        m_user = re.search(r"for\s+(\S+)", line)
        m_ip = re.search(r"from\s+(\S+)", line)
        m_port = re.search(r"port\s+(\d+)", line)
        m_method = re.search(r"Accepted\s+(\S+)", line)
        result["event_type"] = "success"
        result["service"] = "SSH"
        result["user"] = m_user.group(1) if m_user else "?"
        result["ip"] = m_ip.group(1) if m_ip else "?"
        result["port"] = m_port.group(1) if m_port else "?"
        result["method"] = m_method.group(1) if m_method else "?"
        return result

    # --- sudo ---
    if "sudo" in line and "COMMAND=" in line:
        m_user = re.search(r"(\w+)\s*:", line)
        m_cmd = re.search(r"COMMAND=(.*)", line)
        result["event_type"] = "sudo"
        result["service"] = "SUDO"
        result["user"] = m_user.group(1) if m_user else "?"
        result["command"] = m_cmd.group(1) if m_cmd else "?"
        return result

    # --- su (switch user) ---
    if re.search(r"\bsu\b", line) and ("session opened" in line or "session closed" in line or "FAILED" in line or "SUCCESS" in line):
        result["event_type"] = "sudo"  # kelompokkan dengan sudo
        result["service"] = "SU"
        m_user = re.search(r"by\s+(\S+)", line)
        result["user"] = m_user.group(1) if m_user else "?"
        return result

    # --- login (local TTY) ---
    if "login" in line and ("session opened" in line or "session closed" in line):
        m_user = re.search(r"by\s+(\S+)", line)
        result["event_type"] = "other"
        result["service"] = "LOGIN"
        result["user"] = m_user.group(1) if m_user else "?"
        return result

    return None


def format_message(event):
    """Buat HTML message untuk Telegram."""
    ts = event.get("timestamp", "???")
    etype = event["event_type"]

    if etype == "failed":
        return (
            f"🚫 <b>SSH Login Failed</b>\n"
            f"└ User: <code>{event.get('user', '?')}</code>\n"
            f"└ IP: <code>{event.get('ip', '?')}</code>"
            f"  Port: {event.get('port', '?')}\n"
            f"└ Time: {ts}"
        )

    elif etype == "success":
        return (
            f"✅ <b>SSH Login Success</b>\n"
            f"└ User: <code>{event.get('user', '?')}</code>\n"
            f"└ IP: <code>{event.get('ip', '?')}</code>"
            f"  Port: {event.get('port', '?')}\n"
            f"└ Method: {event.get('method', '?')}\n"
            f"└ Time: {ts}"
        )

    elif etype == "sudo":
        cmd = event.get('command', '')
        if cmd:
            return (
                f"⚡ <b>SUDO Command</b>\n"
                f"└ User: <code>{event.get('user', '?')}</code>\n"
                f"└ Cmd: <code>{cmd[:200]}</code>\n"
                f"└ Time: {ts}"
            )
        else:
            return (
                f"🔐 <b>SU Access</b>\n"
                f"└ User: <code>{event.get('user', '?')}</code>\n"
                f"└ Service: {event.get('service', '?')}\n"
                f"└ Time: {ts}"
            )

    elif etype == "other":
        return (
            f"ℹ️ <b>Login Event</b>\n"
            f"└ User: <code>{event.get('user', '?')}</code>\n"
            f"└ Service: {event.get('service', '?')}\n"
            f"└ Time: {ts}"
        )

    return None


def get_log_position():
    """Dapatkan posisi terakhir yang sudah diproses dari file marker."""
    marker = "/root/login-monitor/.log_position"
    try:
        with open(marker) as f:
            return int(f.read().strip())
    except:
        return 0


def save_log_position(pos):
    """Simpan posisi terakhir yang sudah diproses."""
    marker = "/root/login-monitor/.log_position"
    with open(marker, "w") as f:
        f.write(str(pos))


def tail_log():
    """Main loop: tail auth.log dan kirim notifikasi."""
    marker_file = "/root/login-monitor/.log_position"
    last_pos = get_log_position()

    # Kalau file baru atau posisi tidak valid, ambil backlog N baris terakhir
    try:
        current_size = os.path.getsize(AUTH_LOG)
    except:
        current_size = 0

    if last_pos == 0 or last_pos > current_size:
        # Baca N baris terakhir sebagai backlog
        try:
            with open(AUTH_LOG) as f:
                lines = f.readlines()
                backlog = lines[-INITIAL_BACKLOG:] if len(lines) > INITIAL_BACKLOG else lines
                for line in backlog:
                    event = parse_line(line)
                    if event:
                        msg = format_message(event)
                        if msg:
                            print(f"[BACKLOG] {event['event_type']} - {event.get('user','?')}", flush=True)
                            # Kirim backlog sebagai satu pesan grup
                last_pos = sum(len(l) for l in lines)
                save_log_position(last_pos)
                # Kirim notifikasi bahwa monitor sudah mulai
                send_telegram(
                    f"🟢 <b>Login Monitor Started</b>\n"
                    f"└ Memantau: {AUTH_LOG}\n"
                    f"└ Backlog: {len(backlog)} baris diproses\n"
                    f"└ Waktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} WIB"
                )
                print(f"[INIT] Started. Position={last_pos}, backlog={len(backlog)} lines", flush=True)
        except Exception as e:
            print(f"[INIT ERR] {e}", flush=True)
            last_pos = 0

    # Continuous tail
    while True:
        try:
            current_size = os.path.getsize(AUTH_LOG)
            if current_size < last_pos:
                # File dirotasi
                print("[INFO] Log rotated, resetting position", flush=True)
                last_pos = 0

            if current_size > last_pos:
                with open(AUTH_LOG) as f:
                    f.seek(last_pos)
                    new_data = f.read()
                    last_pos = f.tell()

                for line in new_data.splitlines():
                    if not line.strip():
                        continue
                    event = parse_line(line)
                    if event:
                        msg = format_message(event)
                        if msg:
                            print(f"[EVENT] {event['event_type']} - {event.get('user','?')}",
                                  flush=True)
                            send_telegram(msg)
                            time.sleep(0.5)  # anti rate limit

                save_log_position(last_pos)

        except FileNotFoundError:
            print(f"[WARN] {AUTH_LOG} not found, waiting...", flush=True)
            last_pos = 0
            time.sleep(5)
            continue
        except Exception as e:
            print(f"[ERR] {e}", flush=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    # Pastikan direktori ada
    os.makedirs("/root/login-monitor", exist_ok=True)
    print("Starting Login Monitor...", flush=True)
    tail_log()
