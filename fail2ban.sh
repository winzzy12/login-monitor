#!/usr/bin/env bash
set -Eeuo pipefail

# Fail2ban setup for Ubuntu/Debian. Safe to run more than once.
# Run: sudo bash setup.sh

if [[ "${EUID}" -ne 0 ]]; then
  echo "Jalankan sebagai root: sudo bash setup.sh"
  exit 1
fi

echo "[1/5] Memperbarui daftar paket..."
export DEBIAN_FRONTEND=noninteractive
apt-get update

echo "[2/5] Menginstal Fail2ban..."
apt-get install -y fail2ban

echo "[3/5] Membuat konfigurasi SSH jail..."
install -d -m 0755 /etc/fail2ban/jail.d

cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF

echo "[4/5] Memvalidasi konfigurasi..."
fail2ban-client -t

echo "[5/5] Mengaktifkan Fail2ban saat boot dan sekarang..."
systemctl enable fail2ban
systemctl restart fail2ban
systemctl --no-pager --full status fail2ban

echo
echo "=== Status jail SSH ==="
fail2ban-client status sshd

echo
echo "Selesai. Fail2ban telah diaktifkan agar berjalan otomatis setiap reboot."
echo "Konfigurasi: /etc/fail2ban/jail.d/sshd.local"
echo "Periksa nanti dengan: sudo fail2ban-client status sshd"
echo "Catatan: pastikan SSH tetap dapat diakses sebelum mengubah aturan firewall."
