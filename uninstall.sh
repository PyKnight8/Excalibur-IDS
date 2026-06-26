#!/bin/bash
set -e

SERVICE_USER="excalibur"
APP_DIR="/opt/Excalibur"
DATA_DIR="/var/lib/excalibur"
LOG_DIR="/var/log/excalibur"
SYSTEMD_DIR="/etc/systemd/system"

echo "[*] Uninstalling Excalibur..."

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run this as root: sudo ./uninstall.sh"
    exit 1
fi

echo
read -rp "Create backup before uninstall? [Y/n]: " BACKUP

if [[ ! "$BACKUP" =~ ^[Nn]$ ]]; then
    BACKUP_FILE="excalibur-backup-$(date +%Y%m%d-%H%M%S).tar.gz"

    echo "[*] Creating backup: $BACKUP_FILE"

    tar -czf "$BACKUP_FILE" \
        "$APP_DIR" \
        "$DATA_DIR" \
        "$LOG_DIR" \
        2>/dev/null || true

    echo "[+] Backup saved to: $BACKUP_FILE"
fi

echo "[*] Stopping services..."

systemctl stop excalibur-sniffer.service 2>/dev/null || true
systemctl stop excalibur-dashboard.service 2>/dev/null || true
systemctl stop excalibur-helper.service 2>/dev/null || true

echo "[*] Disabling services..."

systemctl disable excalibur-sniffer.service 2>/dev/null || true
systemctl disable excalibur-dashboard.service 2>/dev/null || true
systemctl disable excalibur-helper.service 2>/dev/null || true

echo "[*] Removing service files..."

rm -f "$SYSTEMD_DIR/excalibur-sniffer.service"
rm -f "$SYSTEMD_DIR/excalibur-dashboard.service"
rm -f "$SYSTEMD_DIR/excalibur-helper.service"

systemctl daemon-reload

echo "[*] Removing application files..."

rm -rf "$APP_DIR"

echo "[*] Removing data..."

rm -rf "$DATA_DIR"
rm -rf "$LOG_DIR"

if id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "[*] Removing service user..."
    userdel "$SERVICE_USER" || true
fi

echo
echo "[+] Excalibur has been successfully removed."