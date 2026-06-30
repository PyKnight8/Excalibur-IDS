#!/bin/bash
set -e

APP_DIR="/opt/Excalibur"
SYSTEMD_DIR="/etc/systemd/system"
POLKIT_ACTIONS_DIR="/usr/share/polkit-1/actions"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run as root: sudo ./update.sh"
    exit 1
fi

echo "[*] Installing Excalibur helper service..."

if [ ! -f "$APP_DIR/systemd/excalibur-helper.service" ]; then
    echo "[ERROR] Missing $APP_DIR/systemd/excalibur-helper.service"
    exit 1
fi

cp "$APP_DIR/systemd/excalibur-helper.service" \
    "$SYSTEMD_DIR/excalibur-helper.service"

if [ ! -f "$APP_DIR/polkit/org.excalibur.sensor.policy" ]; then
    echo "[ERROR] Missing $APP_DIR/polkit/org.excalibur.sensor.policy"
    exit 1
fi

install -d "$POLKIT_ACTIONS_DIR"
cp "$APP_DIR/polkit/org.excalibur.sensor.policy" \
    "$POLKIT_ACTIONS_DIR/org.excalibur.sensor.policy"

systemctl daemon-reload

systemctl enable excalibur-helper.service
systemctl restart excalibur-helper.service

echo
echo "[+] Helper service installed."
echo

systemctl status excalibur-helper.service --no-pager
