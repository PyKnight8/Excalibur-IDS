#!/bin/bash
set -e

SERVICE_USER="excalibur"
APP_DIR="/opt/Excalibur"
DATA_DIR="/var/lib/excalibur"
LOG_DIR="/var/log/excalibur"
SYSTEMD_DIR="/etc/systemd/system"

echo "[*] Setting up Excalibur..."

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run this as root: sudo ./setup.sh"
    exit 1
fi

if id "$SERVICE_USER" >/dev/null 2>&1; then
    echo "[+] User '$SERVICE_USER' already exists"
else
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
fi

mkdir -p "$APP_DIR" "$DATA_DIR" "$LOG_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR" "$DATA_DIR" "$LOG_DIR"

rsync -av --delete \
    --exclude=".git" \
    --exclude=".venv" \
    --exclude="*.sqlite" \
    --exclude="*.sqlite-shm" \
    --exclude="*.sqlite-wal" \
    --exclude="__pycache__" \
    --exclude="*.pyc" \
    ./ \
    "$APP_DIR/"

chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

if [ ! -d "$APP_DIR/.venv" ]; then
    sudo -u "$SERVICE_USER" python3 -m venv "$APP_DIR/.venv"
fi

sudo -u "$SERVICE_USER" "$APP_DIR/.venv/bin/pip" install --upgrade pip
sudo -u "$SERVICE_USER" "$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"

cat > /etc/systemd/system/excalibur-sniffer.service <<EOF
[Unit]
Description=Excalibur Packet Sniffer
After=network.target

[Service]
Type=simple
User=excalibur
Group=excalibur
WorkingDirectory=/opt/Excalibur
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
ExecStart=/opt/Excalibur/.venv/bin/python /opt/Excalibur/excalibur/main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/excalibur-dashboard.service <<EOF
[Unit]
Description=Excalibur Dashboard
After=network.target

[Service]
Type=simple
User=excalibur
Group=excalibur
WorkingDirectory=/opt/Excalibur
NoNewPrivileges=true
ExecStart=/opt/Excalibur/.venv/bin/python -m flask --app excalibur/dashboard/app.py run --host=127.0.0.1 --port=5000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

install -m 0644 systemd/excalibur-helper.service "$SYSTEMD_DIR/excalibur-helper.service"

systemctl daemon-reload
systemctl enable excalibur-sniffer excalibur-dashboard excalibur-helper
systemctl restart excalibur-helper excalibur-sniffer excalibur-dashboard

echo "[+] Setup complete."
