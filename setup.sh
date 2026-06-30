#!/bin/bash
set -e

SERVICE_USER="excalibur"
APP_DIR="/opt/Excalibur"
DATA_DIR="/var/lib/excalibur"
LOG_DIR="/var/log/excalibur"
SYSTEMD_DIR="/etc/systemd/system"
POLKIT_ACTIONS_DIR="/usr/share/polkit-1/actions"
TRAY_AUTOSTART_FILE="excalibur-tray.desktop"

desktop_user=""
desktop_user_home=""
desktop_user_uid=""

resolve_desktop_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && id "$SUDO_USER" >/dev/null 2>&1; then
        desktop_user="$SUDO_USER"
        desktop_user_home="$(getent passwd "$desktop_user" | cut -d: -f6)"
        desktop_user_uid="$(id -u "$desktop_user")"
    fi
}

has_desktop_indicators() {
    [ -n "${DISPLAY:-}" ] \
        || [ -n "${WAYLAND_DISPLAY:-}" ] \
        || [ -n "${XDG_CURRENT_DESKTOP:-}" ] \
        || [ -n "${DESKTOP_SESSION:-}" ]
}

desktop_environment_detected() {
    if [ -z "$desktop_user" ] || [ -z "$desktop_user_home" ]; then
        return 1
    fi
    if has_desktop_indicators; then
        return 0
    fi
    if [ -d "$desktop_user_home/.config/autostart" ]; then
        return 0
    fi
    return 1
}

install_tray_autostart() {
    local autostart_dir="$desktop_user_home/.config/autostart"
    local autostart_path="$autostart_dir/$TRAY_AUTOSTART_FILE"

    echo "[+] Desktop environment detected."
    echo "[+] Installing Excalibur System Tray."
    mkdir -p "$autostart_dir"
    cat > "$autostart_path" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=Excalibur Tray
Comment=Excalibur System Tray Controller
Exec=/bin/bash $APP_DIR/scripts/linux/run-tray.sh
Icon=$APP_DIR/assets/Excalibur.png
Terminal=false
Categories=Network;Security;
X-GNOME-Autostart-enabled=true
EOF
    chown "$desktop_user:$desktop_user" "$autostart_path"
    echo "[+] Configuring tray auto-start."

    if has_desktop_indicators; then
        local runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$desktop_user_uid}"
        local dbus_address="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$runtime_dir/bus}"
        echo "[+] Launching Excalibur System Tray."
        sudo -u "$desktop_user" env \
            DISPLAY="${DISPLAY:-}" \
            WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
            XDG_CURRENT_DESKTOP="${XDG_CURRENT_DESKTOP:-}" \
            DESKTOP_SESSION="${DESKTOP_SESSION:-}" \
            XDG_SESSION_TYPE="${XDG_SESSION_TYPE:-}" \
            XDG_RUNTIME_DIR="$runtime_dir" \
            DBUS_SESSION_BUS_ADDRESS="$dbus_address" \
            /bin/bash "$APP_DIR/scripts/linux/run-tray.sh" >/dev/null 2>&1 &
    else
        echo "[+] Desktop auto-start configured. Tray launch will begin on next login."
    fi
}

ensure_desktop_user_helper_access() {
    if [ -z "$desktop_user" ]; then
        return
    fi
    if id -nG "$desktop_user" | tr ' ' '\n' | grep -qx "$SERVICE_USER"; then
        return
    fi
    echo "[+] Granting $desktop_user access to the Excalibur tray helper group."
    usermod -a -G "$SERVICE_USER" "$desktop_user"
}

echo "[*] Setting up Excalibur..."

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run this as root: sudo ./setup.sh"
    exit 1
fi

resolve_desktop_user

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
install -d "$POLKIT_ACTIONS_DIR"
install -m 0644 polkit/org.excalibur.sensor.policy \
    "$POLKIT_ACTIONS_DIR/org.excalibur.sensor.policy"

systemctl daemon-reload
systemctl enable excalibur-sniffer excalibur-dashboard excalibur-helper
systemctl restart excalibur-helper excalibur-sniffer excalibur-dashboard

if desktop_environment_detected; then
    ensure_desktop_user_helper_access
    install_tray_autostart
else
    echo "[+] Headless/server installation detected."
    echo "[+] Skipping system tray installation."
fi

echo "[+] Setup complete."
