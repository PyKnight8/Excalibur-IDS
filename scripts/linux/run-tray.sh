#!/bin/bash
set -e

APP_DIR="/opt/Excalibur"
VENV_PYTHON="$APP_DIR/.venv/bin/python"
SYSTEM_PYTHON="${PYTHON:-python3}"

cd "$APP_DIR"

is_wayland() {
    [ "${XDG_SESSION_TYPE:-}" = "wayland" ] || [ -n "${WAYLAND_DISPLAY:-}" ]
}

system_python_supports_gi() {
    "$SYSTEM_PYTHON" -c "import gi" >/dev/null 2>&1
}

if is_wayland && system_python_supports_gi; then
    exec env PYTHONPATH="$APP_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$SYSTEM_PYTHON" -m excalibur.tray.app
fi

exec "$VENV_PYTHON" -m excalibur.tray.app
