from pathlib import Path
from threading import Event, Lock, Thread
import os
import platform
import sys
import traceback
import webbrowser

from excalibur.services.service_controller import (
    ServiceControllerError,
    create_service_controller,
)


DEFAULT_DASHBOARD_URL = "http://127.0.0.1:5000"
DEFAULT_STATUS_POLL_SECONDS = 15


def running_on_windows():
    return platform.system().lower() == "windows"


def running_on_wayland():
    session_type = os.environ.get("XDG_SESSION_TYPE", "").lower()
    if session_type == "wayland":
        return True
    return bool(os.environ.get("WAYLAND_DISPLAY"))


def running_on_x11():
    session_type = os.environ.get("XDG_SESSION_TYPE", "").lower()
    if session_type == "x11":
        return True
    return bool(os.environ.get("DISPLAY")) and not running_on_wayland()


def _tray_log(message):
    print(f"[Tray] {message}", file=sys.stderr, flush=True)


def _current_session_label():
    if running_on_windows():
        return "Windows"
    if running_on_wayland():
        return "Wayland"
    if running_on_x11():
        return "X11"
    return "Unknown"


def _icon_asset_path():
    return Path(__file__).resolve().parents[2] / "assets" / "Excalibur.png"


class TrayController:
    def __init__(
        self,
        service_controller=None,
        dashboard_url=DEFAULT_DASHBOARD_URL,
        browser_opener=None,
        status_poll_seconds=DEFAULT_STATUS_POLL_SECONDS,
    ):
        self.service_controller = service_controller or create_service_controller()
        self.dashboard_url = dashboard_url
        self.browser_opener = browser_opener or webbrowser.open
        self.status_poll_seconds = status_poll_seconds
        self._icon = None
        self._lock = Lock()
        self._poll_thread = None
        self._stop_event = Event()
        self._status = "unknown"
        self._last_error = None
        self._last_notice = "Ready"

    @property
    def status(self):
        with self._lock:
            return self._status

    @property
    def last_error(self):
        with self._lock:
            return self._last_error

    @property
    def last_notice(self):
        with self._lock:
            return self._last_notice

    @property
    def status_label(self):
        mapping = {
            "running": "Running",
            "stopped": "Stopped",
            "starting": "Starting",
            "error": "Error",
        }
        return f"Sensor Status: {mapping.get(self.status, 'Unknown')}"

    @property
    def detail_label(self):
        return f"Last Result: {self.last_notice}"

    def attach_icon(self, icon):
        self._icon = icon

    def open_dashboard(self):
        self.browser_opener(self.dashboard_url)
        return True

    def start_sensor(self):
        return self._perform_action(self.service_controller.start, "Sensor started.")

    def stop_sensor(self):
        return self._perform_action(self.service_controller.stop, "Sensor stopped.")

    def restart_sensor(self):
        return self._perform_action(
            self.service_controller.restart,
            "Sensor restarted.",
        )

    def refresh_status(self):
        try:
            status = self.service_controller.status() or "unknown"
            self._set_state(status, None)
        except ServiceControllerError as exc:
            self._set_state("error", str(exc))
        return self.status

    def start_polling(self):
        if self._poll_thread is not None and self._poll_thread.is_alive():
            return
        self._stop_event.clear()
        self._poll_thread = Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop_polling(self):
        self._stop_event.set()

    def exit_app(self, icon=None):
        self.stop_polling()
        target_icon = icon or self._icon
        if target_icon is not None:
            target_icon.stop()

    def _perform_action(self, action, success_message):
        try:
            action()
        except ServiceControllerError as exc:
            self._set_notice(str(exc), is_error=True)
            return False
        self._set_notice(success_message, is_error=False)
        self.refresh_status()
        return True

    def _poll_loop(self):
        while not self._stop_event.is_set():
            self.refresh_status()
            self._stop_event.wait(self.status_poll_seconds)

    def _set_state(self, status, error_message):
        with self._lock:
            self._status = status
            self._last_error = error_message
            if error_message:
                self._last_notice = error_message
        if self._icon is not None:
            self._icon.update_menu()

    def _set_notice(self, message, is_error=False):
        with self._lock:
            self._last_notice = message
            self._last_error = message if is_error else None
        if self._icon is not None:
            self._icon.update_menu()


def _load_tray_dependencies():
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError as exc:
        raise RuntimeError(
            "Tray support requires pystray and Pillow. Install requirements.txt first."
        ) from exc
    return pystray, Image, ImageDraw


def _load_appindicator_dependencies():
    try:
        import gi

        gi.require_version("Gtk", "3.0")
        try:
            gi.require_version("AyatanaAppIndicator3", "0.1")
            from gi.repository import AyatanaAppIndicator3 as AppIndicator3
        except (ImportError, ValueError):
            gi.require_version("AppIndicator3", "0.1")
            from gi.repository import AppIndicator3
        from gi.repository import GLib, Gtk
    except (ImportError, ValueError) as exc:
        raise RuntimeError(
            "Wayland tray support requires PyGObject with AyatanaAppIndicator3/AppIndicator3."
        ) from exc
    return AppIndicator3, GLib, Gtk


def _log_capability_success(message):
    _tray_log(f"[OK] {message}")


def _log_capability_failure(message, exc):
    _tray_log(f"[FAILED] {message}:")
    _tray_log(f"{type(exc).__name__}: {exc}")
    _tray_log(traceback.format_exc().rstrip())


def appindicator_supported(log_diagnostics=False):
    if log_diagnostics:
        _tray_log("Checking native Wayland backend...")
    try:
        import gi

        if log_diagnostics:
            _log_capability_success("gi imported")
    except Exception as exc:
        if log_diagnostics:
            _log_capability_failure("gi import", exc)
        return False, "gi import failed"

    try:
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk

        if log_diagnostics:
            _log_capability_success("GTK imported")
    except Exception as exc:
        if log_diagnostics:
            _log_capability_failure("Gtk import", exc)
        return False, "Gtk import failed"

    try:
        gi.require_version("AyatanaAppIndicator3", "0.1")
        from gi.repository import AyatanaAppIndicator3  # noqa: F401

        if log_diagnostics:
            _log_capability_success("AyatanaAppIndicator3 imported")
    except Exception as ayatana_exc:
        if log_diagnostics:
            _log_capability_failure("AyatanaAppIndicator3 import", ayatana_exc)
            _tray_log("Attempting AppIndicator3 import fallback...")
        try:
            gi.require_version("AppIndicator3", "0.1")
            from gi.repository import AppIndicator3  # noqa: F401

            if log_diagnostics:
                _log_capability_success("AppIndicator3 imported")
        except Exception as appindicator_exc:
            if log_diagnostics:
                _log_capability_failure("AppIndicator3 import", appindicator_exc)
            return False, "No supported AppIndicator binding available"

    try:
        _load_appindicator_dependencies()
        if log_diagnostics:
            _log_capability_success("Native Wayland dependencies resolved")
    except Exception as exc:
        if log_diagnostics:
            _log_capability_failure("native dependency resolution", exc)
        return False, "Native Wayland dependency resolution failed"

    return True, "Native Wayland backend available"


def _load_icon_image(Image, ImageDraw):
    icon_path = _icon_asset_path()
    if icon_path.exists():
        return Image.open(icon_path)

    image = Image.new("RGBA", (64, 64), (15, 23, 42, 255))
    draw = ImageDraw.Draw(image)
    draw.rectangle((10, 10, 54, 54), outline=(96, 165, 250, 255), width=4)
    draw.line((20, 48, 32, 16, 44, 48), fill=(244, 114, 182, 255), width=4)
    return image


class AppIndicatorBackend:
    def __init__(self, controller):
        AppIndicator3, GLib, Gtk = _load_appindicator_dependencies()
        self._appindicator = AppIndicator3
        self._glib = GLib
        self._gtk = Gtk
        self._controller = controller
        self._status_item = Gtk.MenuItem(label=controller.status_label)
        self._status_item.set_sensitive(False)
        self._detail_item = Gtk.MenuItem(label=controller.detail_label)
        self._detail_item.set_sensitive(False)
        self._menu = self._build_menu()
        category = AppIndicator3.IndicatorCategory.APPLICATION_STATUS
        self._indicator = AppIndicator3.Indicator.new(
            "excalibur-tray",
            "applications-system",
            category,
        )
        self._configure_icon()
        self._indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self._indicator.set_menu(self._menu)

    def _build_menu(self):
        Gtk = self._gtk
        menu = Gtk.Menu()
        menu.append(self._status_item)
        menu.append(self._detail_item)
        menu.append(Gtk.SeparatorMenuItem())

        dashboard_item = Gtk.MenuItem(label="Open Dashboard")
        dashboard_item.connect("activate", lambda *_args: self._controller.open_dashboard())
        menu.append(dashboard_item)

        start_item = Gtk.MenuItem(label="Start Sensor")
        start_item.connect("activate", lambda *_args: self._controller.start_sensor())
        menu.append(start_item)

        stop_item = Gtk.MenuItem(label="Stop Sensor")
        stop_item.connect("activate", lambda *_args: self._controller.stop_sensor())
        menu.append(stop_item)

        restart_item = Gtk.MenuItem(label="Restart Sensor")
        restart_item.connect("activate", lambda *_args: self._controller.restart_sensor())
        menu.append(restart_item)

        menu.append(Gtk.SeparatorMenuItem())

        exit_item = Gtk.MenuItem(label="Exit Tray App")
        exit_item.connect("activate", lambda *_args: self._controller.exit_app(self))
        menu.append(exit_item)
        menu.show_all()
        return menu

    def _configure_icon(self):
        icon_path = _icon_asset_path()
        if not icon_path.exists():
            return
        if hasattr(self._indicator, "set_icon_theme_path"):
            self._indicator.set_icon_theme_path(str(icon_path.parent))
        if hasattr(self._indicator, "set_icon_full"):
            self._indicator.set_icon_full(str(icon_path), "Excalibur")
            return
        if hasattr(self._indicator, "set_icon"):
            self._indicator.set_icon(str(icon_path))

    def run(self):
        self._controller.start_polling()
        self._controller.refresh_status()
        self._gtk.main()

    def stop(self):
        self._glib.idle_add(self._gtk.main_quit)

    def update_menu(self):
        self._glib.idle_add(self._apply_status_label)

    def _apply_status_label(self):
        self._status_item.set_label(self._controller.status_label)
        self._detail_item.set_label(self._controller.detail_label)
        return False


def create_tray_icon(controller=None):
    pystray, Image, ImageDraw = _load_tray_dependencies()
    controller = controller or TrayController()

    def _menu_item(label, callback=None, enabled=True):
        return pystray.MenuItem(label, callback, enabled=enabled)

    icon = pystray.Icon(
        "excalibur-tray",
        _load_icon_image(Image, ImageDraw),
        "Excalibur",
        menu=pystray.Menu(
            _menu_item(lambda item: controller.status_label, None, enabled=False),
            _menu_item(lambda item: controller.detail_label, None, enabled=False),
            pystray.Menu.SEPARATOR,
            _menu_item("Open Dashboard", lambda icon, item: controller.open_dashboard()),
            _menu_item("Start Sensor", lambda icon, item: controller.start_sensor()),
            _menu_item("Stop Sensor", lambda icon, item: controller.stop_sensor()),
            _menu_item("Restart Sensor", lambda icon, item: controller.restart_sensor()),
            pystray.Menu.SEPARATOR,
            _menu_item("Exit Tray App", lambda icon, item: controller.exit_app(icon)),
        ),
    )
    controller.attach_icon(icon)
    return icon, controller


def select_linux_tray_backend():
    if running_on_wayland():
        supported, reason = appindicator_supported(log_diagnostics=True)
        if supported:
            _tray_log("Native Wayland backend is available.")
            return "appindicator"
        _tray_log(f"Falling back to pystray because native Wayland backend was rejected: {reason}")
    return "pystray"


def create_tray_backend(controller=None):
    controller = controller or TrayController()
    _tray_log(f"Session: {_current_session_label()}")
    if running_on_windows():
        _tray_log("Checking pystray backend for Windows...")
        icon, controller = create_tray_icon(controller)
        _tray_log("Backend selected: pystray")
        return icon, controller, "pystray"
    if platform.system().lower() == "linux":
        selected_backend = select_linux_tray_backend()
        if selected_backend == "appindicator":
            _tray_log("Checking native Wayland backend initialization...")
            try:
                backend = AppIndicatorBackend(controller)
            except Exception as exc:
                _tray_log("[FAILED] Native Wayland backend initialization:")
                _tray_log(f"{type(exc).__name__}: {exc}")
                _tray_log(traceback.format_exc().rstrip())
                _tray_log("Falling back to pystray because native backend initialization failed.")
            else:
                controller.attach_icon(backend)
                _tray_log("[OK] Native backend initialized.")
                _tray_log("Backend selected: Wayland AppIndicator")
                return backend, controller, "appindicator"
        _tray_log("Checking pystray backend...")
    icon, controller = create_tray_icon(controller)
    _tray_log("Backend selected: pystray")
    return icon, controller, "pystray"


def run_tray_app():
    backend, controller, backend_name = create_tray_backend()
    if backend_name == "pystray":
        controller.start_polling()
        controller.refresh_status()
    backend.run()


def main():
    try:
        run_tray_app()
    except RuntimeError as exc:
        print(f"[TRAY] {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
