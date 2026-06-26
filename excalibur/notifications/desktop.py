try:
    from plyer import notification
except ImportError:  # pragma: no cover - environment dependent fallback
    notification = None


class DesktopNotificationSender:
    def __init__(self, notify_func=None):
        default_notify = notification.notify if notification is not None else None
        self.notify_func = notify_func or default_notify

    def send_alert(self, alert, settings):
        if not settings.get("enabled", False):
            return False
        if self.notify_func is None:
            raise RuntimeError("Desktop notification support is not available.")
        self.notify_func(
            title=self._title(alert),
            message=self._message(alert),
            app_name="Excalibur",
            timeout=10,
        )
        return True

    def send_test(self, settings):
        if not settings.get("enabled", False):
            return False
        if self.notify_func is None:
            raise RuntimeError("Desktop notification support is not available.")
        self.notify_func(
            title="[Medium] Excalibur Test Notification",
            message=(
                "Source: dashboard\n"
                "Description: Native desktop notifications are functioning correctly."
            ),
            app_name="Excalibur",
            timeout=10,
        )
        return True

    def _title(self, alert):
        severity = alert.get("severity", "Medium")
        title = alert.get("title", "Excalibur Alert")
        return f"[{severity}] {title}"

    def _message(self, alert):
        source_ip = alert.get("source_ip") or "unknown"
        description = alert.get("description") or ""
        return (
            f"Source: {source_ip}\n"
            f"Description: {description}"
        )
