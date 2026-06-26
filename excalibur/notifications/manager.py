from excalibur.config import Config
from excalibur.notifications.desktop import DesktopNotificationSender
from excalibur.notifications.ntfy import NtfyNotificationSender


class NotificationManager:
    def __init__(self, config=None, desktop_sender=None, ntfy_sender=None):
        self.config = config or Config._default_config()
        self.notification_config = Config._merge_notifications(
            self.config.get("notifications", {})
        )
        self.desktop_sender = desktop_sender or DesktopNotificationSender()
        self.ntfy_sender = ntfy_sender or NtfyNotificationSender()

    def notify_alert(self, alert):
        if not self.notification_config.get("enabled", False):
            return False
        sent_any = False
        if self.notification_config.get("desktop", {}).get("enabled", False):
            sent_any = self._send_provider(
                self.desktop_sender.send_alert,
                alert,
                self.notification_config.get("desktop", {}),
                provider_name="desktop",
            ) or sent_any
        if self.notification_config.get("ntfy", {}).get("enabled", False):
            sent_any = self._send_provider(
                self.ntfy_sender.send_alert,
                alert,
                self.notification_config.get("ntfy", {}),
                provider_name="ntfy",
            ) or sent_any
        return sent_any

    def send_test_notification(self):
        if not self.notification_config.get("enabled", False):
            return False, "Notifications are disabled."
        provider_results = []
        if self.notification_config.get("desktop", {}).get("enabled", False):
            provider_results.append(
                self._send_provider(
                    self.desktop_sender.send_test,
                    self.notification_config.get("desktop", {}),
                    provider_name="desktop",
                )
            )
        if self.notification_config.get("ntfy", {}).get("enabled", False):
            provider_results.append(
                self._send_provider(
                    self.ntfy_sender.send_test,
                    self.notification_config.get("ntfy", {}),
                    provider_name="ntfy",
                )
            )
        if not provider_results:
            return False, "No notification providers are enabled."
        if not any(provider_results):
            return False, "Test notification failed."
        return True, None

    def _send_provider(self, send_func, *args, provider_name):
        try:
            return send_func(*args)
        except Exception as exc:
            print(
                f"[WARN] {provider_name} notification failed: {exc}",
                flush=True,
            )
            return False
