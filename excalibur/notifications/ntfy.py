import requests


class NtfyNotificationSender:
    def __init__(self, post_func=None):
        self.post_func = post_func or requests.post

    def send_alert(self, alert, settings):
        message = self._format_alert_message(alert)
        return self._post_message(message, settings)

    def send_test(self, settings):
        message = (
            "[Medium] Excalibur Test Notification\n"
            "Source: dashboard\n"
            "Description: Excalibur alert relay is functioning correctly."
        )
        return self._post_message(message, settings)

    def _post_message(self, message, settings):
        url = str(settings.get("url", "")).strip()
        timeout_seconds = int(settings.get("timeout_seconds", 5))
        if not url:
            raise ValueError("Notification URL is not configured.")
        try:
            response = self.post_func(
                url,
                data=message.encode("utf-8"),
                headers={"Content-Type": "text/plain; charset=utf-8"},
                timeout=timeout_seconds,
            )
            response.raise_for_status()
            return True
        except requests.RequestException as exc:
            print(f"[WARN] ntfy notification failed: {exc}", flush=True)
            return False

    def _format_alert_message(self, alert):
        severity = alert.get("severity", "Medium")
        title = alert.get("title", "Excalibur Alert")
        source_ip = alert.get("source_ip") or "unknown"
        description = alert.get("description") or ""
        return (
            f"[{severity}] {title}\n"
            f"Source: {source_ip}\n"
            f"Description: {description}"
        )
