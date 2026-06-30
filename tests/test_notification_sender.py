from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import requests

from excalibur.config import Config
from excalibur.database import Database
from excalibur.notifications import (
    DesktopNotificationSender,
    NotificationManager,
    NtfyNotificationSender,
)


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class NotificationSenderTest(unittest.TestCase):
    def test_disabled_notifications_skip_alert_send(self):
        desktop_calls = []
        calls = []
        desktop_sender = DesktopNotificationSender(
            notify_func=lambda **kwargs: desktop_calls.append(kwargs)
        )
        sender = NtfyNotificationSender(
            post_func=lambda *args, **kwargs: calls.append((args, kwargs))
        )
        manager = NotificationManager(
            self._config(enabled=False),
            desktop_sender=desktop_sender,
            ntfy_sender=sender,
        )

        result = manager.notify_alert(self._alert())

        self.assertFalse(result)
        self.assertEqual(desktop_calls, [])
        self.assertEqual(calls, [])

    def test_enabled_desktop_notifications_send_native_notification(self):
        desktop_calls = []
        manager = NotificationManager(
            self._config(enabled=True, desktop_enabled=True, ntfy_enabled=False),
            desktop_sender=DesktopNotificationSender(
                notify_func=lambda **kwargs: desktop_calls.append(kwargs)
            ),
            ntfy_sender=NtfyNotificationSender(post_func=lambda *args, **kwargs: FakeResponse()),
        )

        result = manager.notify_alert(self._alert())

        self.assertTrue(result)
        self.assertEqual(len(desktop_calls), 1)
        self.assertEqual(desktop_calls[0]["title"], "[High] SMB Recon Activity")
        self.assertIn("Source: 10.0.2.10", desktop_calls[0]["message"])

    def test_enabled_notifications_send_plain_text_to_configured_ntfy_url(self):
        calls = []

        def fake_post(*args, **kwargs):
            calls.append((args, kwargs))
            return FakeResponse()

        sender = NtfyNotificationSender(post_func=fake_post)
        manager = NotificationManager(
            self._config(
                enabled=True,
                desktop_enabled=False,
                ntfy_enabled=True,
                url="http://relay.local/topic",
                timeout_seconds=7,
            ),
            desktop_sender=DesktopNotificationSender(
                notify_func=lambda **kwargs: None
            ),
            ntfy_sender=sender,
        )

        result = manager.notify_alert(self._alert())

        self.assertTrue(result)
        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(args[0], "http://relay.local/topic")
        self.assertEqual(kwargs["timeout"], 7)
        self.assertEqual(
            kwargs["headers"]["Content-Type"],
            "text/plain; charset=utf-8",
        )
        self.assertEqual(
            kwargs["data"].decode("utf-8"),
            "[High] SMB Recon Activity\n"
            "Source: 10.0.2.10\n"
            "Description: Source contacted many hosts via SMB.",
        )

    def test_ntfy_unreachable_does_not_raise(self):
        def failing_post(*args, **kwargs):
            raise requests.ConnectionError("network unavailable")

        sender = NtfyNotificationSender(post_func=failing_post)
        manager = NotificationManager(
            self._config(enabled=True, desktop_enabled=False, ntfy_enabled=True),
            desktop_sender=DesktopNotificationSender(
                notify_func=lambda **kwargs: None
            ),
            ntfy_sender=sender,
        )

        result = manager.notify_alert(self._alert())

        self.assertFalse(result)

    def test_multiple_enabled_providers_fan_out_even_if_one_fails(self):
        desktop_calls = []

        def failing_post(*args, **kwargs):
            raise requests.ConnectionError("network unavailable")

        manager = NotificationManager(
            self._config(enabled=True, desktop_enabled=True, ntfy_enabled=True),
            desktop_sender=DesktopNotificationSender(
                notify_func=lambda **kwargs: desktop_calls.append(kwargs)
            ),
            ntfy_sender=NtfyNotificationSender(post_func=failing_post),
        )

        result = manager.notify_alert(self._alert())

        self.assertTrue(result)
        self.assertEqual(len(desktop_calls), 1)

    def test_alert_storage_continues_when_notification_fails(self):
        with TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "notifications.sqlite"
            database = Database(db_path)
            database.set_notification_manager(
                NotificationManager(
                    self._config(enabled=True, desktop_enabled=False, ntfy_enabled=True),
                    desktop_sender=DesktopNotificationSender(
                        notify_func=lambda **kwargs: None
                    ),
                    ntfy_sender=NtfyNotificationSender(
                        post_func=lambda *args, **kwargs: (_ for _ in ()).throw(
                            requests.ConnectionError("relay down")
                        )
                    ),
                )
            )

            alert_id = database.create_alert(
                "2026-06-08T10:00:00+00:00",
                "Medium",
                "Possible Port Scan",
                "Source IP 10.0.0.10 contacted 20 unique destination ports.",
            )

            self.assertIsNotNone(alert_id)
            self.assertEqual(database.count_alerts(), 1)
            database.close()

    def test_test_notification_succeeds_if_any_enabled_provider_succeeds(self):
        manager = NotificationManager(
            self._config(enabled=True, desktop_enabled=True, ntfy_enabled=True),
            desktop_sender=DesktopNotificationSender(
                notify_func=lambda **kwargs: None
            ),
            ntfy_sender=NtfyNotificationSender(
                post_func=lambda *args, **kwargs: (_ for _ in ()).throw(
                    requests.ConnectionError("relay down")
                )
            ),
        )

        success, error = manager.send_test_notification()

        self.assertTrue(success)
        self.assertIsNone(error)

    def _config(
        self,
        enabled,
        desktop_enabled=False,
        ntfy_enabled=False,
        url="http://ntfyServer:5002/Excalibur-Relay-Notifications",
        timeout_seconds=5,
    ):
        config = Config._default_config()
        config["notifications"] = {
            "enabled": enabled,
            "desktop": {
                "enabled": desktop_enabled,
            },
            "ntfy": {
                "enabled": ntfy_enabled,
                "url": url,
                "timeout_seconds": timeout_seconds,
            },
        }
        return config

    def _alert(self):
        return {
            "timestamp": "2026-06-08T10:00:00+00:00",
            "severity": "High",
            "title": "SMB Recon Activity",
            "description": "Source contacted many hosts via SMB.",
            "source_ip": "10.0.2.10",
        }


if __name__ == "__main__":
    unittest.main()
