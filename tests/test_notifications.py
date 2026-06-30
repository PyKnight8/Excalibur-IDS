import unittest

from excalibur.dashboard.app import create_app


class NotificationTest(unittest.TestCase):
    def test_test_notification_endpoint_returns_json_success(self):
        app = create_app(":memory:")
        app.config["NOTIFICATION_MANAGER"] = FakeNotificationManager(
            success=True,
            error=None,
        )

        response = app.test_client().post("/api/notifications/test")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload, {"success": True})

    def test_test_notification_endpoint_returns_json_error(self):
        app = create_app(":memory:")
        app.config["NOTIFICATION_MANAGER"] = FakeNotificationManager(
            success=False,
            error="Test notification failed.",
        )

        response = app.test_client().post("/api/notifications/test")
        payload = response.get_json()

        self.assertEqual(response.status_code, 500)
        self.assertFalse(payload["success"])
        self.assertIn("Test notification failed", payload["error"])


class FakeNotificationManager:
    def __init__(self, success, error):
        self.success = success
        self.error = error

    def send_test_notification(self):
        return self.success, self.error


if __name__ == "__main__":
    unittest.main()
