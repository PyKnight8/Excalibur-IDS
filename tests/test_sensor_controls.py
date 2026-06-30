from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.dashboard.app import create_app
from excalibur.services.service_controller import ServiceControllerError


class FakeServiceController:
    def __init__(self, status="running", restart_error=None):
        self._status = status
        self._restart_error = restart_error
        self.restart_calls = 0

    def status(self):
        return self._status

    def restart(self):
        self.restart_calls += 1
        if self._restart_error is not None:
            raise self._restart_error
        return True


class SensorControlsTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "sensor-controls.sqlite"
        self.rules_dir = Path(self.temp_dir.name) / "rules"
        self.rules_dir.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sensor_status_endpoint_returns_running_status(self):
        app = create_app(
            self.db_path,
            rule_packs_path=self.rules_dir,
            service_controller=FakeServiceController(status="running"),
        )

        response = app.test_client().get("/sensor/status")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "running"})

    def test_sensor_restart_endpoint_returns_success(self):
        controller = FakeServiceController()
        app = create_app(
            self.db_path,
            rule_packs_path=self.rules_dir,
            service_controller=controller,
        )

        response = app.test_client().post("/sensor/restart")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"success": True})
        self.assertEqual(controller.restart_calls, 1)

    def test_sensor_restart_endpoint_returns_error_payload_on_failure(self):
        app = create_app(
            self.db_path,
            rule_packs_path=self.rules_dir,
            service_controller=FakeServiceController(
                restart_error=ServiceControllerError("Permission denied while restarting the sensor.")
            ),
        )

        response = app.test_client().post("/sensor/restart")
        payload = response.get_json()

        self.assertEqual(response.status_code, 500)
        self.assertFalse(payload["success"])
        self.assertEqual(
            payload["error"],
            "Permission denied while restarting the sensor.",
        )

    def test_rules_page_shows_sensor_status_and_restart_button_after_save(self):
        app = create_app(
            self.db_path,
            rule_packs_path=self.rules_dir,
            service_controller=FakeServiceController(status="running"),
        )

        response = app.test_client().get("/rules?pack=recon&saved=1")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Sensor Status", html)
        self.assertIn("Restart Sensor", html)
        self.assertIn("/sensor/status", html)
        self.assertIn("/sensor/restart", html)


if __name__ == "__main__":
    unittest.main()
