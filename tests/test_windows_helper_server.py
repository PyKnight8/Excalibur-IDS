import unittest

from excalibur.helper.windows_server import WindowsHelperServer


class FakeServiceManager:
    def __init__(self):
        self.calls = []

    def status(self, service_name):
        self.calls.append(("status", service_name))
        return "running"

    def restart(self, service_name):
        self.calls.append(("restart", service_name))
        return True

    def start(self, service_name):
        self.calls.append(("start", service_name))
        return True

    def stop(self, service_name):
        self.calls.append(("stop", service_name))
        return True


class WindowsHelperServerTest(unittest.TestCase):
    def setUp(self):
        self.manager = FakeServiceManager()
        self.server = WindowsHelperServer.__new__(WindowsHelperServer)
        self.server.service_manager = self.manager

    def test_dispatch_checks_sensor_status(self):
        self.assertEqual(
            self.server.dispatch("sensor_status"),
            {"ok": True, "status": "running"},
        )
        self.assertEqual(self.manager.calls, [("status", "ExcaliburSensor")])

    def test_dispatch_restarts_sensor(self):
        self.assertEqual(self.server.dispatch("sensor_restart"), {"ok": True})
        self.assertEqual(self.manager.calls, [("restart", "ExcaliburSensor")])

    def test_dispatch_starts_and_stops_sensor(self):
        self.assertEqual(self.server.dispatch("sensor_start"), {"ok": True})
        self.assertEqual(self.server.dispatch("sensor_stop"), {"ok": True})
        self.assertEqual(
            self.manager.calls,
            [("start", "ExcaliburSensor"), ("stop", "ExcaliburSensor")],
        )

    def test_dispatch_rejects_other_actions(self):
        with self.assertRaises(ValueError):
            self.server.dispatch("restart_arbitrary_service")


if __name__ == "__main__":
    unittest.main()
