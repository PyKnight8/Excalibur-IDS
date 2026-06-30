import socket
import unittest
from unittest.mock import patch

from excalibur.services.service_controller import (
    LinuxServiceController,
    ServiceControllerError,
    WindowsServiceController,
)
from excalibur.services.windows_service_manager import WindowsServiceManagerError


class FakeSocket:
    def __init__(self, response):
        self.response = response
        self.sent = b""
        self.connected_to = None
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, path):
        self.connected_to = path

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        if self.response is None:
            return b""
        response = self.response
        self.response = None
        return response

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class LinuxServiceControllerTest(unittest.TestCase):
    @patch("excalibur.services.service_controller.socket.socket")
    def test_status_requests_sensor_status_over_helper_socket(self, socket_mock):
        fake_socket = FakeSocket(b'{"ok": true, "status": "running"}\n')
        socket_mock.return_value = fake_socket

        status = LinuxServiceController().status()

        self.assertEqual(status, "running")
        self.assertEqual(fake_socket.connected_to, "/run/excalibur/helper.sock")
        self.assertIn(b'"action": "sensor_status"', fake_socket.sent)

    @patch("excalibur.services.service_controller.socket.socket")
    def test_restart_requests_sensor_restart_over_helper_socket(self, socket_mock):
        fake_socket = FakeSocket(b'{"ok": true}\n')
        socket_mock.return_value = fake_socket

        self.assertTrue(LinuxServiceController().restart())
        self.assertIn(b'"action": "sensor_restart"', fake_socket.sent)

    @patch("excalibur.services.service_controller.socket.socket")
    def test_start_and_stop_request_helper_actions(self, socket_mock):
        start_socket = FakeSocket(b'{"ok": true}\n')
        stop_socket = FakeSocket(b'{"ok": true}\n')
        socket_mock.side_effect = [start_socket, stop_socket]

        self.assertTrue(LinuxServiceController().start())
        self.assertTrue(LinuxServiceController().stop())
        self.assertIn(b'"action": "sensor_start"', start_socket.sent)
        self.assertIn(b'"action": "sensor_stop"', stop_socket.sent)

    @patch("excalibur.services.service_controller.socket.socket")
    def test_restart_surfaces_helper_error(self, socket_mock):
        fake_socket = FakeSocket(
            b'{"ok": false, "error": "Permission denied while restarting the sensor."}\n'
        )
        socket_mock.return_value = fake_socket

        with self.assertRaises(ServiceControllerError) as context:
            LinuxServiceController().restart()

        self.assertIn("Permission denied", str(context.exception))


class FakeWindowsServiceManager:
    def __init__(self, status="running", error=None):
        self.status_value = status
        self.error = error
        self.calls = []

    def status(self, service_name):
        self.calls.append(("status", service_name))
        if self.error:
            raise self.error
        return self.status_value

    def restart(self, service_name):
        self.calls.append(("restart", service_name))
        if self.error:
            raise self.error
        return True

    def start(self, service_name):
        self.calls.append(("start", service_name))
        if self.error:
            raise self.error
        return True

    def stop(self, service_name):
        self.calls.append(("stop", service_name))
        if self.error:
            raise self.error
        return True


class WindowsServiceControllerTest(unittest.TestCase):
    def test_status_uses_windows_sensor_service(self):
        manager = FakeWindowsServiceManager()

        self.assertEqual(WindowsServiceController(manager).status(), "running")
        self.assertEqual(manager.calls, [("status", "ExcaliburSensor")])

    def test_restart_uses_windows_sensor_service(self):
        manager = FakeWindowsServiceManager()

        self.assertTrue(WindowsServiceController(manager).restart())
        self.assertEqual(manager.calls, [("restart", "ExcaliburSensor")])

    def test_start_and_stop_use_windows_sensor_service(self):
        manager = FakeWindowsServiceManager()
        controller = WindowsServiceController(manager)

        self.assertTrue(controller.start())
        self.assertTrue(controller.stop())
        self.assertEqual(
            manager.calls,
            [("start", "ExcaliburSensor"), ("stop", "ExcaliburSensor")],
        )

    def test_backend_error_is_exposed_as_controller_error(self):
        controller = WindowsServiceController(
            FakeWindowsServiceManager(error=WindowsServiceManagerError("denied"))
        )

        with self.assertRaises(ServiceControllerError):
            controller.restart()


if __name__ == "__main__":
    unittest.main()
