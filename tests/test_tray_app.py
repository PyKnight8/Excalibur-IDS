import unittest
from unittest.mock import patch

from excalibur.services.service_controller import ServiceControllerError
from excalibur.tray.app import TrayController, create_tray_backend


class FakeServiceController:
    def __init__(self, status="running", error=None):
        self.status_value = status
        self.error = error
        self.calls = []

    def status(self):
        self.calls.append("status")
        if self.error:
            raise self.error
        return self.status_value

    def start(self):
        self.calls.append("start")
        if self.error:
            raise self.error
        return True

    def stop(self):
        self.calls.append("stop")
        if self.error:
            raise self.error
        return True

    def restart(self):
        self.calls.append("restart")
        if self.error:
            raise self.error
        return True


class TrayControllerTest(unittest.TestCase):
    def test_refresh_status_updates_label_state(self):
        controller = TrayController(service_controller=FakeServiceController(status="starting"))

        self.assertEqual(controller.refresh_status(), "starting")
        self.assertEqual(controller.status_label, "Sensor Status: Starting")

    def test_open_dashboard_uses_browser_opener(self):
        opened = []
        controller = TrayController(
            service_controller=FakeServiceController(),
            browser_opener=opened.append,
        )

        controller.open_dashboard()

        self.assertEqual(opened, ["http://127.0.0.1:5000"])

    def test_actions_refresh_status_after_success(self):
        service_controller = FakeServiceController(status="running")
        controller = TrayController(service_controller=service_controller)

        self.assertTrue(controller.restart_sensor())

        self.assertEqual(service_controller.calls, ["restart", "status"])
        self.assertEqual(controller.detail_label, "Last Result: Sensor restarted.")

    def test_action_failure_preserves_last_status_and_sets_notice(self):
        service_controller = FakeServiceController(status="running")
        controller = TrayController(service_controller=service_controller)
        controller.refresh_status()
        service_controller.error = ServiceControllerError("Authentication was denied.")

        self.assertFalse(controller.stop_sensor())

        self.assertEqual(controller.status_label, "Sensor Status: Running")
        self.assertEqual(
            controller.detail_label,
            "Last Result: Authentication was denied.",
        )

    @patch("excalibur.tray.app.platform.system", return_value="Linux")
    @patch("excalibur.tray.app.running_on_windows", return_value=False)
    @patch("excalibur.tray.app.running_on_wayland", return_value=True)
    @patch(
        "excalibur.tray.app.appindicator_supported",
        return_value=(True, "Native Wayland backend available"),
    )
    @patch("excalibur.tray.app.AppIndicatorBackend")
    def test_wayland_uses_appindicator_backend(
        self,
        backend_mock,
        _supported_mock,
        _wayland_mock,
        _windows_mock,
        _system_mock,
    ):
        controller = TrayController(service_controller=FakeServiceController())
        backend_instance = backend_mock.return_value

        backend, returned_controller, backend_name = create_tray_backend(controller)

        self.assertIs(backend, backend_instance)
        self.assertIs(returned_controller, controller)
        self.assertEqual(backend_name, "appindicator")
        backend_mock.assert_called_once_with(controller)

    @patch("excalibur.tray.app.platform.system", return_value="Linux")
    @patch("excalibur.tray.app.running_on_windows", return_value=False)
    @patch("excalibur.tray.app.running_on_wayland", return_value=False)
    @patch("excalibur.tray.app.create_tray_icon")
    def test_x11_uses_existing_pystray_backend(
        self,
        create_icon_mock,
        _wayland_mock,
        _windows_mock,
        _system_mock,
    ):
        controller = TrayController(service_controller=FakeServiceController())
        backend = object()
        create_icon_mock.return_value = (backend, controller)

        returned_backend, returned_controller, backend_name = create_tray_backend(controller)

        self.assertIs(returned_backend, backend)
        self.assertIs(returned_controller, controller)
        self.assertEqual(backend_name, "pystray")
        create_icon_mock.assert_called_once_with(controller)

    @patch("excalibur.tray.app.platform.system", return_value="Linux")
    @patch("excalibur.tray.app.running_on_windows", return_value=False)
    @patch("excalibur.tray.app.running_on_wayland", return_value=True)
    @patch(
        "excalibur.tray.app.appindicator_supported",
        return_value=(False, "No supported AppIndicator binding available"),
    )
    @patch("excalibur.tray.app.create_tray_icon")
    def test_wayland_falls_back_to_pystray_when_native_backend_unavailable(
        self,
        create_icon_mock,
        _supported_mock,
        _wayland_mock,
        _windows_mock,
        _system_mock,
    ):
        controller = TrayController(service_controller=FakeServiceController())
        backend = object()
        create_icon_mock.return_value = (backend, controller)

        returned_backend, returned_controller, backend_name = create_tray_backend(controller)

        self.assertIs(returned_backend, backend)
        self.assertIs(returned_controller, controller)
        self.assertEqual(backend_name, "pystray")
        create_icon_mock.assert_called_once_with(controller)


if __name__ == "__main__":
    unittest.main()
