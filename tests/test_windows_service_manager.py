import subprocess
import unittest
from unittest.mock import patch

from excalibur.services.windows_service_manager import (
    WindowsServiceManager,
    WindowsServiceManagerError,
)


class WindowsServiceManagerTest(unittest.TestCase):
    @patch("excalibur.services.windows_service_manager.subprocess.run")
    def test_status_maps_running(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Running\n", stderr=""
        )

        self.assertEqual(WindowsServiceManager().status("ExcaliburSensor"), "running")
        command = run_mock.call_args.args[0]
        self.assertEqual(command[:3], ["powershell.exe", "-NoProfile", "-NonInteractive"])
        self.assertIn("Get-Service", command[-1])

    @patch("excalibur.services.windows_service_manager.subprocess.run")
    def test_status_maps_startpending_to_starting(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="StartPending\n", stderr=""
        )

        self.assertEqual(WindowsServiceManager().status("ExcaliburSensor"), "starting")

    @patch("excalibur.services.windows_service_manager.subprocess.run")
    def test_restart_returns_true(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Running\n", stderr=""
        )

        self.assertTrue(WindowsServiceManager().restart("ExcaliburSensor"))
        self.assertIn("Restart-Service", run_mock.call_args.args[0][-1])

    @patch("excalibur.services.windows_service_manager.subprocess.run")
    def test_missing_service_is_reported(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Cannot find any service with service name 'Missing'.",
        )

        with self.assertRaises(WindowsServiceManagerError) as context:
            WindowsServiceManager().status("Missing")

        self.assertIn("not found", str(context.exception).lower())


if __name__ == "__main__":
    unittest.main()
