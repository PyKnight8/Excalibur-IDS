import subprocess
import unittest
from unittest.mock import patch

from excalibur.helper.service_ops import ServiceOperations, ServiceOpsError


class ServiceOperationsTest(unittest.TestCase):
    @patch("excalibur.helper.service_ops.subprocess.run")
    def test_sensor_status_uses_hardcoded_systemctl_command(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="active\n",
            stderr="",
        )

        status = ServiceOperations().sensor_status()

        self.assertEqual(status, "running")
        run_mock.assert_called_once_with(
            [
                "/bin/systemctl",
                "is-active",
                "excalibur-sniffer.service",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

    @patch("excalibur.helper.service_ops.subprocess.run")
    def test_sensor_restart_uses_hardcoded_systemctl_command(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="",
        )

        self.assertTrue(ServiceOperations().sensor_restart())

        run_mock.assert_called_once_with(
            [
                "/bin/systemctl",
                "restart",
                "excalibur-sniffer.service",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

    @patch("excalibur.helper.service_ops.subprocess.run")
    def test_sensor_start_uses_hardcoded_systemctl_command(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="",
        )

        self.assertTrue(ServiceOperations().sensor_start())
        self.assertEqual(
            run_mock.call_args.args[0],
            ["/bin/systemctl", "start", "excalibur-sniffer.service"],
        )

    @patch("excalibur.helper.service_ops.subprocess.run")
    def test_sensor_stop_uses_hardcoded_systemctl_command(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="",
        )

        self.assertTrue(ServiceOperations().sensor_stop())
        self.assertEqual(
            run_mock.call_args.args[0],
            ["/bin/systemctl", "stop", "excalibur-sniffer.service"],
        )

    @patch("excalibur.helper.service_ops.subprocess.run")
    def test_sensor_status_maps_failed_to_error(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=3,
            stdout="failed\n",
            stderr="",
        )

        self.assertEqual(ServiceOperations().sensor_status(), "error")

    @patch("excalibur.helper.service_ops.subprocess.run")
    def test_sensor_restart_maps_service_not_found(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Unit excalibur-sniffer.service could not be found.\n",
        )

        with self.assertRaises(ServiceOpsError) as context:
            ServiceOperations().sensor_restart()

        self.assertIn("not found", str(context.exception).lower())


if __name__ == "__main__":
    unittest.main()
