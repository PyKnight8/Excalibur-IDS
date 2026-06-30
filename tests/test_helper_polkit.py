import subprocess
import unittest
from unittest.mock import mock_open, patch

from excalibur.helper.polkit import PolicyKitAuthorizer, PolicyKitError


class PolicyKitAuthorizerTest(unittest.TestCase):
    def setUp(self):
        self.authorizer = PolicyKitAuthorizer(trusted_service_uid=999)

    @patch("excalibur.helper.polkit.subprocess.run")
    def test_status_does_not_invoke_pkcheck(self, run_mock):
        self.assertTrue(self.authorizer.authorize("sensor_status", 123, 1000))
        run_mock.assert_not_called()

    @patch("excalibur.helper.polkit.subprocess.run")
    def test_trusted_service_user_bypasses_pkcheck(self, run_mock):
        self.assertTrue(self.authorizer.authorize("sensor_restart", 123, 999))
        run_mock.assert_not_called()

    @patch(
        "excalibur.helper.polkit.open",
        new_callable=mock_open,
        read_data="1234 (python) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 456 21",
    )
    @patch("excalibur.helper.polkit.subprocess.run")
    def test_non_trusted_user_uses_pkcheck_with_process_tuple(self, run_mock, _open_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="",
        )

        self.assertTrue(self.authorizer.authorize("sensor_restart", 1234, 1000))

        self.assertEqual(
            run_mock.call_args.args[0],
            [
                "/usr/bin/pkcheck",
                "--action-id",
                "org.excalibur.sensor.restart",
                "--process",
                "1234,456,1000",
                "--allow-user-interaction",
            ],
        )

    @patch(
        "excalibur.helper.polkit.open",
        new_callable=mock_open,
        read_data="1234 (python) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 456 21",
    )
    @patch("excalibur.helper.polkit.subprocess.run")
    def test_cancelled_authentication_returns_clear_error(self, run_mock, _open_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="User cancelled authentication dialog\n",
        )

        with self.assertRaises(PolicyKitError) as context:
            self.authorizer.authorize("sensor_stop", 1234, 1000)

        self.assertIn("cancelled", str(context.exception).lower())


if __name__ == "__main__":
    unittest.main()
