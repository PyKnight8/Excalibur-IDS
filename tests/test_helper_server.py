import unittest
from unittest.mock import patch
import stat

from excalibur.helper.server import HelperServer


class FakeServiceOperations:
    def sensor_status(self):
        return "running"

    def sensor_start(self):
        return True

    def sensor_stop(self):
        return True

    def sensor_restart(self):
        return True


class FakePolicyAuthorizer:
    def __init__(self):
        self.calls = []

    def authorize(self, action, peer_pid, peer_uid):
        self.calls.append((action, peer_pid, peer_uid))
        return True


class HelperServerTest(unittest.TestCase):
    def test_authorized_peer_accepts_connected_local_user(self):
        server = HelperServer.__new__(HelperServer)

        self.assertTrue(server.is_authorized_peer((123, 1001, 1001)))

    def test_dispatch_supports_only_expected_actions(self):
        server = HelperServer.__new__(HelperServer)
        server.service_operations = FakeServiceOperations()
        server.policy_authorizer = FakePolicyAuthorizer()

        self.assertEqual(
            server.dispatch("sensor_status", (123, 1002, 1002)),
            {"ok": True, "status": "running"},
        )
        self.assertEqual(server.dispatch("sensor_start", (123, 1002, 1002)), {"ok": True})
        self.assertEqual(server.dispatch("sensor_stop", (123, 1002, 1002)), {"ok": True})
        self.assertEqual(server.dispatch("sensor_restart", (123, 1002, 1002)), {"ok": True})
        self.assertEqual(
            server.policy_authorizer.calls,
            [
                ("sensor_start", 123, 1002),
                ("sensor_stop", 123, 1002),
                ("sensor_restart", 123, 1002),
            ],
        )

    @patch("excalibur.helper.server.os.chown")
    @patch("excalibur.helper.server.os.chmod")
    @patch("excalibur.helper.server.os.makedirs")
    @patch("excalibur.helper.server.os.unlink")
    @patch("excalibur.helper.server.os.path.exists", return_value=True)
    @patch("excalibur.helper.server.os.stat")
    @patch("excalibur.helper.server._required_gid", return_value=1001)
    @patch("excalibur.helper.server.os.geteuid", return_value=0)
    @patch("excalibur.helper.server.sys.platform", "linux")
    @patch("excalibur.helper.server.HelperServer")
    def test_main_refuses_to_unlink_non_socket_path(
        self,
        helper_server_mock,
        geteuid_mock,
        gid_mock,
        stat_mock,
        exists_mock,
        unlink_mock,
        makedirs_mock,
        chmod_mock,
        chown_mock,
    ):
        fake_stat = type("FakeStat", (), {"st_mode": stat.S_IFREG | 0o660})()
        stat_mock.return_value = fake_stat

        from excalibur.helper import server as helper_server_module

        with self.assertRaises(RuntimeError):
            helper_server_module.main()

        unlink_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
