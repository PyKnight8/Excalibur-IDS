from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.config import Config
from excalibur.database import Database


class TrafficRetentionTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.database = Database(Path(self.temp_dir.name) / "test.sqlite")

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_enforce_traffic_limit_removes_oldest_records(self):
        for index in range(5):
            self._log_packet(index)

        purged = self.database.enforce_traffic_limit(3)
        rows, total = self.database.get_traffic(sort_by="timestamp", sort_order="ASC")

        self.assertEqual(purged, 2)
        self.assertEqual(total, 3)
        self.assertEqual(
            [row["src_ip"] for row in rows],
            ["10.0.0.2", "10.0.0.3", "10.0.0.4"],
        )

    def test_get_traffic_count_returns_current_traffic_count(self):
        self._log_packet(1)
        self._log_packet(2)

        self.assertEqual(self.database.get_traffic_count(), 2)

    def test_retention_does_not_purge_hosts_or_alerts(self):
        self.database.add_host(
            "10.0.0.1",
            None,
            "2026-06-08T10:00:00",
            "2026-06-08T10:00:00",
        )
        self.database.create_alert(
            "2026-06-08T10:00:00",
            "Medium",
            "Possible Port Scan",
            "Test alert",
        )
        for index in range(3):
            self._log_packet(index)

        self.database.enforce_traffic_limit(1)

        self.assertEqual(self.database.get_traffic_count(), 1)
        self.assertEqual(self.database.count_hosts(), 1)
        self.assertEqual(self.database.count_alerts(), 1)

    def test_add_host_does_not_trigger_traffic_retention(self):
        for index in range(3):
            self._log_packet(index)

        original_limit = Config.TRAFFIC_MAX_RECORDS
        Config.TRAFFIC_MAX_RECORDS = 1
        try:
            self.database.add_host(
                "10.0.0.99",
                None,
                "2026-06-08T10:00:00",
                "2026-06-08T10:00:00",
            )
        finally:
            Config.TRAFFIC_MAX_RECORDS = original_limit

        self.assertEqual(self.database.get_traffic_count(), 3)
        self.assertEqual(self.database.count_hosts(), 1)

    def test_log_traffic_runs_batched_retention(self):
        original_limit = Config.TRAFFIC_MAX_RECORDS
        original_interval = Database.TRAFFIC_RETENTION_CHECK_INTERVAL
        Config.TRAFFIC_MAX_RECORDS = 3
        Database.TRAFFIC_RETENTION_CHECK_INTERVAL = 2
        try:
            for index in range(6):
                self._log_packet(index)
        finally:
            Config.TRAFFIC_MAX_RECORDS = original_limit
            Database.TRAFFIC_RETENTION_CHECK_INTERVAL = original_interval

        rows, total = self.database.get_traffic(sort_by="timestamp", sort_order="ASC")
        self.assertEqual(total, 3)
        self.assertEqual(
            [row["src_ip"] for row in rows],
            ["10.0.0.3", "10.0.0.4", "10.0.0.5"],
        )

    def test_batched_retention_touches_only_traffic(self):
        original_limit = Config.TRAFFIC_MAX_RECORDS
        original_interval = Database.TRAFFIC_RETENTION_CHECK_INTERVAL
        Config.TRAFFIC_MAX_RECORDS = 1
        Database.TRAFFIC_RETENTION_CHECK_INTERVAL = 2
        try:
            self.database.add_host(
                "10.0.0.50",
                None,
                "2026-06-08T10:00:00",
                "2026-06-08T10:00:00",
            )
            self.database.create_alert(
                "2026-06-08T10:00:00",
                "Medium",
                "Test Alert",
                "Alert should remain",
            )
            self.database.log_dns_query(
                "2026-06-08T10:00:00",
                "10.0.0.50",
                "10.0.0.1",
                "example.com",
                "A",
            )
            self._log_packet(0)
            self._log_packet(1)
        finally:
            Config.TRAFFIC_MAX_RECORDS = original_limit
            Database.TRAFFIC_RETENTION_CHECK_INTERVAL = original_interval

        self.assertEqual(self.database.get_traffic_count(), 1)
        self.assertEqual(self.database.count_hosts(), 1)
        self.assertEqual(self.database.count_alerts(), 1)
        self.assertEqual(self.database.get_dns_query_count(), 1)
        self.assertEqual(self.database.get_domain_count(), 1)

    def _log_packet(self, index):
        self.database.log_traffic(
            timestamp=f"2026-06-08T10:00:0{index}",
            src_ip=f"10.0.0.{index}",
            dst_ip="10.0.1.1",
            protocol="TCP",
            src_port=1000 + index,
            dst_port=80,
            packet_size=60 + index,
        )


if __name__ == "__main__":
    unittest.main()
