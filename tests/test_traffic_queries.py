from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.database import Database
from excalibur.service_lookup import get_service_name


class TrafficQueryTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.database = Database(Path(self.temp_dir.name) / "test.sqlite")

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_search_matches_source_destination_protocol_and_ports(self):
        self._log_packet("2026-06-08T10:00:00", "10.0.0.1", "10.0.0.2", "TCP", 1111, 80, 60)
        self._log_packet("2026-06-08T10:01:00", "10.0.0.3", "10.0.0.4", "UDP", 2222, 53, 70)

        rows, total = self.database.get_traffic(search="UDP")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["protocol"], "UDP")

        rows, total = self.database.get_traffic(search="80")
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["dst_port"], 80)

    def test_service_names_are_returned_for_common_ports(self):
        self._log_packet("2026-06-08T10:00:00", "10.0.0.1", "10.0.0.2", "TCP", 1111, 22, 60)
        self._log_packet("2026-06-08T10:01:00", "10.0.0.3", "10.0.0.4", "TCP", 2222, 4444, 70)

        rows, total = self.database.get_traffic(sort_by="timestamp", sort_order="ASC")

        self.assertEqual(total, 2)
        self.assertEqual(rows[0]["service"], "SSH")
        self.assertEqual(rows[1]["service"], "Unknown")

    def test_search_matches_service_name(self):
        self._log_packet("2026-06-08T10:00:00", "10.0.0.1", "10.0.0.2", "TCP", 1111, 445, 60)
        self._log_packet("2026-06-08T10:01:00", "10.0.0.3", "10.0.0.4", "TCP", 2222, 3389, 70)

        rows, total = self.database.get_traffic(search="SMB")

        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["dst_port"], 445)
        self.assertEqual(rows[0]["service"], "SMB")

    def test_sorting_by_service_name(self):
        self._log_packet("2026-06-08T10:00:00", "10.0.0.1", "10.0.0.2", "TCP", 1111, 445, 60)
        self._log_packet("2026-06-08T10:01:00", "10.0.0.3", "10.0.0.4", "TCP", 2222, 22, 70)

        rows, total = self.database.get_traffic(sort_by="service", sort_order="ASC")

        self.assertEqual(total, 2)
        self.assertEqual([row["service"] for row in rows], ["SMB", "SSH"])

    def test_service_lookup_returns_unknown_for_unmapped_ports(self):
        self.assertEqual(get_service_name("TCP", 443), "HTTPS")
        self.assertEqual(get_service_name("UDP", 53), "DNS")
        self.assertEqual(get_service_name("TCP", 4444), "Unknown")

    def test_filters_match_traffic_columns(self):
        self._log_packet("2026-06-08T10:00:00", "10.0.0.1", "10.0.0.2", "TCP", 1111, 80, 60)
        self._log_packet("2026-06-08T10:01:00", "10.0.0.3", "10.0.0.4", "UDP", 2222, 53, 70)

        rows, total = self.database.get_traffic(
            filters={"src_ip": "10.0.0.1", "protocol": "TCP", "dst_port": "80"}
        )

        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["src_ip"], "10.0.0.1")

    def test_sorting_and_pagination(self):
        for index in range(105):
            self._log_packet(
                f"2026-06-08T10:{index // 60:02d}:{index % 60:02d}",
                f"10.0.0.{index}",
                "10.0.1.1",
                "TCP",
                1000 + index,
                80,
                60 + index,
            )

        rows, total = self.database.get_traffic(
            sort_by="packet_size",
            sort_order="ASC",
            page=2,
            per_page=100,
        )

        self.assertEqual(total, 105)
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["packet_size"], 160)

    def _log_packet(
        self,
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_size,
    ):
        self.database.log_traffic(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            packet_size=packet_size,
        )


if __name__ == "__main__":
    unittest.main()
