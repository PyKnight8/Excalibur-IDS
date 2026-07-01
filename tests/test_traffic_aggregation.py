from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.database import Database


class TrafficAggregationTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.database = Database(Path(self.temp_dir.name) / "traffic-aggregation.sqlite", async_writes=True)

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_same_second_flow_collapses_into_one_record(self):
        self._log_packet("2026-07-01T12:00:00.100", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 100)
        self._log_packet("2026-07-01T12:00:00.900", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 200)

        self.database._flush_for_read()
        rows, total = self.database.get_traffic(sort_by="timestamp", sort_order="ASC")

        self.assertEqual(total, 1)
        row = rows[0]
        self.assertEqual(row["timestamp"], "2026-07-01T12:00:00")
        self.assertEqual(row["packet_count"], 2)
        self.assertEqual(row["byte_count"], 300)
        self.assertEqual(row["first_seen"], "2026-07-01T12:00:00.100")
        self.assertEqual(row["last_seen"], "2026-07-01T12:00:00.900")

    def test_different_flows_remain_separate(self):
        self._log_packet("2026-07-01T12:00:00.100", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 100)
        self._log_packet("2026-07-01T12:00:00.200", "10.0.0.1", "10.0.0.3", "TCP", 1234, 443, 100)

        self.database._flush_for_read()
        _, total = self.database.get_traffic()

        self.assertEqual(total, 2)
        self.assertEqual(self.database.count_traffic_packets(), 2)

    def test_different_timestamp_buckets_remain_separate(self):
        self._log_packet("2026-07-01T12:00:00.999", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 100)
        self._log_packet("2026-07-01T12:00:01.001", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 100)

        self.database._flush_for_read()
        rows, total = self.database.get_traffic(sort_by="timestamp", sort_order="ASC")

        self.assertEqual(total, 2)
        self.assertEqual([row["timestamp"] for row in rows], ["2026-07-01T12:00:00", "2026-07-01T12:00:01"])

    def test_protocols_without_ports_aggregate_consistently(self):
        self._log_packet("2026-07-01T12:00:00.100", "10.0.0.1", "10.0.0.2", "ICMP", None, None, 64)
        self._log_packet("2026-07-01T12:00:00.800", "10.0.0.1", "10.0.0.2", "ICMP", None, None, 96)

        self.database._flush_for_read()
        rows, total = self.database.get_traffic()

        self.assertEqual(total, 1)
        row = rows[0]
        self.assertIsNone(row["src_port"])
        self.assertIsNone(row["dst_port"])
        self.assertEqual(row["packet_count"], 2)
        self.assertEqual(row["byte_count"], 160)

    def test_same_flow_across_multiple_flushes_merges_into_one_record(self):
        self.database._flush_pending_writes(
            traffic_rows=[
                ("2026-07-01T12:00:00.100", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 100),
            ],
            dns_rows=[],
            flush_domains=False,
            flush_hosts=False,
            flush_metrics=False,
        )
        self.database._flush_pending_writes(
            traffic_rows=[
                ("2026-07-01T12:00:00.900", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 200),
            ],
            dns_rows=[],
            flush_domains=False,
            flush_hosts=False,
            flush_metrics=False,
        )

        rows, total = self.database.get_traffic()
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["packet_count"], 2)
        self.assertEqual(rows[0]["byte_count"], 300)
        self.assertEqual(self.database.count_traffic_packets(), 2)

    def test_legacy_rows_remain_readable(self):
        with self.database._lock:
            with self.database.connection:
                self.database.connection.execute(
                    """
                    INSERT INTO traffic (
                        timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("2026-07-01T12:00:00", "10.0.0.10", "10.0.0.20", "UDP", 53000, 53, 128),
                )

        rows, total = self.database.get_traffic()
        self.assertEqual(total, 1)
        row = rows[0]
        self.assertEqual(row["packet_count"], 1)
        self.assertEqual(row["byte_count"], 128)
        self.assertEqual(row["first_seen"], "2026-07-01T12:00:00")
        self.assertEqual(row["last_seen"], "2026-07-01T12:00:00")

    def test_packet_and_byte_totals_use_aggregated_sums(self):
        self._log_packet("2026-07-01T12:00:00.100", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 100)
        self._log_packet("2026-07-01T12:00:00.200", "10.0.0.1", "10.0.0.2", "TCP", 1234, 443, 200)
        self._log_packet("2026-07-01T12:00:01.200", "10.0.0.3", "10.0.0.4", "UDP", 5050, 53, 50)

        self.database._flush_for_read()
        health = self.database.get_system_health()

        self.assertEqual(self.database.count_traffic(), 2)
        self.assertEqual(self.database.count_traffic_packets(), 3)
        self.assertEqual(self.database.count_traffic_bytes(), 350)
        self.assertEqual(health["database"]["traffic_records"], 2)
        self.assertEqual(health["database"]["traffic_packets"], 3)
        self.assertEqual(health["database"]["traffic_bytes"], 350)
        self.assertEqual(health["writes"]["traffic_records_written"], 3)

    def test_retention_keeps_aggregated_totals_intact(self):
        self.database._flush_pending_writes(
            traffic_rows=[
                ("2026-07-01T12:00:00.100", "10.0.0.1", "10.0.0.2", "TCP", 1000, 80, 100),
                ("2026-07-01T12:00:00.200", "10.0.0.1", "10.0.0.2", "TCP", 1000, 80, 100),
            ],
            dns_rows=[],
            flush_domains=False,
            flush_hosts=False,
            flush_metrics=False,
        )
        self.database._flush_pending_writes(
            traffic_rows=[
                ("2026-07-01T12:00:01.100", "10.0.0.3", "10.0.0.4", "TCP", 2000, 443, 150),
                ("2026-07-01T12:00:01.200", "10.0.0.3", "10.0.0.4", "TCP", 2000, 443, 150),
                ("2026-07-01T12:00:01.300", "10.0.0.3", "10.0.0.4", "TCP", 2000, 443, 150),
            ],
            dns_rows=[],
            flush_domains=False,
            flush_hosts=False,
            flush_metrics=False,
        )

        purged = self.database.enforce_traffic_limit(1)
        rows, total = self.database.get_traffic()

        self.assertEqual(purged, 1)
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["packet_count"], 3)
        self.assertEqual(rows[0]["byte_count"], 450)
        self.assertEqual(self.database.count_traffic_packets(), 3)

    def test_multi_row_insert_chunking_respects_sqlite_parameter_limits(self):
        class _ConnectionProxy:
            def __init__(self, connection):
                self._connection = connection
                self.insert_param_lengths = []

            def __enter__(self):
                self._connection.__enter__()
                return self

            def __exit__(self, exc_type, exc, tb):
                return self._connection.__exit__(exc_type, exc, tb)

            def execute(self, sql, params=()):
                if "INSERT INTO traffic" in sql:
                    self.insert_param_lengths.append(len(params))
                return self._connection.execute(sql, params)

            def executemany(self, sql, params):
                return self._connection.executemany(sql, params)

            def __getattr__(self, name):
                return getattr(self._connection, name)

        proxy = _ConnectionProxy(self.database.connection)
        self.database.connection = proxy
        traffic_rows = [
            (
                f"2026-07-01T12:00:{index:02d}",
                f"10.0.0.{index}",
                f"10.0.1.{index}",
                "TCP",
                1000 + index,
                443,
                128,
                1,
                128,
                f"2026-07-01T12:00:{index:02d}",
                f"2026-07-01T12:00:{index:02d}",
            )
            for index in range(Database.TRAFFIC_INSERT_CHUNK_SIZE * 2 + 5)
        ]

        with self.database._lock:
            with self.database.connection:
                inserted = self.database._insert_traffic_rows_locked(traffic_rows)

        self.assertEqual(inserted, len(traffic_rows))
        self.assertGreater(len(proxy.insert_param_lengths), 1)
        self.assertTrue(
            all(length <= Database.SQLITE_MAX_VARIABLES for length in proxy.insert_param_lengths)
        )

    def _log_packet(self, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size):
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
