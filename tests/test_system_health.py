from pathlib import Path
from tempfile import TemporaryDirectory
import os
import sqlite3
import unittest
from unittest.mock import patch

from excalibur.dashboard.app import create_app
from excalibur.database import Database


class SystemHealthTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir.name)
        self.db_path = Path(self.temp_dir.name) / "system.sqlite"
        self.database = Database(self.db_path)
        self.database._get_system_health_history().reset()

    def tearDown(self):
        if self.database is not None:
            self.database.close()
        Database._get_system_health_history().reset()
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def test_system_health_tracks_database_metrics_and_io_estimates(self):
        self.database.add_host(
            "10.0.0.10",
            "00:11:22:33:44:55",
            "2026-06-08T10:00:00",
            "2026-06-08T10:00:00",
        )
        self.database.log_traffic(
            "2026-06-08T10:00:01",
            "10.0.0.10",
            "10.0.0.1",
            "TCP",
            12345,
            80,
            512,
        )
        self.database.log_dns_query(
            "2026-06-08T10:00:02",
            "10.0.0.10",
            "10.0.0.1",
            "example.com",
            "A",
        )
        self.database.create_alert(
            "2026-06-08T10:00:03",
            "Medium",
            "Possible Port Scan",
            "Test alert",
        )
        self.database.get_traffic()
        self.database.get_dns_queries()
        self.database.get_domains()
        self.database.get_alerts()
        self.database.get_hosts()

        health = self.database.get_system_health()

        self.assertEqual(health["database"]["traffic_records"], 1)
        self.assertEqual(health["database"]["dns_queries"], 1)
        self.assertEqual(health["database"]["unique_domains"], 1)
        self.assertEqual(health["database"]["alerts"], 1)
        self.assertEqual(health["database"]["hosts"], 1)
        self.assertEqual(health["writes"]["traffic_records_written"], 1)
        self.assertEqual(health["writes"]["dns_queries_written"], 1)
        self.assertEqual(health["writes"]["unique_domains_discovered"], 1)
        self.assertEqual(health["writes"]["alerts_written"], 1)
        self.assertEqual(health["writes"]["hosts_added"], 1)
        self.assertGreaterEqual(health["reads"]["dashboard_queries_executed"], 5)
        self.assertGreater(health["writes"]["estimated_bytes_written"], 0)
        self.assertGreater(health["reads"]["estimated_bytes_read"], 0)
        self.assertIn(health["database"]["journal_mode"], {"DELETE", "WAL", "MEMORY", "OFF"})

    def test_system_health_route_renders(self):
        app = create_app(self.db_path)
        response = app.test_client().get("/system")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("System Health", html)
        self.assertIn("Database Metrics", html)
        self.assertIn("Retention Status", html)
        self.assertIn("Excalibur Process", html)
        self.assertIn("process-history-chart", html)
        self.assertIn("sensor-history-chart", html)

    def test_system_health_includes_process_metrics(self):
        with patch.object(Database, "_get_process_metrics", return_value={
            "available": True,
            "cpu_percent": 3.12,
            "cpu_percent_raw": 12.5,
            "logical_cpu_count": 4,
            "memory_rss_bytes": 104857600,
            "memory_rss_mb": 100.0,
            "memory_percent": 3.2,
            "thread_count": 7,
            "uptime_seconds": 3661,
            "uptime_display": "1h 1m 1s",
        }):
            health = self.database.get_system_health()

        self.assertTrue(health["process"]["available"])
        self.assertEqual(health["process"]["cpu_percent"], 3.12)
        self.assertEqual(health["process"]["cpu_percent_raw"], 12.5)
        self.assertEqual(health["process"]["logical_cpu_count"], 4)
        self.assertEqual(health["process"]["memory_rss_mb"], 100.0)
        self.assertEqual(health["process"]["memory_percent"], 3.2)
        self.assertEqual(health["process"]["thread_count"], 7)
        self.assertEqual(health["process"]["uptime_display"], "1h 1m 1s")

    def test_system_health_json_route_returns_process_metrics(self):
        app = create_app(self.db_path)
        with patch.object(Database, "_get_process_metrics", return_value={
            "available": True,
            "cpu_percent": 1.62,
            "cpu_percent_raw": 6.5,
            "logical_cpu_count": 4,
            "memory_rss_bytes": 52428800,
            "memory_rss_mb": 50.0,
            "memory_percent": 1.2,
            "thread_count": 5,
            "uptime_seconds": 90,
            "uptime_display": "1m 30s",
        }):
            response = app.test_client().get("/system?format=json")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("process", payload)
        self.assertEqual(payload["process"]["thread_count"], 5)
        self.assertEqual(payload["process"]["uptime_display"], "1m 30s")
        self.assertEqual(payload["process"]["cpu_percent_raw"], 6.5)
        self.assertIn("history", payload)

    def test_process_metrics_normalize_cpu_by_logical_cpu_count(self):
        process_mock = unittest.mock.Mock()
        process_mock.cpu_percent.return_value = 20.0
        process_mock.memory_info.return_value = unittest.mock.Mock(rss=10485760)
        process_mock.memory_percent.return_value = 1.5
        process_mock.num_threads.return_value = 3
        process_mock.create_time.return_value = 1000

        with patch.object(Database, "_sensor_process", return_value=process_mock):
            with patch("excalibur.database.db.psutil.cpu_count", return_value=8):
                with patch("excalibur.database.db.time.time", return_value=1060):
                    metrics = self.database._get_process_metrics()

        self.assertEqual(metrics["cpu_percent_raw"], 20.0)
        self.assertEqual(metrics["cpu_percent"], 2.5)
        self.assertEqual(metrics["logical_cpu_count"], 8)

    def test_sensor_process_matcher_accepts_sensor_entrypoints(self):
        self.assertTrue(
            Database._is_sensor_process_info(
                {"cmdline": [r"C:\Python\python.exe", r"D:\Excalibur\excalibur\main.py"]}
            )
        )
        self.assertTrue(
            Database._is_sensor_process_info(
                {"cmdline": [r"C:\Python\python.exe", "-m", "excalibur.main"]}
            )
        )

    def test_sensor_process_matcher_rejects_dashboard_and_helper_entrypoints(self):
        self.assertFalse(
            Database._is_sensor_process_info(
                {
                    "cmdline": [
                        r"C:\Python\python.exe",
                        "-m",
                        "flask",
                        "--app",
                        r"excalibur\dashboard\app.py",
                        "run",
                    ]
                }
            )
        )
        self.assertFalse(
            Database._is_sensor_process_info(
                {
                    "cmdline": [
                        r"C:\Python\python.exe",
                        "-m",
                        "excalibur.helper.windows_server",
                    ]
                }
            )
        )

    def test_sensor_process_logs_windows_candidates_for_selected_sensor(self):
        class _FakeProcess:
            def __init__(self, info):
                self.info = info
                self.pid = info["pid"]

            def cpu_percent(self, interval=None):
                return 0.0

            def create_time(self):
                return float(self.pid)

        helper = _FakeProcess(
            {
                "pid": 10,
                "cmdline": [r"C:\Python\python.exe", "-m", "excalibur.helper.windows_server"],
                "exe": r"C:\Python\python.exe",
                "name": "python.exe",
            }
        )
        sensor = _FakeProcess(
            {
                "pid": 11,
                "cmdline": [r"C:\Python\python.exe", r"D:\Excalibur\excalibur\main.py"],
                "exe": r"C:\Python\python.exe",
                "name": "python.exe",
            }
        )

        with patch("excalibur.database.db._SENSOR_PROCESS_HANDLE", None):
            with patch("excalibur.database.db._SENSOR_PROCESS_PID", None):
                with patch("excalibur.database.db.os.name", "nt"):
                    with patch(
                        "excalibur.database.db.psutil.process_iter",
                        return_value=[helper, sensor],
                    ):
                        with patch("builtins.print") as print_mock:
                            selected = Database._sensor_process()

        self.assertIs(selected, sensor)
        printed_lines = [" ".join(str(arg) for arg in call.args) for call in print_mock.call_args_list]
        self.assertTrue(
            any("Selected sensor process on Windows" in line for line in printed_lines)
        )
        self.assertTrue(
            any(
                "Selection reason: process_enumeration_fallback" in line
                for line in printed_lines
            )
        )
        self.assertTrue(any("PID: 11" in line for line in printed_lines))
        self.assertTrue(any("PID: 10" in line for line in printed_lines))

    def test_sensor_process_prefers_windows_service_pid(self):
        class _FakeProcess:
            def __init__(self, info):
                self.info = info
                self.pid = info["pid"]
                self._children = []

            def cpu_percent(self, interval=None):
                return 0.0

            def as_dict(self, attrs=None):
                return dict(self.info)

            def create_time(self):
                return float(self.pid)

            def children(self, recursive=False):
                return list(self._children)

        helper = _FakeProcess(
            {
                "pid": 10,
                "cmdline": [r"C:\Python\python.exe", "-m", "excalibur.helper.windows_server"],
                "exe": r"C:\Python\python.exe",
                "name": "python.exe",
            }
        )
        manual_sensor = _FakeProcess(
            {
                "pid": 11,
                "cmdline": [r"C:\Python\python.exe", r"D:\Excalibur\excalibur\main.py"],
                "exe": r"C:\Python\python.exe",
                "name": "python.exe",
            }
        )
        service_sensor = _FakeProcess(
            {
                "pid": 22,
                "cmdline": [r"C:\Program Files\Excalibur\.venv\Scripts\python.exe", r"D:\Excalibur\excalibur\main.py"],
                "exe": r"C:\Program Files\Excalibur\.venv\Scripts\python.exe",
                "name": "python.exe",
            }
        )
        service_mock = unittest.mock.Mock()
        service_mock.as_dict.return_value = {"pid": 22, "status": "running"}

        with patch("excalibur.database.db._SENSOR_PROCESS_HANDLE", None):
            with patch("excalibur.database.db._SENSOR_PROCESS_PID", None):
                with patch("excalibur.database.db.os.name", "nt"):
                    with patch(
                        "excalibur.database.db.psutil.process_iter",
                        return_value=[helper, manual_sensor],
                    ):
                        with patch(
                            "excalibur.database.db.psutil.win_service_get",
                            return_value=service_mock,
                            create=True,
                        ):
                            with patch(
                                "excalibur.database.db.psutil.Process",
                                return_value=service_sensor,
                            ):
                                with patch("builtins.print") as print_mock:
                                    selected = Database._sensor_process()

        self.assertIs(selected, service_sensor)
        printed_lines = [" ".join(str(arg) for arg in call.args) for call in print_mock.call_args_list]
        self.assertTrue(
            any("Selection reason: windows_service_lookup" in line for line in printed_lines)
        )
        self.assertTrue(any("PID: 22" in line for line in printed_lines))

    def test_sensor_process_prefers_windows_service_child_worker(self):
        class _FakeProcess:
            def __init__(self, info, children=None):
                self.info = info
                self.pid = info["pid"]
                self._children = list(children or [])

            def cpu_percent(self, interval=None):
                return 0.0

            def as_dict(self, attrs=None):
                return dict(self.info)

            def create_time(self):
                return float(self.pid)

            def children(self, recursive=False):
                if not recursive:
                    return list(self._children)
                descendants = []
                for child in self._children:
                    descendants.append(child)
                    descendants.extend(child.children(recursive=True))
                return descendants

        service_child = _FakeProcess(
            {
                "pid": 33,
                "cmdline": [r"C:\Program Files\Excalibur\.venv\Scripts\python.exe", r"D:\Excalibur\excalibur\main.py"],
                "exe": r"C:\Program Files\Excalibur\.venv\Scripts\python.exe",
                "name": "python.exe",
            }
        )
        service_parent = _FakeProcess(
            {
                "pid": 22,
                "cmdline": [r"C:\Program Files\Excalibur\.venv\Scripts\python.exe", r"D:\Excalibur\excalibur\main.py"],
                "exe": r"C:\Program Files\Excalibur\.venv\Scripts\python.exe",
                "name": "python.exe",
            },
            children=[service_child],
        )
        service_mock = unittest.mock.Mock()
        service_mock.as_dict.return_value = {"pid": 22, "status": "running"}

        with patch("excalibur.database.db._SENSOR_PROCESS_HANDLE", None):
            with patch("excalibur.database.db._SENSOR_PROCESS_PID", None):
                with patch("excalibur.database.db.os.name", "nt"):
                    with patch(
                        "excalibur.database.db.psutil.process_iter",
                        return_value=[service_parent, service_child],
                    ):
                        with patch(
                            "excalibur.database.db.psutil.win_service_get",
                            return_value=service_mock,
                            create=True,
                        ):
                            with patch(
                                "excalibur.database.db.psutil.Process",
                                return_value=service_parent,
                            ):
                                with patch("builtins.print") as print_mock:
                                    selected = Database._sensor_process()

        self.assertIs(selected, service_child)
        printed_lines = [" ".join(str(arg) for arg in call.args) for call in print_mock.call_args_list]
        self.assertTrue(
            any(
                "Selection reason: windows_service_child_worker" in line
                for line in printed_lines
            )
        )
        self.assertTrue(any("PID: 33" in line for line in printed_lines))

    def test_sensor_process_prefers_deepest_windows_service_child_worker(self):
        class _FakeProcess:
            def __init__(self, info, children=None):
                self.info = info
                self.pid = info["pid"]
                self._children = list(children or [])

            def cpu_percent(self, interval=None):
                return 0.0

            def as_dict(self, attrs=None):
                return dict(self.info)

            def create_time(self):
                return float(self.pid)

            def children(self, recursive=False):
                if not recursive:
                    return list(self._children)
                descendants = []
                for child in self._children:
                    descendants.append(child)
                    descendants.extend(child.children(recursive=True))
                return descendants

        deepest_worker = _FakeProcess(
            {
                "pid": 44,
                "cmdline": [r"C:\Program Files\Excalibur\.venv\Scripts\python.exe", r"D:\Excalibur\excalibur\main.py"],
                "exe": r"C:\Python313\python.exe",
                "name": "python.exe",
            }
        )
        intermediate_worker = _FakeProcess(
            {
                "pid": 33,
                "cmdline": [r"C:\Program Files\Excalibur\.venv\Scripts\python.exe", r"D:\Excalibur\excalibur\main.py"],
                "exe": r"C:\Program Files\Excalibur\.venv\Scripts\python.exe",
                "name": "python.exe",
            },
            children=[deepest_worker],
        )
        service_parent = _FakeProcess(
            {
                "pid": 22,
                "cmdline": [r"C:\Program Files\Excalibur\.venv\Scripts\python.exe", r"D:\Excalibur\excalibur\main.py"],
                "exe": r"C:\Program Files\Excalibur\.venv\Scripts\python.exe",
                "name": "python.exe",
            },
            children=[intermediate_worker],
        )
        service_mock = unittest.mock.Mock()
        service_mock.as_dict.return_value = {"pid": 22, "status": "running"}

        with patch("excalibur.database.db._SENSOR_PROCESS_HANDLE", None):
            with patch("excalibur.database.db._SENSOR_PROCESS_PID", None):
                with patch("excalibur.database.db.os.name", "nt"):
                    with patch(
                        "excalibur.database.db.psutil.process_iter",
                        return_value=[service_parent, intermediate_worker, deepest_worker],
                    ):
                        with patch(
                            "excalibur.database.db.psutil.win_service_get",
                            return_value=service_mock,
                            create=True,
                        ):
                            with patch(
                                "excalibur.database.db.psutil.Process",
                                return_value=service_parent,
                            ):
                                selected = Database._sensor_process()

        self.assertIs(selected, deepest_worker)

    def test_sensor_process_invalidates_cached_pid_when_create_time_changes(self):
        class _CachedProcess:
            pid = 44

            def is_running(self):
                return True

            def create_time(self):
                return 2000.0

        class _FreshProcess:
            def __init__(self, info, create_time_value):
                self.info = info
                self.pid = info["pid"]
                self._create_time = create_time_value

            def cpu_percent(self, interval=None):
                return 0.0

            def create_time(self):
                return self._create_time

        stale_cached = _CachedProcess()
        fresh_sensor = _FreshProcess(
            {
                "pid": 44,
                "cmdline": [r"C:\Python\python.exe", r"D:\Excalibur\excalibur\main.py"],
                "exe": r"C:\Python\python.exe",
                "name": "python.exe",
            },
            3000.0,
        )

        with patch("excalibur.database.db._SENSOR_PROCESS_HANDLE", stale_cached):
            with patch("excalibur.database.db._SENSOR_PROCESS_PID", 44):
                with patch("excalibur.database.db._SENSOR_PROCESS_CREATE_TIME", 1000.0):
                    with patch(
                        "excalibur.database.db.psutil.process_iter",
                        return_value=[fresh_sensor],
                    ):
                        selected = Database._sensor_process()

        self.assertIs(selected, fresh_sensor)

    def test_system_health_history_computes_rates(self):
        history = self.database._get_system_health_history()
        with patch("excalibur.database.db.time.time", side_effect=[1000, 1005]):
            first = history.record(
                {"cpu_percent": 10.0, "cpu_percent_raw": 40.0, "memory_rss_mb": 100.0},
                {
                    "traffic_records_written": 10,
                    "dns_queries_written": 5,
                    "alerts_written": 1,
                },
            )
            second = history.record(
                {"cpu_percent": 20.0, "cpu_percent_raw": 80.0, "memory_rss_mb": 120.0},
                {
                    "traffic_records_written": 20,
                    "dns_queries_written": 15,
                    "alerts_written": 6,
                },
            )

        self.assertEqual(len(first["samples"]), 1)
        self.assertEqual(len(second["samples"]), 2)
        latest = second["samples"][-1]
        self.assertEqual(latest["cpu_percent"], 20.0)
        self.assertEqual(latest["cpu_percent_raw"], 80.0)
        self.assertEqual(latest["packets_per_second"], 2.0)
        self.assertEqual(latest["dns_queries_per_second"], 2.0)
        self.assertEqual(latest["alerts_per_second"], 1.0)

    def test_system_health_history_uses_fixed_size_ring_buffer(self):
        history = self.database._get_system_health_history()
        for index in range(history.MAX_SAMPLES + 8):
            with patch("excalibur.database.db.time.time", return_value=1000 + (index * 5)):
                snapshot = history.record(
                    {
                        "cpu_percent": float(index),
                        "cpu_percent_raw": float(index * 2),
                        "memory_rss_mb": float(index),
                    },
                    {
                        "traffic_records_written": index,
                        "dns_queries_written": index,
                        "alerts_written": index,
                    },
                )

        self.assertEqual(len(snapshot["samples"]), history.MAX_SAMPLES)
        self.assertEqual(snapshot["samples"][0]["cpu_percent"], 8.0)

    def test_reconcile_system_metrics_backfills_existing_rows(self):
        self.database.close()
        self.database = None
        self._insert_rows_without_metrics()

        self.database = Database(self.db_path)
        self.database.reconcile_system_metrics()
        health = self.database.get_system_health()

        self.assertEqual(health["writes"]["traffic_records_written"], 2)
        self.assertEqual(health["writes"]["dns_queries_written"], 1)
        self.assertEqual(health["writes"]["unique_domains_discovered"], 1)
        self.assertEqual(health["writes"]["alerts_written"], 1)
        self.assertEqual(health["writes"]["hosts_added"], 1)
        self.assertEqual(health["writes"]["total_writes"], 6)

    def test_reconcile_system_metrics_preserves_larger_existing_metrics(self):
        self.database.close()
        self.database = None
        self._insert_rows_without_metrics()
        connection = sqlite3.connect(self.db_path)
        try:
            for name, value in {
                "traffic_records_written": 10,
                "dns_queries_written": 9,
                "unique_domains_discovered": 8,
                "alerts_written": 7,
                "hosts_added": 6,
                "total_writes": 999,
            }.items():
                connection.execute(
                    """
                    INSERT INTO system_metrics (name, value)
                    VALUES (?, ?)
                    ON CONFLICT(name) DO UPDATE SET value = excluded.value
                    """,
                    (name, value),
                )
            connection.commit()
        finally:
            connection.close()

        self.database = Database(self.db_path)
        self.database.reconcile_system_metrics()
        health = self.database.get_system_health()

        self.assertEqual(health["writes"]["traffic_records_written"], 10)
        self.assertEqual(health["writes"]["dns_queries_written"], 9)
        self.assertEqual(health["writes"]["unique_domains_discovered"], 8)
        self.assertEqual(health["writes"]["alerts_written"], 7)
        self.assertEqual(health["writes"]["hosts_added"], 6)
        self.assertEqual(health["writes"]["total_writes"], 40)

    def test_reconcile_system_metrics_recalculates_total_writes(self):
        self.database.close()
        self.database = None
        connection = sqlite3.connect(self.db_path)
        try:
            for name, value in {
                "traffic_records_written": 3,
                "dns_queries_written": 4,
                "unique_domains_discovered": 5,
                "alerts_written": 6,
                "hosts_added": 7,
                "total_writes": 1,
            }.items():
                connection.execute(
                    """
                    INSERT INTO system_metrics (name, value)
                    VALUES (?, ?)
                    ON CONFLICT(name) DO UPDATE SET value = excluded.value
                    """,
                    (name, value),
                )
            connection.commit()
        finally:
            connection.close()

        self.database = Database(self.db_path)
        self.database.reconcile_system_metrics()
        health = self.database.get_system_health()

        self.assertEqual(health["writes"]["total_writes"], 25)

    def test_database_init_does_not_run_reconcile_system_metrics(self):
        self.database.close()
        self.database = None

        with patch.object(Database, "reconcile_system_metrics") as reconcile_mock:
            self.database = Database(self.db_path)

        reconcile_mock.assert_not_called()

    def test_format_duration_formats_process_uptime(self):
        self.assertEqual(Database._format_duration(59), "59s")
        self.assertEqual(Database._format_duration(61), "1m 1s")
        self.assertEqual(Database._format_duration(3661), "1h 1m 1s")
        self.assertEqual(Database._format_duration(90061), "1d 1h 1m 1s")

    def _insert_rows_without_metrics(self):
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute(
                """
                INSERT INTO traffic (
                    timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                ("2026-06-08T10:00:00", "10.0.0.1", "10.0.0.2", "TCP", 1111, 80, 60),
            )
            connection.execute(
                """
                INSERT INTO traffic (
                    timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                ("2026-06-08T10:00:01", "10.0.0.3", "10.0.0.4", "UDP", 2222, 53, 70),
            )
            connection.execute(
                """
                INSERT INTO dns_queries (
                    timestamp, client_ip, dns_server_ip, query_name, query_type
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                ("2026-06-08T10:00:02", "10.0.0.1", "10.0.0.2", "example.com", "A"),
            )
            connection.execute(
                """
                INSERT INTO domains (domain, first_seen, last_seen, query_count)
                VALUES (?, ?, ?, ?)
                """,
                ("example.com", "2026-06-08T10:00:02", "2026-06-08T10:00:02", 1),
            )
            connection.execute(
                """
                INSERT INTO alerts (timestamp, severity, title, description)
                VALUES (?, ?, ?, ?)
                """,
                ("2026-06-08T10:00:03", "Medium", "Test Alert", "Test"),
            )
            connection.execute(
                """
                INSERT INTO hosts (ip_address, mac_address, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                """,
                ("10.0.0.1", None, "2026-06-08T10:00:00", "2026-06-08T10:00:00"),
            )
            connection.commit()
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
