from pathlib import Path
from queue import Queue
from tempfile import TemporaryDirectory
import os
import time
import unittest
from unittest.mock import patch

from excalibur.database import Database


class AsyncWriterPipelineTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir.name)
        self.db_path = Path(self.temp_dir.name) / "async-writer.sqlite"
        self.database = Database(self.db_path, async_writes=True)

    def tearDown(self):
        if self.database is not None:
            self.database.close()
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def _domain_state(self, domain):
        risk_result = self.database.analyze_domain_risk(domain)
        return {
            "first_seen": "2026-07-01T00:00:00",
            "last_seen": "2026-07-01T00:00:01",
            "query_count": 1,
            "risk_result": risk_result,
            "is_new": True,
        }

    def test_flush_domain_updates_uses_batched_database_operations(self):
        class _ConnectionProxy:
            def __init__(self, connection):
                self._connection = connection
                self.executemany_calls = []
                self.execute_calls = []

            def executemany(self, sql, params):
                self.executemany_calls.append(sql)
                return self._connection.executemany(sql, params)

            def execute(self, sql, params=()):
                self.execute_calls.append(sql)
                return self._connection.execute(sql, params)

            def __getattr__(self, name):
                return getattr(self._connection, name)

        domain_updates = {
            "a.example.com": self._domain_state("a.example.com"),
            "b.example.com": self._domain_state("b.example.com"),
            "c.example.com": self._domain_state("c.example.com"),
        }
        proxy = _ConnectionProxy(self.database.connection)
        self.database.connection = proxy
        domains_to_log = self.database._flush_domain_updates_locked(domain_updates)
        self.assertEqual(set(domains_to_log), set(domain_updates))
        self.assertEqual(len(proxy.executemany_calls), 2)
        executed_sql = proxy.execute_calls
        self.assertFalse(
            any("INSERT INTO domains" in sql for sql in executed_sql)
        )
        self.assertFalse(
            any("INSERT INTO domain_risk" in sql for sql in executed_sql)
        )

    def test_domain_log_append_happens_after_database_lock_is_released(self):
        self.database._pending_domain_updates = {
            "example.com": self._domain_state("example.com"),
        }
        lock_owned_states = []

        def record_domains(domains):
            lock_owned_states.append(self.database._lock._is_owned())

        with patch.object(self.database, "_append_new_domains", side_effect=record_domains):
            self.database._flush_pending_writes(
                traffic_rows=[],
                dns_rows=[],
                flush_domains=True,
                flush_hosts=False,
                flush_metrics=False,
            )

        self.assertEqual(lock_owned_states, [False])

    def test_bounded_side_work_leaves_remaining_domain_updates_queued(self):
        self.database._pending_domain_updates = {
            f"domain{index}.example.com": self._domain_state(f"domain{index}.example.com")
            for index in range(5)
        }

        flush_stats = self.database._flush_pending_writes(
            traffic_rows=[],
            dns_rows=[],
            flush_domains=True,
            flush_hosts=False,
            flush_metrics=False,
            domain_limit=2,
        )

        self.assertEqual(flush_stats["domain_updates"], 2)
        self.assertTrue(flush_stats["remaining_side_work"])
        self.assertEqual(len(self.database._pending_domain_updates), 3)

    def test_multiple_bounded_flushes_preserve_all_domain_updates(self):
        domains = [f"domain{index}.example.com" for index in range(5)]
        self.database._pending_domain_updates = {
            domain: self._domain_state(domain)
            for domain in domains
        }

        while self.database._pending_domain_updates:
            self.database._flush_pending_writes(
                traffic_rows=[],
                dns_rows=[],
                flush_domains=True,
                flush_hosts=False,
                flush_metrics=False,
                domain_limit=2,
            )

        stored_domains, total = self.database.get_domains()
        logged_domains = (
            self.database.runtime_data_dir / "domains.log"
        ).read_text(encoding="utf-8").splitlines()

        self.assertEqual(total, 5)
        self.assertEqual({row["domain"] for row in stored_domains}, set(domains))
        self.assertEqual(set(logged_domains), set(domains))

    def test_queue_full_warnings_are_rate_limited_and_drop_count_stays_exact(self):
        self.database._write_queue = Queue(maxsize=1)
        self.database._write_queue.put_nowait({"kind": "traffic", "row": ("x",)})

        with patch.object(self.database, "_ensure_writer_thread"):
            with patch("excalibur.database.db.time.monotonic", side_effect=[10.0, 10.5, 11.0]):
                with patch("builtins.print") as print_mock:
                    for _ in range(3):
                        self.assertTrue(self.database._enqueue_write("traffic", ("row",)))

        warning_lines = [
            " ".join(str(arg) for arg in call.args)
            for call in print_mock.call_args_list
            if "SQLite writer queue full; dropped" in " ".join(str(arg) for arg in call.args)
        ]
        self.assertEqual(len(warning_lines), 1)
        self.assertEqual(self.database._writer_overflow_drop_total, 3)
        self.assertEqual(self.database._writer_overflow_drop_lifetime_total, 3)

    def test_writer_performs_immediate_consecutive_flushes_under_pressure(self):
        self.database.WRITE_BATCH_SIZE = 1
        self.database.WRITE_BATCH_SIZE_LOW = 1
        self.database.WRITE_BATCH_SIZE_HIGH = 1
        self.database.WRITE_BATCH_SIZE_CRITICAL = 1
        self.database.WRITE_PRESSURE_CONTINUE_DEPTH = 1
        self.database.WRITE_FLUSH_INTERVAL_SECONDS = 1.0

        for index in range(3):
            self.database._write_queue.put_nowait(
                {
                    "kind": "traffic",
                    "row": (
                        f"2026-07-01T00:00:0{index}",
                        "10.0.0.1",
                        "10.0.0.2",
                        "TCP",
                        1000 + index,
                        443,
                        128,
                    ),
                }
            )

        original_flush_pending_writes = self.database._flush_pending_writes
        flush_calls = []

        def wrapped_flush_pending_writes(*args, **kwargs):
            result = original_flush_pending_writes(*args, **kwargs)
            flush_calls.append(result)
            if self.database._write_queue.empty():
                self.database._writer_stop_event.set()
                self.database._writer_flush_event.set()
            return result

        self.database._flush_pending_writes = wrapped_flush_pending_writes
        started_at = time.perf_counter()
        self.database._ensure_writer_thread()
        self.database._writer_thread.join(timeout=2)
        elapsed = time.perf_counter() - started_at

        self.assertFalse(self.database._writer_thread.is_alive())
        self.assertLess(elapsed, 0.5)
        self.assertGreaterEqual(len(flush_calls), 3)
