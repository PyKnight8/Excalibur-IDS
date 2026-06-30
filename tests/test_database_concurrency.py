from pathlib import Path
from tempfile import TemporaryDirectory
import os
import sqlite3
import unittest

from excalibur.database import Database


class DatabaseConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir.name)
        self.db_path = Path(self.temp_dir.name) / "concurrency.sqlite"
        self.writer_database = Database(self.db_path)
        self.reader_database = Database(self.db_path)
        self.writer_database.log_dns_query(
            timestamp="2026-06-08T10:00:00+00:00",
            client_ip="10.0.0.10",
            dns_server_ip="10.0.0.1",
            query_name="example.com",
            query_type="A",
        )

    def tearDown(self):
        self.reader_database.close()
        self.writer_database.close()
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def test_database_initializes_wal_mode_and_busy_timeout(self):
        journal_mode = self.reader_database.connection.execute(
            "PRAGMA journal_mode"
        ).fetchone()[0].upper()
        busy_timeout = self.reader_database.connection.execute(
            "PRAGMA busy_timeout"
        ).fetchone()[0]

        self.assertEqual(journal_mode, "WAL")
        self.assertEqual(busy_timeout, 5000)

    def test_get_dns_queries_does_not_raise_when_metrics_write_is_locked(self):
        lock_holder = sqlite3.connect(self.db_path, timeout=5.0, check_same_thread=False)
        lock_holder.execute("PRAGMA journal_mode=WAL")
        lock_holder.execute("PRAGMA busy_timeout = 5000")
        self.reader_database.connection.execute("PRAGMA busy_timeout = 50")

        try:
            lock_holder.execute("BEGIN IMMEDIATE")
            lock_holder.execute(
                """
                INSERT INTO system_metrics (name, value)
                VALUES ('lock_holder', 1)
                ON CONFLICT(name) DO UPDATE SET value = value + 1
                """
            )

            rows, total = self.reader_database.get_dns_queries()

            self.assertEqual(total, 1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["query_name"], "example.com")
        finally:
            lock_holder.rollback()
            lock_holder.close()


if __name__ == "__main__":
    unittest.main()
