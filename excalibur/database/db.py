from collections import deque
from datetime import datetime, timezone
import json
import os
from queue import Empty, Full, Queue
import sqlite3
import time
from pathlib import Path
from threading import Event, RLock, Thread

import psutil

from excalibur.config import Config
from excalibur.detection.domain_risk import DomainRiskAnalyzer
from excalibur.events import AlertEvent
from excalibur.service_lookup import service_case_sql

_SENSOR_PROCESS_HANDLE = None
_SENSOR_PROCESS_PID = None


class _SystemHealthHistory:
    SAMPLE_INTERVAL_SECONDS = 5
    HISTORY_DURATION_SECONDS = 300
    MAX_SAMPLES = HISTORY_DURATION_SECONDS // SAMPLE_INTERVAL_SECONDS

    def __init__(self):
        self._lock = RLock()
        self._samples = deque(maxlen=self.MAX_SAMPLES)
        self._last_sample_at = None

    def record(self, process_metrics, writes):
        now = time.time()
        with self._lock:
            if (
                self._last_sample_at is not None
                and now - self._last_sample_at < self.SAMPLE_INTERVAL_SECONDS
            ):
                return self.snapshot()

            previous = self._samples[-1] if self._samples else None
            elapsed = (
                max(now - previous["_sampled_at"], self.SAMPLE_INTERVAL_SECONDS)
                if previous
                else self.SAMPLE_INTERVAL_SECONDS
            )
            sample = {
                "_sampled_at": now,
                "timestamp": datetime.fromtimestamp(now, timezone.utc).isoformat(),
                "cpu_percent": process_metrics.get("cpu_percent"),
                "cpu_percent_raw": process_metrics.get("cpu_percent_raw"),
                "memory_rss_mb": process_metrics.get("memory_rss_mb"),
                "packets_per_second": self._rate(
                    previous,
                    "traffic_records_written",
                    int(writes.get("traffic_records_written", 0)),
                    elapsed,
                ),
                "dns_queries_per_second": self._rate(
                    previous,
                    "dns_queries_written",
                    int(writes.get("dns_queries_written", 0)),
                    elapsed,
                ),
                "alerts_per_second": self._rate(
                    previous,
                    "alerts_written",
                    int(writes.get("alerts_written", 0)),
                    elapsed,
                ),
                "traffic_records_written": int(writes.get("traffic_records_written", 0)),
                "dns_queries_written": int(writes.get("dns_queries_written", 0)),
                "alerts_written": int(writes.get("alerts_written", 0)),
            }
            self._samples.append(sample)
            self._last_sample_at = now
            return self.snapshot()

    def snapshot(self):
        return {
            "sample_interval_seconds": self.SAMPLE_INTERVAL_SECONDS,
            "history_duration_seconds": self.HISTORY_DURATION_SECONDS,
            "samples": [
                {
                    "timestamp": sample["timestamp"],
                    "cpu_percent": sample["cpu_percent"],
                    "cpu_percent_raw": sample["cpu_percent_raw"],
                    "memory_rss_mb": sample["memory_rss_mb"],
                    "packets_per_second": sample["packets_per_second"],
                    "dns_queries_per_second": sample["dns_queries_per_second"],
                    "alerts_per_second": sample["alerts_per_second"],
                }
                for sample in self._samples
            ],
        }

    def reset(self):
        with self._lock:
            self._samples.clear()
            self._last_sample_at = None

    @staticmethod
    def _rate(previous, key, current_value, elapsed):
        if previous is None:
            return 0.0
        delta = max(0, current_value - int(previous.get(key, 0)))
        return round(delta / max(elapsed, 1), 2)


_SYSTEM_HEALTH_HISTORY = _SystemHealthHistory()


class Database:
    TRAFFIC_RETENTION_CHECK_INTERVAL = 1000
    WRITE_BATCH_SIZE = 500
    WRITE_FLUSH_INTERVAL_SECONDS = 0.25
    METRICS_FLUSH_INTERVAL_SECONDS = 5
    HOST_UPDATE_DEBOUNCE_SECONDS = 5
    WRITER_QUEUE_MAXSIZE = 20000

    def __init__(self, db_path="excalibur.sqlite", config=None, async_writes=False):
        self.db_path = Path(db_path)
        self.runtime_data_dir = Path(os.environ.get("EXCALIBUR_DATA_DIR", "data"))
        self.config = config or Config.load()
        self.async_writes = bool(async_writes)
        self.domain_risk_analyzer = DomainRiskAnalyzer(self.config)
        self._lock = RLock()
        self._state_lock = RLock()
        self._traffic_insert_counter = 0
        self._write_queue = Queue(maxsize=self.WRITER_QUEUE_MAXSIZE)
        self._writer_stop_event = Event()
        self._writer_flush_event = Event()
        self._writer_thread = None
        self._pending_metrics = {}
        self._pending_host_updates = {}
        self._host_update_deadlines = {}
        self._known_domains = {}
        self._pending_domain_updates = {}
        self.connection = sqlite3.connect(
            self.db_path,
            timeout=5.0,
            check_same_thread=False,
        )
        self.connection.row_factory = sqlite3.Row
        self.notification_manager = None
        self.event_bus = None
        self._configure_connection()
        self._create_tables()

    def set_notification_manager(self, notification_manager):
        self.notification_manager = notification_manager

    def set_event_bus(self, event_bus):
        self.event_bus = event_bus

    def _configure_connection(self):
        journal_mode = self.connection.execute(
            "PRAGMA journal_mode=WAL"
        ).fetchone()[0].upper()
        self.connection.execute("PRAGMA busy_timeout = 5000")
        busy_timeout = self.connection.execute(
            "PRAGMA busy_timeout"
        ).fetchone()[0]
        print(f"[DB] Journal Mode: {journal_mode}", flush=True)
        print(f"[DB] Busy Timeout: {busy_timeout}ms", flush=True)
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA wal_autocheckpoint = 1000")

    def _create_tables(self):
        with self._lock:
            with self.connection:
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS hosts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        mac_address TEXT,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL
                    )
                    """
                )
                self.connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_hosts_ip_address
                    ON hosts (ip_address)
                    """
                )
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS traffic (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        src_ip TEXT NOT NULL,
                        dst_ip TEXT NOT NULL,
                        protocol TEXT NOT NULL,
                        src_port INTEGER,
                        dst_port INTEGER,
                        packet_size INTEGER NOT NULL
                    )
                    """
                )
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        source_ip TEXT,
                        destination_ip TEXT,
                        context_json TEXT
                    )
                    """
                )
                self.connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                    ON alerts (timestamp)
                    """
                )
                self._ensure_column("alerts", "source_ip", "TEXT")
                self._ensure_column("alerts", "destination_ip", "TEXT")
                self._ensure_column("alerts", "context_json", "TEXT")
                self.connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
                    ON alerts (source_ip)
                    """
                )
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS portscan_debug (
                        src_ip TEXT PRIMARY KEY,
                        unique_port_count INTEGER NOT NULL,
                        in_cooldown INTEGER NOT NULL,
                        last_alert_time TEXT
                    )
                    """
                )
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dns_queries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        dns_server_ip TEXT NOT NULL,
                        query_name TEXT NOT NULL,
                        query_type TEXT NOT NULL,
                        dns_rcode TEXT
                    )
                    """
                )
                self.connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp
                    ON dns_queries (timestamp)
                    """
                )
                self._ensure_column("dns_queries", "dns_rcode", "TEXT")
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS domains (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL UNIQUE,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        query_count INTEGER NOT NULL
                    )
                    """
                )
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS domain_risk (
                        domain TEXT PRIMARY KEY,
                        risk_score INTEGER NOT NULL,
                        risk_level TEXT NOT NULL,
                        reasons TEXT,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        query_count INTEGER NOT NULL
                    )
                    """
                )
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        name TEXT PRIMARY KEY,
                        value REAL NOT NULL
                    )
                    """
                )
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS rule_stats (
                        rule_name TEXT PRIMARY KEY,
                        hits INTEGER NOT NULL DEFAULT 0,
                        alerts_generated INTEGER NOT NULL DEFAULT 0,
                        last_triggered TEXT
                    )
                    """
                )

    def _ensure_column(self, table_name, column_name, column_type):
        columns = {
            row["name"]
            for row in self.connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name not in columns:
            self.connection.execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
            )

    def _serialize_context(self, context, context_json):
        if context_json is not None:
            return context_json
        if context is None:
            return None
        return json.dumps(context, sort_keys=True)

    def _ensure_writer_thread(self):
        with self._state_lock:
            if self._writer_thread is not None and self._writer_thread.is_alive():
                return
            self._writer_stop_event.clear()
            self._writer_flush_event.clear()
            self._writer_thread = Thread(
                target=self._writer_loop,
                name="ExcaliburSQLiteWriter",
                daemon=True,
            )
            self._writer_thread.start()

    def _writer_loop(self):
        # The writer thread batches hot-path packet/DNS writes so packet capture
        # work does not churn SQLite transactions on every event.
        traffic_rows = []
        dns_rows = []
        last_flush = time.monotonic()
        last_metrics_flush = last_flush
        last_domain_flush = last_flush
        last_host_flush = last_flush

        while True:
            timeout = max(
                0.01,
                self.WRITE_FLUSH_INTERVAL_SECONDS - (time.monotonic() - last_flush),
            )
            try:
                item = self._write_queue.get(timeout=timeout)
                kind = item["kind"]
                if kind == "traffic":
                    traffic_rows.append(item["row"])
                elif kind == "dns":
                    dns_rows.append(item["row"])
            except Empty:
                item = None

            now = time.monotonic()
            force_flush = self._writer_flush_event.is_set()
            should_flush_batches = (
                force_flush
                or len(traffic_rows) >= self.WRITE_BATCH_SIZE
                or len(dns_rows) >= self.WRITE_BATCH_SIZE
                or (
                    (traffic_rows or dns_rows)
                    and now - last_flush >= self.WRITE_FLUSH_INTERVAL_SECONDS
                )
            )
            should_flush_domains = (
                force_flush or now - last_domain_flush >= self.WRITE_FLUSH_INTERVAL_SECONDS
            )
            should_flush_hosts = (
                force_flush or now - last_host_flush >= self.WRITE_FLUSH_INTERVAL_SECONDS
            )
            should_flush_metrics = (
                force_flush or now - last_metrics_flush >= self.METRICS_FLUSH_INTERVAL_SECONDS
            )

            if should_flush_batches or should_flush_domains or should_flush_hosts or should_flush_metrics:
                flushed_traffic = len(traffic_rows)
                flushed_dns = len(dns_rows)
                self._flush_pending_writes(
                    traffic_rows=traffic_rows,
                    dns_rows=dns_rows,
                    flush_domains=should_flush_domains,
                    flush_hosts=should_flush_hosts,
                    flush_metrics=should_flush_metrics,
                )
                traffic_rows = []
                dns_rows = []
                last_flush = now
                if should_flush_domains:
                    last_domain_flush = now
                if should_flush_hosts:
                    last_host_flush = now
                if should_flush_metrics:
                    last_metrics_flush = now
                self._writer_flush_event.clear()
                for _ in range(flushed_traffic + flushed_dns):
                    self._write_queue.task_done()

            if (
                self._writer_stop_event.is_set()
                and self._write_queue.empty()
                and not traffic_rows
                and not dns_rows
            ):
                self._flush_pending_writes(
                    traffic_rows=[],
                    dns_rows=[],
                    flush_domains=True,
                    flush_hosts=True,
                    flush_metrics=True,
                )
                break

    def _enqueue_write(self, kind, row):
        self._ensure_writer_thread()
        try:
            self._write_queue.put_nowait({"kind": kind, "row": row})
            return True
        except Full:
            print(
                f"[WARN] SQLite writer queue full; falling back to synchronous {kind} write",
                flush=True,
            )
            return False

    def _flush_pending_writes(
        self,
        *,
        traffic_rows=None,
        dns_rows=None,
        flush_domains=True,
        flush_hosts=True,
        flush_metrics=True,
    ):
        traffic_rows = list(traffic_rows or [])
        dns_rows = list(dns_rows or [])

        with self._state_lock:
            host_updates = {}
            if flush_hosts and self._pending_host_updates:
                host_updates = self._pending_host_updates
                self._pending_host_updates = {}
                self._host_update_deadlines = {}

            domain_updates = {}
            if flush_domains and self._pending_domain_updates:
                domain_updates = self._pending_domain_updates
                self._pending_domain_updates = {}

            metrics = {}
            if flush_metrics and self._pending_metrics:
                metrics = self._pending_metrics
                self._pending_metrics = {}

        if not (traffic_rows or dns_rows or host_updates or domain_updates or metrics):
            return

        retention_check = False
        with self._lock:
            with self.connection:
                if traffic_rows:
                    self.connection.executemany(
                        """
                        INSERT INTO traffic (
                            timestamp,
                            src_ip,
                            dst_ip,
                            protocol,
                            src_port,
                            dst_port,
                            packet_size
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        traffic_rows,
                    )
                    self._traffic_insert_counter += len(traffic_rows)
                    if self._traffic_insert_counter >= self.TRAFFIC_RETENTION_CHECK_INTERVAL:
                        self._traffic_insert_counter %= self.TRAFFIC_RETENTION_CHECK_INTERVAL
                        retention_check = True

                if dns_rows:
                    self.connection.executemany(
                        """
                        INSERT INTO dns_queries (
                            timestamp,
                            client_ip,
                            dns_server_ip,
                            query_name,
                            query_type,
                            dns_rcode
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        dns_rows,
                    )

                if host_updates:
                    self.connection.executemany(
                        """
                        UPDATE hosts
                        SET last_seen = ?
                        WHERE ip_address = ?
                        """,
                        [(timestamp, ip_address) for ip_address, timestamp in host_updates.items()],
                    )

                if domain_updates:
                    self._flush_domain_updates_locked(domain_updates)

                if metrics:
                    self._flush_metrics_locked(metrics)

        if retention_check:
            self.enforce_traffic_limit(Config.TRAFFIC_MAX_RECORDS)

    def _flush_domain_updates_locked(self, domain_updates):
        for domain, state in domain_updates.items():
            self.connection.execute(
                """
                INSERT INTO domains (domain, first_seen, last_seen, query_count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    query_count = domains.query_count + excluded.query_count
                """,
                (
                    domain,
                    state["first_seen"],
                    state["last_seen"],
                    state["query_count"],
                ),
            )
            risk_result = state["risk_result"]
            self.connection.execute(
                """
                INSERT INTO domain_risk (
                    domain,
                    risk_score,
                    risk_level,
                    reasons,
                    first_seen,
                    last_seen,
                    query_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    risk_level = excluded.risk_level,
                    reasons = excluded.reasons,
                    last_seen = excluded.last_seen,
                    query_count = domain_risk.query_count + excluded.query_count
                """,
                (
                    risk_result["domain"],
                    risk_result["risk_score"],
                    risk_result["risk_level"],
                    "; ".join(risk_result["reasons"]),
                    state["first_seen"],
                    state["last_seen"],
                    state["query_count"],
                ),
            )
            if state["is_new"]:
                self._append_new_domain(domain)

    def _flush_metrics_locked(self, metrics):
        if not metrics:
            return
        self.connection.execute(
            """
            INSERT OR IGNORE INTO system_metrics (name, value)
            VALUES (?, ?)
            """,
            ("metrics_started_at", float(time.time())),
        )
        self.connection.executemany(
            """
            INSERT INTO system_metrics (name, value)
            VALUES (?, ?)
            ON CONFLICT(name) DO UPDATE SET value = value + excluded.value
            """,
            [(name, float(value)) for name, value in metrics.items()],
        )

    def _flush_for_read(self):
        self._writer_flush_event.set()
        if self._writer_thread is not None and self._writer_thread.is_alive():
            self._write_queue.join()
        self._flush_pending_writes(
            traffic_rows=[],
            dns_rows=[],
            flush_domains=True,
            flush_hosts=True,
            flush_metrics=True,
        )

    def _add_pending_metric(self, name, amount):
        if not self.async_writes:
            self._increment_metric(name, amount)
            return
        with self._state_lock:
            self._pending_metrics[name] = self._pending_metrics.get(name, 0) + amount

    def _domain_exists(self, normalized_domain):
        with self._lock:
            row = self.connection.execute(
                """
                SELECT 1
                FROM domains
                WHERE domain = ?
                """,
                (normalized_domain,),
            ).fetchone()
            return row is not None

    def add_host(self, ip_address, mac_address, first_seen, last_seen):
        started_at = time.perf_counter()
        with self._lock:
            with self.connection:
                cursor = self.connection.execute(
                    """
                    INSERT OR IGNORE INTO hosts (
                        ip_address,
                        mac_address,
                        first_seen,
                        last_seen
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (ip_address, mac_address, first_seen, last_seen),
                )
                row_id = cursor.lastrowid
                if cursor.rowcount:
                    self._record_write_metrics(
                        "hosts_added",
                        self._estimate_bytes(
                            ip_address,
                            mac_address,
                            first_seen,
                            last_seen,
                        ),
                        started_at,
                    )
                return row_id

    def update_host_last_seen(self, ip_address, last_seen):
        if not self.async_writes:
            with self._lock:
                with self.connection:
                    cursor = self.connection.execute(
                        """
                        UPDATE hosts
                        SET last_seen = ?
                        WHERE ip_address = ?
                        """,
                        (last_seen, ip_address),
                    )
                    return cursor.rowcount
        now = time.monotonic()
        with self._state_lock:
            deadline = self._host_update_deadlines.get(ip_address)
            if deadline is not None and now < deadline:
                self._pending_host_updates[ip_address] = last_seen
                return 0
            self._pending_host_updates[ip_address] = last_seen
            self._host_update_deadlines[ip_address] = (
                now + self.HOST_UPDATE_DEBOUNCE_SECONDS
            )
        self._ensure_writer_thread()
        return 1

    def get_host_by_ip(self, ip_address):
        with self._lock:
            return self.connection.execute(
                """
                SELECT id, ip_address, mac_address, first_seen, last_seen
                FROM hosts
                WHERE ip_address = ?
                """,
                (ip_address,),
            ).fetchone()

    def host_exists(self, ip_address):
        return self.get_host_by_ip(ip_address) is not None

    def log_traffic(
        self,
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_size,
    ):
        if not self.async_writes:
            started_at = time.perf_counter()
            with self._lock:
                with self.connection:
                    cursor = self.connection.execute(
                        """
                        INSERT INTO traffic (
                            timestamp,
                            src_ip,
                            dst_ip,
                            protocol,
                            src_port,
                            dst_port,
                            packet_size
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            timestamp,
                            src_ip,
                            dst_ip,
                            protocol,
                            src_port,
                            dst_port,
                            packet_size,
                        ),
                    )
                    self._record_write_metrics(
                        "traffic_records_written",
                        self._estimate_bytes(
                            timestamp,
                            src_ip,
                            dst_ip,
                            protocol,
                            src_port,
                            dst_port,
                            packet_size,
                        ),
                        started_at,
                    )
                    row_id = cursor.lastrowid
                    self._traffic_insert_counter += 1

            if self._traffic_insert_counter >= self.TRAFFIC_RETENTION_CHECK_INTERVAL:
                self._traffic_insert_counter = 0
                self.enforce_traffic_limit(Config.TRAFFIC_MAX_RECORDS)
            return row_id
        started_at = time.perf_counter()
        row = (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            packet_size,
        )
        self._record_write_metrics(
            "traffic_records_written",
            self._estimate_bytes(*row),
            started_at,
        )
        if not self._enqueue_write("traffic", row):
            self._flush_pending_writes(
                traffic_rows=[row],
                dns_rows=[],
                flush_domains=False,
                flush_hosts=False,
                flush_metrics=False,
            )
        return None

    def create_alert(
        self,
        timestamp,
        severity,
        title,
        description,
        source_ip=None,
        destination_ip=None,
        context=None,
        context_json=None,
    ):
        started_at = time.perf_counter()
        serialized_context = self._serialize_context(context, context_json)
        with self._lock:
            with self.connection:
                cursor = self.connection.execute(
                    """
                    INSERT INTO alerts (
                        timestamp,
                        severity,
                        title,
                        description,
                        source_ip,
                        destination_ip,
                        context_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        timestamp,
                        severity,
                        title,
                        description,
                        source_ip,
                        destination_ip,
                        serialized_context,
                    ),
                )
                self._record_write_metrics(
                    "alerts_written",
                    self._estimate_bytes(
                        timestamp,
                        severity,
                        title,
                        description,
                        source_ip,
                        destination_ip,
                        serialized_context,
                    ),
                    started_at,
                )
                alert_id = cursor.lastrowid

        self._notify_alert(
            {
                "id": alert_id,
                "timestamp": timestamp,
                "severity": severity,
                "title": title,
                "description": description,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "context_json": serialized_context,
            }
        )
        self._emit_alert_event(
            alert_id=alert_id,
            timestamp=timestamp,
            severity=severity,
            title=title,
            description=description,
            source_ip=source_ip,
            destination_ip=destination_ip,
            context_json=serialized_context,
        )
        return alert_id

    def _notify_alert(self, alert):
        if self.notification_manager is None:
            return
        try:
            self.notification_manager.notify_alert(alert)
        except Exception as exc:
            print(f"[WARN] Alert notification failed: {exc}", flush=True)

    def _emit_alert_event(
        self,
        alert_id,
        timestamp,
        severity,
        title,
        description,
        source_ip=None,
        destination_ip=None,
        context_json=None,
    ):
        if self.event_bus is None:
            return
        self.event_bus.emit(
            AlertEvent(
                timestamp=timestamp,
                alert_id=alert_id,
                title=title,
                severity=severity,
                description=description,
                source_ip=source_ip,
                destination_ip=destination_ip,
                context_json=context_json,
            )
        )

    def delete_alert(self, alert_id):
        with self._lock:
            with self.connection:
                cursor = self.connection.execute(
                    "DELETE FROM alerts WHERE id = ?",
                    (alert_id,),
                )
                return cursor.rowcount

    def delete_all_alerts(self):
        with self._lock:
            with self.connection:
                cursor = self.connection.execute("DELETE FROM alerts")
                return cursor.rowcount

    def log_dns_query(
        self,
        timestamp,
        client_ip,
        dns_server_ip,
        query_name,
        query_type,
        dns_rcode=None,
    ):
        if not self.async_writes:
            normalized_domain = self._normalize_domain(query_name)
            started_at = time.perf_counter()
            with self._lock:
                with self.connection:
                    cursor = self.connection.execute(
                        """
                        INSERT INTO dns_queries (
                            timestamp,
                            client_ip,
                            dns_server_ip,
                            query_name,
                            query_type,
                            dns_rcode
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            timestamp,
                            client_ip,
                            dns_server_ip,
                            normalized_domain,
                            str(query_type),
                            dns_rcode,
                        ),
                    )
                    self._record_write_metrics(
                        "dns_queries_written",
                        self._estimate_bytes(
                            timestamp,
                            client_ip,
                            dns_server_ip,
                            normalized_domain,
                            query_type,
                            dns_rcode or "",
                        ),
                        started_at,
                    )
                risk_result = self.upsert_domain(
                    normalized_domain,
                    timestamp,
                    client_ip=client_ip,
                    dns_server_ip=dns_server_ip,
                )
                return {
                    "id": cursor.lastrowid,
                    "domain_risk": risk_result,
                }
        normalized_domain = self._normalize_domain(query_name)
        started_at = time.perf_counter()
        row = (
            timestamp,
            client_ip,
            dns_server_ip,
            normalized_domain,
            str(query_type),
            dns_rcode,
        )
        self._record_write_metrics(
            "dns_queries_written",
            self._estimate_bytes(
                timestamp,
                client_ip,
                dns_server_ip,
                normalized_domain,
                query_type,
                dns_rcode or "",
            ),
            started_at,
        )
        if not self._enqueue_write("dns", row):
            self._flush_pending_writes(
                traffic_rows=[],
                dns_rows=[row],
                flush_domains=False,
                flush_hosts=False,
                flush_metrics=False,
            )
        risk_result = self.upsert_domain(
            normalized_domain,
            timestamp,
            client_ip=client_ip,
            dns_server_ip=dns_server_ip,
        )
        return {
            "id": None,
            "domain_risk": risk_result,
        }

    def upsert_domain(self, domain, timestamp, client_ip=None, dns_server_ip=None):
        normalized_domain = self._normalize_domain(domain)
        risk_result = self.analyze_domain_risk(normalized_domain)
        if not self.async_writes:
            with self._lock:
                existing_domain = self.connection.execute(
                    """
                    SELECT id
                    FROM domains
                    WHERE domain = ?
                    """,
                    (normalized_domain,),
                ).fetchone()

                with self.connection:
                    if existing_domain:
                        self.connection.execute(
                            """
                            UPDATE domains
                            SET last_seen = ?, query_count = query_count + 1
                            WHERE domain = ?
                            """,
                            (timestamp, normalized_domain),
                        )
                        self._upsert_domain_risk(
                            risk_result,
                            first_seen=timestamp,
                            last_seen=timestamp,
                            increment_existing=True,
                        )
                        return risk_result

                    self.connection.execute(
                        """
                        INSERT INTO domains (domain, first_seen, last_seen, query_count)
                        VALUES (?, ?, ?, 1)
                        """,
                        (normalized_domain, timestamp, timestamp),
                    )
                self._append_new_domain(normalized_domain)
                self._record_write_metrics(
                    "unique_domains_discovered",
                    self._estimate_bytes(normalized_domain, timestamp, timestamp, 1),
                    time.perf_counter(),
                )
                self._add_pending_metric(
                    "domains_log_bytes_written",
                    len(f"{normalized_domain}\n".encode("utf-8")),
                )
                self._upsert_domain_risk(
                    risk_result,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    increment_existing=False,
                )
                self._create_domain_risk_alert_if_needed(
                    risk_result,
                    timestamp,
                    client_ip,
                    dns_server_ip,
                )
                return risk_result
        should_create_alert = False
        with self._state_lock:
            domain_state = self._pending_domain_updates.get(normalized_domain)
            if domain_state is None:
                known_domain = self._known_domains.get(normalized_domain)
                if known_domain is None:
                    known_domain = self._domain_exists(normalized_domain)
                is_new = not known_domain
                domain_state = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "query_count": 1,
                    "risk_result": risk_result,
                    "is_new": is_new,
                }
                self._pending_domain_updates[normalized_domain] = domain_state
                self._known_domains[normalized_domain] = True
                if is_new:
                    self._record_write_metrics(
                        "unique_domains_discovered",
                        self._estimate_bytes(normalized_domain, timestamp, timestamp, 1),
                        time.perf_counter(),
                    )
                    self._add_pending_metric(
                        "domains_log_bytes_written",
                        len(f"{normalized_domain}\n".encode("utf-8")),
                    )
                    should_create_alert = True
            else:
                domain_state["last_seen"] = timestamp
                domain_state["query_count"] += 1
                domain_state["risk_result"] = risk_result

        self._ensure_writer_thread()
        if should_create_alert:
            self._create_domain_risk_alert_if_needed(
                risk_result,
                timestamp,
                client_ip,
                dns_server_ip,
            )
        return risk_result

    def analyze_domain_risk(self, domain):
        if not self.domain_risk_analyzer.enabled:
            normalized_domain = self._normalize_domain(domain)
            return {
                "domain": normalized_domain,
                "risk_score": 0,
                "risk_level": "None",
                "reasons": [],
            }
        return self.domain_risk_analyzer.analyze(domain)

    def _upsert_domain_risk(
        self,
        risk_result,
        first_seen,
        last_seen,
        increment_existing,
    ):
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO domain_risk (
                    domain,
                    risk_score,
                    risk_level,
                    reasons,
                    first_seen,
                    last_seen,
                    query_count
                )
                VALUES (?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(domain) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    risk_level = excluded.risk_level,
                    reasons = excluded.reasons,
                    last_seen = excluded.last_seen,
                    query_count = domain_risk.query_count + ?
                """,
                (
                    risk_result["domain"],
                    risk_result["risk_score"],
                    risk_result["risk_level"],
                    "; ".join(risk_result["reasons"]),
                    first_seen,
                    last_seen,
                    1 if increment_existing else 0,
                ),
            )

    def _create_domain_risk_alert_if_needed(
        self,
        risk_result,
        timestamp,
        client_ip,
        dns_server_ip,
    ):
        if not self.domain_risk_analyzer.should_alert(risk_result):
            return
        self.create_alert(
            timestamp,
            risk_result["risk_level"],
            "Suspicious Browser Domain",
            f"Domain {risk_result['domain']} scored {risk_result['risk_score']} for browser threat risk.",
            source_ip=client_ip,
            destination_ip=dns_server_ip,
            context={
                "rule": {
                    "name": "Suspicious Browser Domain",
                    "pack": "browser.yaml",
                    "tags": ["browser", "domain_risk"],
                    "event_type": "dns",
                    "thresholds": {
                        "risk_score": self.domain_risk_analyzer.risk_threshold,
                    },
                },
                "evidence": {
                    "observed": {
                        "domain": risk_result["domain"],
                        "risk_score": risk_result["risk_score"],
                        "risk_level": risk_result["risk_level"],
                        "reasons": ", ".join(risk_result["reasons"]),
                    },
                    "thresholds": {
                        "risk_score": self.domain_risk_analyzer.risk_threshold,
                    },
                },
            },
        )

    def get_dns_queries(
        self,
        search=None,
        sort_by="timestamp",
        sort_order="DESC",
        page=1,
        per_page=100,
        limit=None,
    ):
        self._flush_for_read()
        if limit is not None:
            per_page = limit

        allowed_sort_columns = {
            "timestamp",
            "client_ip",
            "dns_server_ip",
            "query_name",
            "query_type",
            "dns_rcode",
        }
        sort_by = self._normalize_sort_column(sort_by, allowed_sort_columns, "timestamp")
        sort_order = self._normalize_sort_order(sort_order)
        page = max(int(page), 1)
        per_page = max(int(per_page), 1)
        offset = (page - 1) * per_page
        where_clause, params = self._build_dns_query_where_clause(search)

        count_query = f"SELECT COUNT(*) FROM dns_queries {where_clause}"
        select_query = f"""
            SELECT timestamp, client_ip, dns_server_ip, query_name, query_type, dns_rcode
            FROM dns_queries
            {where_clause}
            ORDER BY {sort_by} {sort_order}, id DESC
            LIMIT ? OFFSET ?
        """

        with self._lock:
            started_at = time.perf_counter()
            rows = self.connection.execute(
                select_query,
                [*params, per_page, offset],
            ).fetchall()
            if limit is not None and not search:
                self._record_read_metrics("dns_rows_returned", rows, started_at)
                return rows

            total = self.connection.execute(count_query, params).fetchone()[0]
            self._record_read_metrics("dns_rows_returned", rows, started_at)
            return rows, total

    def get_domains(
        self,
        search=None,
        sort_by="last_seen",
        sort_order="DESC",
        page=1,
        per_page=100,
    ):
        self._flush_for_read()
        allowed_sort_columns = {
            "domain",
            "first_seen",
            "last_seen",
            "query_count",
        }
        sort_by = self._normalize_sort_column(sort_by, allowed_sort_columns, "last_seen")
        sort_order = self._normalize_sort_order(sort_order)
        page = max(int(page), 1)
        per_page = max(int(per_page), 1)
        offset = (page - 1) * per_page
        where_clause, params = self._build_domains_where_clause(search)

        count_query = f"SELECT COUNT(*) FROM domains {where_clause}"
        select_query = f"""
            SELECT domain, first_seen, last_seen, query_count
            FROM domains
            {where_clause}
            ORDER BY {sort_by} {sort_order}, id DESC
            LIMIT ? OFFSET ?
        """

        with self._lock:
            started_at = time.perf_counter()
            total = self.connection.execute(count_query, params).fetchone()[0]
            rows = self.connection.execute(
                select_query,
                [*params, per_page, offset],
            ).fetchall()
            self._record_read_metrics("domain_rows_returned", rows, started_at)
            return rows, total

    def get_domain_risk(
        self,
        search=None,
        risk_level=None,
        sort_by="risk_score",
        sort_order="DESC",
        page=1,
        per_page=100,
    ):
        self._flush_for_read()
        allowed_sort_columns = {
            "domain",
            "risk_score",
            "risk_level",
            "first_seen",
            "last_seen",
            "query_count",
        }
        sort_by = self._normalize_sort_column(sort_by, allowed_sort_columns, "risk_score")
        sort_order = self._normalize_sort_order(sort_order)
        page = max(int(page), 1)
        per_page = max(int(per_page), 1)
        offset = (page - 1) * per_page
        where_clause, params = self._build_domain_risk_where_clause(search, risk_level)

        count_query = f"SELECT COUNT(*) FROM domain_risk {where_clause}"
        select_query = f"""
            SELECT
                domain,
                risk_score,
                risk_level,
                reasons,
                first_seen,
                last_seen,
                query_count
            FROM domain_risk
            {where_clause}
            ORDER BY {sort_by} {sort_order}, last_seen DESC
            LIMIT ? OFFSET ?
        """

        with self._lock:
            started_at = time.perf_counter()
            total = self.connection.execute(count_query, params).fetchone()[0]
            rows = self.connection.execute(
                select_query,
                [*params, per_page, offset],
            ).fetchall()
            self._record_read_metrics("domain_rows_returned", rows, started_at)
            return rows, total

    def get_dns_query_count(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                "SELECT COUNT(*) FROM dns_queries"
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def get_domain_count(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute("SELECT COUNT(*) FROM domains").fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def get_risky_domain_count(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                "SELECT COUNT(*) FROM domain_risk WHERE risk_level != 'None'"
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def count_hosts(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute("SELECT COUNT(*) FROM hosts").fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def count_traffic(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute("SELECT COUNT(*) FROM traffic").fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def get_traffic_count(self):
        return self.count_traffic()

    def count_alerts(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute("SELECT COUNT(*) FROM alerts").fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def count_alerts_between(self, start_timestamp, end_timestamp):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE timestamp >= ? AND timestamp < ?
                """,
                (start_timestamp, end_timestamp),
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def count_dns_queries_between(self, start_timestamp, end_timestamp):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                """
                SELECT COUNT(*)
                FROM dns_queries
                WHERE timestamp >= ? AND timestamp < ?
                """,
                (start_timestamp, end_timestamp),
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def get_total_rule_hits(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                "SELECT COALESCE(SUM(hits), 0) FROM rule_stats"
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return int(row[0] or 0)

    def get_top_rule_stats(self, limit=10):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            rows = self.connection.execute(
                """
                SELECT rule_name, hits, alerts_generated, last_triggered
                FROM rule_stats
                ORDER BY alerts_generated DESC, hits DESC, rule_name ASC
                LIMIT ?
                """,
                (max(int(limit), 1),),
            ).fetchall()
            self._record_read_metrics("dashboard_queries_executed", rows, started_at)
            return rows

    def get_top_alert_sources(self, limit=10):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            rows = self.connection.execute(
                """
                SELECT
                    COALESCE(NULLIF(source_ip, ''), 'unknown') AS source_ip,
                    COUNT(*) AS alert_count
                FROM alerts
                GROUP BY COALESCE(NULLIF(source_ip, ''), 'unknown')
                ORDER BY alert_count DESC, source_ip ASC
                LIMIT ?
                """,
                (max(int(limit), 1),),
            ).fetchall()
            self._record_read_metrics("dashboard_queries_executed", rows, started_at)
            return rows

    def enforce_traffic_limit(self, max_records):
        with self._lock:
            current_count = self.connection.execute(
                "SELECT COUNT(*) FROM traffic"
            ).fetchone()[0]
            excess_count = current_count - max_records
            if excess_count <= 0:
                return 0

            with self.connection:
                cursor = self.connection.execute(
                    """
                    DELETE FROM traffic
                    WHERE id IN (
                        SELECT id
                        FROM traffic
                        ORDER BY id ASC
                        LIMIT ?
                    )
                    """,
                    (excess_count,),
                )

            purged_count = cursor.rowcount
            print("[INFO] Traffic retention check", flush=True)
            print(f"[INFO] Purged {purged_count} traffic records", flush=True)
            return purged_count

    def get_latest_traffic(self, limit=100):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            rows = self.connection.execute(
                """
                SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size
                FROM traffic
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            self._record_read_metrics("traffic_rows_returned", rows, started_at)
            return rows

    def get_traffic(
        self,
        search=None,
        filters=None,
        sort_by="timestamp",
        sort_order="DESC",
        page=1,
        per_page=100,
    ):
        self._flush_for_read()
        allowed_sort_columns = {
            "timestamp",
            "src_ip",
            "dst_ip",
            "protocol",
            "src_port",
            "dst_port",
            "packet_size",
            "service",
        }
        if sort_by not in allowed_sort_columns:
            sort_by = "timestamp"

        sort_order = str(sort_order).upper()
        if sort_order not in {"ASC", "DESC"}:
            sort_order = "DESC"

        page = max(int(page), 1)
        per_page = max(int(per_page), 1)
        offset = (page - 1) * per_page

        service_expression = service_case_sql("dst_port")
        where_clause, params = self._build_traffic_where_clause(
            search,
            filters,
            service_expression=service_expression,
        )
        count_query = f"SELECT COUNT(*) FROM traffic {where_clause}"
        select_query = f"""
            SELECT
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                {service_expression} AS service,
                packet_size
            FROM traffic
            {where_clause}
            ORDER BY {sort_by} {sort_order}, id DESC
            LIMIT ? OFFSET ?
        """

        with self._lock:
            started_at = time.perf_counter()
            total = self.connection.execute(count_query, params).fetchone()[0]
            rows = self.connection.execute(
                select_query,
                [*params, per_page, offset],
            ).fetchall()
            self._record_read_metrics("traffic_rows_returned", rows, started_at)
            return rows, total

    def _build_traffic_where_clause(self, search=None, filters=None, service_expression=None):
        filters = filters or {}
        service_expression = service_expression or service_case_sql("dst_port")
        clauses = []
        params = []

        filter_columns = {
            "src_ip": "src_ip",
            "dst_ip": "dst_ip",
            "protocol": "protocol",
            "src_port": "src_port",
            "dst_port": "dst_port",
        }
        for key, column in filter_columns.items():
            value = filters.get(key)
            if value in (None, ""):
                continue
            clauses.append(f"{column} = ?")
            params.append(value)

        if search:
            search_value = f"%{search}%"
            clauses.append(
                f"""
                (
                    src_ip LIKE ?
                    OR dst_ip LIKE ?
                    OR protocol LIKE ?
                    OR CAST(src_port AS TEXT) LIKE ?
                    OR CAST(dst_port AS TEXT) LIKE ?
                    OR {service_expression} LIKE ?
                )
                """
            )
            params.extend([search_value] * 6)

        if not clauses:
            return "", []
        return "WHERE " + " AND ".join(clauses), params

    def _build_dns_query_where_clause(self, search=None):
        if not search:
            return "", []
        search_value = f"%{search}%"
        return (
            """
            WHERE (
                client_ip LIKE ?
                OR dns_server_ip LIKE ?
                OR query_name LIKE ?
                OR query_type LIKE ?
                OR dns_rcode LIKE ?
            )
            """,
            [search_value] * 5,
        )

    def _build_domains_where_clause(self, search=None):
        if not search:
            return "", []
        return "WHERE domain LIKE ?", [f"%{search}%"]

    def _build_domain_risk_where_clause(self, search=None, risk_level=None):
        clauses = []
        params = []
        if search:
            search_value = f"%{search}%"
            clauses.append("(domain LIKE ? OR reasons LIKE ?)")
            params.extend([search_value, search_value])
        if risk_level:
            clauses.append("risk_level = ?")
            params.append(risk_level)
        else:
            clauses.append("risk_level != 'None'")
        if not clauses:
            return "", []
        return "WHERE " + " AND ".join(clauses), params

    def _normalize_sort_column(self, sort_by, allowed_columns, default):
        if sort_by not in allowed_columns:
            return default
        return sort_by

    def _normalize_sort_order(self, sort_order):
        sort_order = str(sort_order).upper()
        if sort_order not in {"ASC", "DESC"}:
            return "DESC"
        return sort_order

    def get_hosts(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            rows = self.connection.execute(
                """
                SELECT ip_address, mac_address, first_seen, last_seen
                FROM hosts
                ORDER BY last_seen DESC
                """
            ).fetchall()
            self._record_read_metrics("host_rows_returned", rows, started_at)
            return rows

    def get_alerts(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            rows = self.connection.execute(
                """
                SELECT
                    id,
                    timestamp,
                    severity,
                    title,
                    description,
                    source_ip,
                    destination_ip,
                    context_json
                FROM alerts
                ORDER BY id DESC
                """
            ).fetchall()
            self._record_read_metrics("alert_rows_returned", rows, started_at)
            return rows

    def get_recent_alerts(self, limit=10):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            rows = self.connection.execute(
                """
                SELECT
                    id,
                    timestamp,
                    severity,
                    title,
                    description,
                    source_ip,
                    destination_ip,
                    context_json
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(int(limit), 1),),
            ).fetchall()
            self._record_read_metrics("alert_rows_returned", rows, started_at)
            return rows

    def get_alert(self, alert_id):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                """
                SELECT
                    id,
                    timestamp,
                    severity,
                    title,
                    description,
                    source_ip,
                    destination_ip,
                    context_json
                FROM alerts
                WHERE id = ?
                """,
                (alert_id,),
            ).fetchone()
            self._record_read_metrics("alert_rows_returned", [row] if row else [], started_at)
            return row

    def get_recent_alerts_for_source(self, source_ip, exclude_alert_id=None, limit=20):
        if not source_ip:
            return []
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            params = [source_ip]
            where_clause = "WHERE source_ip = ?"
            if exclude_alert_id is not None:
                where_clause += " AND id != ?"
                params.append(exclude_alert_id)
            params.append(max(int(limit), 1))
            rows = self.connection.execute(
                f"""
                SELECT id, timestamp, severity, title, source_ip, destination_ip
                FROM alerts
                {where_clause}
                ORDER BY id DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
            self._record_read_metrics("alert_rows_returned", rows, started_at)
            return rows

    def get_recent_dns_queries_for_source(self, source_ip, limit=20):
        if not source_ip:
            return []
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            rows = self.connection.execute(
                """
                SELECT timestamp, client_ip, dns_server_ip, query_name, query_type, dns_rcode
                FROM dns_queries
                WHERE client_ip = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (source_ip, max(int(limit), 1)),
            ).fetchall()
            self._record_read_metrics("dns_rows_returned", rows, started_at)
            return rows

    def get_recent_traffic_for_source(self, source_ip, limit=20):
        if not source_ip:
            return []
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            rows = self.connection.execute(
                """
                SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size
                FROM traffic
                WHERE src_ip = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (source_ip, max(int(limit), 1)),
            ).fetchall()
            self._record_read_metrics("traffic_rows_returned", rows, started_at)
            return rows

    def update_portscan_debug_state(
        self,
        src_ip,
        unique_port_count,
        in_cooldown,
        last_alert_time,
    ):
        with self._lock:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO portscan_debug (
                        src_ip,
                        unique_port_count,
                        in_cooldown,
                        last_alert_time
                    )
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(src_ip) DO UPDATE SET
                        unique_port_count = excluded.unique_port_count,
                        in_cooldown = excluded.in_cooldown,
                        last_alert_time = excluded.last_alert_time
                    """,
                    (
                        src_ip,
                        unique_port_count,
                        1 if in_cooldown else 0,
                        last_alert_time,
                    ),
                )

    def get_portscan_debug_state(self):
        self._flush_for_read()
        with self._lock:
            return self.connection.execute(
                """
                SELECT src_ip, unique_port_count, in_cooldown, last_alert_time
                FROM portscan_debug
                ORDER BY unique_port_count DESC, src_ip ASC
                """
            ).fetchall()

    def get_system_health(self):
        self._flush_for_read()
        with self._lock:
            metrics = self._get_metric_values()
            counts = {
                "traffic": self._count_table("traffic"),
                "dns_queries": self._count_table("dns_queries"),
                "domains": self._count_table("domains"),
                "alerts": self._count_table("alerts"),
                "hosts": self._count_table("hosts"),
            }
            database_size_bytes = self._get_file_size(self.db_path)
            domains_log_path = self.runtime_data_dir / "domains.log"
            domains_log_size_bytes = self._get_file_size(domains_log_path)
            elapsed_hours = self._metric_elapsed_hours(metrics)
            write_bytes = metrics.get("sqlite_bytes_written", 0)
            read_bytes = metrics.get("sqlite_bytes_read", 0)
            process_metrics = self._get_process_metrics()
            writes = {
                "traffic_records_written": int(metrics.get("traffic_records_written", 0)),
                "dns_queries_written": int(metrics.get("dns_queries_written", 0)),
                "unique_domains_discovered": int(metrics.get("unique_domains_discovered", 0)),
                "alerts_written": int(metrics.get("alerts_written", 0)),
                "hosts_added": int(metrics.get("hosts_added", 0)),
                "total_writes": int(metrics.get("total_writes", 0)),
                "estimated_bytes_written": write_bytes,
                "estimated_mb_written": self._bytes_to_mb(write_bytes),
                "estimated_mb_per_hour": self._rate_per_hour(write_bytes, elapsed_hours),
                "estimated_mb_per_day": self._rate_per_hour(write_bytes, elapsed_hours) * 24,
                "domains_log_bytes_written": int(metrics.get("domains_log_bytes_written", 0)),
                "domains_log_mb_written": self._bytes_to_mb(metrics.get("domains_log_bytes_written", 0)),
            }

            return {
                "database": {
                    "path": str(self.db_path.resolve()),
                    "size_bytes": database_size_bytes,
                    "size_mb": self._bytes_to_mb(database_size_bytes),
                    "traffic_records": counts["traffic"],
                    "dns_queries": counts["dns_queries"],
                    "unique_domains": counts["domains"],
                    "alerts": counts["alerts"],
                    "hosts": counts["hosts"],
                    "journal_mode": self._get_journal_mode(),
                },
                "writes": writes,
                "reads": {
                    "dashboard_queries_executed": int(metrics.get("dashboard_queries_executed", 0)),
                    "traffic_rows_returned": int(metrics.get("traffic_rows_returned", 0)),
                    "dns_rows_returned": int(metrics.get("dns_rows_returned", 0)),
                    "domain_rows_returned": int(metrics.get("domain_rows_returned", 0)),
                    "alert_rows_returned": int(metrics.get("alert_rows_returned", 0)),
                    "host_rows_returned": int(metrics.get("host_rows_returned", 0)),
                    "total_reads": int(metrics.get("dashboard_queries_executed", 0)),
                    "estimated_bytes_read": read_bytes,
                    "estimated_mb_read": self._bytes_to_mb(read_bytes),
                    "estimated_mb_per_hour": self._rate_per_hour(read_bytes, elapsed_hours),
                    "estimated_mb_per_day": self._rate_per_hour(read_bytes, elapsed_hours) * 24,
                },
                "performance": {
                    "average_write_ms": self._average_latency_ms(
                        metrics.get("write_latency_total", 0),
                        metrics.get("write_latency_count", 0),
                    ),
                    "average_read_ms": self._average_latency_ms(
                        metrics.get("read_latency_total", 0),
                        metrics.get("read_latency_count", 0),
                    ),
                },
                "process": process_metrics,
                "history": self._get_system_health_history().record(process_metrics, writes),
                "storage": {
                    "database_size_mb": self._bytes_to_mb(database_size_bytes),
                    "domains_log_size_mb": self._bytes_to_mb(domains_log_size_bytes),
                    "traffic_table_estimate_mb": self._estimate_table_mb("traffic"),
                    "dns_table_estimate_mb": self._estimate_table_mb("dns_queries"),
                    "domains_table_estimate_mb": self._estimate_table_mb("domains"),
                    "alerts_table_estimate_mb": self._estimate_table_mb("alerts"),
                    "hosts_table_estimate_mb": self._estimate_table_mb("hosts"),
                },
                "retention": {
                    "traffic_max_records": Config.TRAFFIC_MAX_RECORDS,
                    "current_traffic_count": counts["traffic"],
                    "traffic_buffer_percent": (
                        counts["traffic"] / Config.TRAFFIC_MAX_RECORDS * 100
                        if Config.TRAFFIC_MAX_RECORDS
                        else 0
                    ),
                },
            }

    def _get_process_metrics(self):
        try:
            process = self._sensor_process()
            raw_cpu_percent = round(process.cpu_percent(interval=None), 2)
            logical_cpu_count = max(psutil.cpu_count(logical=True) or 1, 1)
            cpu_percent = round(raw_cpu_percent / logical_cpu_count, 2)
            memory_info = process.memory_info()
            memory_percent = round(process.memory_percent(), 2)
            thread_count = process.num_threads()
            create_time = process.create_time()
        except (psutil.Error, OSError):
            return {
                "available": False,
                "cpu_percent": None,
                "cpu_percent_raw": None,
                "logical_cpu_count": None,
                "memory_rss_bytes": None,
                "memory_rss_mb": None,
                "memory_percent": None,
                "thread_count": None,
                "uptime_seconds": None,
                "uptime_display": None,
            }

        uptime_seconds = max(0, int(time.time() - create_time))
        return {
            "available": True,
            "cpu_percent": cpu_percent,
            "cpu_percent_raw": raw_cpu_percent,
            "logical_cpu_count": logical_cpu_count,
            "memory_rss_bytes": int(memory_info.rss),
            "memory_rss_mb": self._bytes_to_mb(memory_info.rss),
            "memory_percent": memory_percent,
            "thread_count": int(thread_count),
            "uptime_seconds": uptime_seconds,
            "uptime_display": self._format_duration(uptime_seconds),
        }

    @staticmethod
    def _sensor_process():
        global _SENSOR_PROCESS_HANDLE, _SENSOR_PROCESS_PID

        if _SENSOR_PROCESS_HANDLE is not None:
            try:
                if _SENSOR_PROCESS_HANDLE.is_running():
                    return _SENSOR_PROCESS_HANDLE
            except (psutil.Error, OSError):
                _SENSOR_PROCESS_HANDLE = None
                _SENSOR_PROCESS_PID = None

        windows_candidates = []
        selected_info = None

        for process in psutil.process_iter(["pid", "cmdline", "exe", "name"]):
            try:
                if os.name == "nt" and Database._is_windows_process_debug_candidate(process.info):
                    windows_candidates.append(Database._copy_process_info(process.info))
                if Database._is_sensor_process_info(process.info):
                    _SENSOR_PROCESS_HANDLE = process
                    _SENSOR_PROCESS_PID = process.pid
                    selected_info = Database._copy_process_info(process.info)
                    _SENSOR_PROCESS_HANDLE.cpu_percent(interval=None)
                    if os.name == "nt":
                        Database._print_windows_sensor_process_debug(
                            selected_info, windows_candidates
                        )
                    return _SENSOR_PROCESS_HANDLE
            except (psutil.Error, OSError):
                continue

        raise psutil.NoSuchProcess(_SENSOR_PROCESS_PID or os.getpid())

    @staticmethod
    def _is_sensor_process_info(info):
        cmdline = Database._normalized_cmdline(info)

        if (
            "excalibur.helper.windows_server" in cmdline
            or "excalibur/dashboard/app.py" in cmdline
            or "-m flask" in cmdline
        ):
            return False

        return "excalibur/main.py" in cmdline or "-m excalibur.main" in cmdline

    @staticmethod
    def _normalized_cmdline(info):
        return " ".join(info.get("cmdline") or []).lower().replace("\\", "/")

    @staticmethod
    def _copy_process_info(info):
        return {
            "pid": info.get("pid"),
            "exe": info.get("exe"),
            "cmdline": list(info.get("cmdline") or []),
            "name": info.get("name"),
        }

    @staticmethod
    def _is_windows_process_debug_candidate(info):
        cmdline = Database._normalized_cmdline(info)
        exe = str(info.get("exe") or "").lower().replace("\\", "/")
        name = str(info.get("name") or "").lower()
        return (
            "python" in name
            or "python" in exe
            or "excalibur" in cmdline
            or "excalibur" in exe
            or "excalibur" in name
        )

    @staticmethod
    def _print_windows_sensor_process_debug(selected_info, candidate_infos):
        print("[SystemHealth] Selected sensor process on Windows:", flush=True)
        print(f"[SystemHealth]   PID: {selected_info.get('pid')}", flush=True)
        print(f"[SystemHealth]   Executable path: {selected_info.get('exe')}", flush=True)
        print(
            f"[SystemHealth]   Command line: {' '.join(selected_info.get('cmdline') or [])}",
            flush=True,
        )
        print(f"[SystemHealth]   Process name: {selected_info.get('name')}", flush=True)
        print("[SystemHealth] Windows Python/Excalibur process candidates:", flush=True)
        for info in candidate_infos:
            print(f"[SystemHealth]   PID: {info.get('pid')}", flush=True)
            print(f"[SystemHealth]     Name: {info.get('name')}", flush=True)
            print(f"[SystemHealth]     Executable path: {info.get('exe')}", flush=True)
            print(
                f"[SystemHealth]     Command line: {' '.join(info.get('cmdline') or [])}",
                flush=True,
            )

    @staticmethod
    def _get_system_health_history():
        return _SYSTEM_HEALTH_HISTORY

    @staticmethod
    def _format_duration(total_seconds):
        days, remainder = divmod(int(total_seconds), 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours or parts:
            parts.append(f"{hours}h")
        if minutes or parts:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")
        return " ".join(parts)

    def record_rule_hit(self, rule_name, timestamp):
        with self._lock:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO rule_stats (rule_name, hits, alerts_generated, last_triggered)
                    VALUES (?, 1, 0, ?)
                    ON CONFLICT(rule_name) DO UPDATE SET
                        hits = hits + 1,
                        last_triggered = excluded.last_triggered
                    """,
                    (rule_name, timestamp),
                )

    def record_rule_alert(self, rule_name, timestamp):
        with self._lock:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO rule_stats (rule_name, hits, alerts_generated, last_triggered)
                    VALUES (?, 0, 1, ?)
                    ON CONFLICT(rule_name) DO UPDATE SET
                        alerts_generated = alerts_generated + 1,
                        last_triggered = excluded.last_triggered
                    """,
                    (rule_name, timestamp),
                )

    def get_rule_stats(self):
        self._flush_for_read()
        with self._lock:
            return self.connection.execute(
                """
                SELECT rule_name, hits, alerts_generated, last_triggered
                FROM rule_stats
                ORDER BY rule_name ASC
                """
            ).fetchall()

    def reconcile_system_metrics(self):
        self._flush_for_read()
        write_metric_tables = {
            "traffic_records_written": "traffic",
            "dns_queries_written": "dns_queries",
            "unique_domains_discovered": "domains",
            "alerts_written": "alerts",
            "hosts_added": "hosts",
        }
        with self._lock:
            metrics = self._get_metric_values()
            reconciled_values = {}
            with self.connection:
                for metric_name, table_name in write_metric_tables.items():
                    current_metric = metrics.get(metric_name, 0)
                    current_count = self._count_table(table_name)
                    reconciled_value = max(current_metric, current_count)
                    reconciled_values[metric_name] = reconciled_value
                    if current_metric < current_count:
                        self._set_metric(metric_name, reconciled_value)

                self._set_metric("total_writes", sum(reconciled_values.values()))
            print("[DB] System metrics reconciled", flush=True)

    def _record_write_metrics(self, metric_name, estimated_bytes, started_at):
        elapsed = time.perf_counter() - started_at
        if not self.async_writes:
            self._increment_metric(metric_name, 1)
            self._increment_metric("total_writes", 1)
            self._increment_metric("sqlite_bytes_written", estimated_bytes)
            self._increment_metric("write_latency_total", elapsed)
            self._increment_metric("write_latency_count", 1)
            self._ensure_metric_start_time()
            return
        with self._state_lock:
            self._pending_metrics[metric_name] = self._pending_metrics.get(metric_name, 0) + 1
            self._pending_metrics["total_writes"] = self._pending_metrics.get("total_writes", 0) + 1
            self._pending_metrics["sqlite_bytes_written"] = (
                self._pending_metrics.get("sqlite_bytes_written", 0) + estimated_bytes
            )
            self._pending_metrics["write_latency_total"] = (
                self._pending_metrics.get("write_latency_total", 0) + elapsed
            )
            self._pending_metrics["write_latency_count"] = (
                self._pending_metrics.get("write_latency_count", 0) + 1
            )

    def _record_read_metrics(self, row_metric_name, rows, started_at):
        elapsed = time.perf_counter() - started_at
        estimated_bytes = self._estimate_rows_bytes(rows)
        try:
            self._increment_metric("dashboard_queries_executed", 1)
            if row_metric_name and row_metric_name != "dashboard_queries_executed":
                self._increment_metric(row_metric_name, len(rows))
            self._increment_metric("sqlite_bytes_read", estimated_bytes)
            self._increment_metric("read_latency_total", elapsed)
            self._increment_metric("read_latency_count", 1)
            self._ensure_metric_start_time()
        except sqlite3.OperationalError as exc:
            if self._is_database_locked_error(exc):
                print(
                    "[DB] Warning: skipped read metrics update because database is locked",
                    flush=True,
                )
                return
            raise

    def _increment_metric(self, name, amount):
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO system_metrics (name, value)
                VALUES (?, ?)
                ON CONFLICT(name) DO UPDATE SET value = value + excluded.value
                """,
                (name, float(amount)),
            )

    def _set_metric_if_missing(self, name, value):
        with self.connection:
            self.connection.execute(
                """
                INSERT OR IGNORE INTO system_metrics (name, value)
                VALUES (?, ?)
                """,
                (name, float(value)),
            )

    def _set_metric(self, name, value):
        self.connection.execute(
            """
            INSERT INTO system_metrics (name, value)
            VALUES (?, ?)
            ON CONFLICT(name) DO UPDATE SET value = excluded.value
            """,
            (name, float(value)),
        )

    def _ensure_metric_start_time(self):
        self._set_metric_if_missing("metrics_started_at", time.time())

    def _get_metric_values(self):
        rows = self.connection.execute(
            "SELECT name, value FROM system_metrics"
        ).fetchall()
        return {row["name"]: row["value"] for row in rows}

    def _metric_elapsed_hours(self, metrics):
        started_at = metrics.get("metrics_started_at")
        if not started_at:
            return 0
        elapsed_seconds = max(time.time() - started_at, 1)
        return elapsed_seconds / 3600

    def _count_table(self, table_name):
        return self.connection.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]

    def _get_journal_mode(self):
        return self.connection.execute("PRAGMA journal_mode").fetchone()[0].upper()

    def _estimate_table_mb(self, table_name):
        return self._bytes_to_mb(self._estimate_table_bytes(table_name))

    def _estimate_table_bytes(self, table_name):
        row_count = self._count_table(table_name)
        if row_count == 0:
            return 0
        rows = self.connection.execute(f"SELECT * FROM {table_name} LIMIT 1000").fetchall()
        sampled_bytes = self._estimate_rows_bytes(rows)
        return int(sampled_bytes / len(rows) * row_count) if rows else 0

    def _estimate_rows_bytes(self, rows):
        return sum(self._estimate_bytes(*tuple(row)) for row in rows)

    def _estimate_bytes(self, *values):
        return sum(len(str(value).encode("utf-8")) for value in values if value is not None)

    def _get_file_size(self, path):
        path = Path(path)
        if not path.exists():
            return 0
        return path.stat().st_size

    def _bytes_to_mb(self, value):
        return round(float(value) / 1024 / 1024, 4)

    def _rate_per_hour(self, byte_count, elapsed_hours):
        if elapsed_hours <= 0:
            return 0
        return self._bytes_to_mb(byte_count) / elapsed_hours

    def _average_latency_ms(self, total_seconds, count):
        if count <= 0:
            return 0
        return round((total_seconds / count) * 1000, 4)

    def _is_database_locked_error(self, exc):
        return "database is locked" in str(exc).lower()

    def _normalize_domain(self, domain):
        return str(domain).strip().rstrip(".").lower()

    def _append_new_domain(self, domain):
        log_path = self.runtime_data_dir / "domains.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(f"{domain}\n")

    def close(self):
        if self._writer_thread is not None and self._writer_thread.is_alive():
            self._writer_stop_event.set()
            self._writer_flush_event.set()
            self._writer_thread.join(timeout=5)
        self._flush_pending_writes(
            traffic_rows=[],
            dns_rows=[],
            flush_domains=True,
            flush_hosts=True,
            flush_metrics=True,
        )
        with self._lock:
            self.connection.close()
