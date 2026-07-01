from collections import deque
from datetime import datetime, timezone
from itertools import islice
import json
import os
from queue import Empty, Full, Queue
import sqlite3
import time
from pathlib import Path
from threading import Event, RLock, Thread, current_thread

import psutil

from excalibur.config import Config
from excalibur.detection.domain_risk import DomainRiskAnalyzer
from excalibur.events import AlertEvent
from excalibur.service_lookup import service_case_sql

_SENSOR_PROCESS_HANDLE = None
_SENSOR_PROCESS_PID = None
_SENSOR_PROCESS_CREATE_TIME = None
_SENSOR_PROCESS_SELECTION_SOURCE = None
_WINDOWS_SENSOR_SERVICE_NAME = "ExcaliburSensor"


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
    WRITE_BATCH_SIZE_LOW = 250
    WRITE_BATCH_SIZE_HIGH = 1000
    WRITE_BATCH_SIZE_CRITICAL = 1500
    WRITE_FLUSH_INTERVAL_SECONDS = 0.25
    METRICS_FLUSH_INTERVAL_SECONDS = 5
    HOST_UPDATE_DEBOUNCE_SECONDS = 5
    WRITER_QUEUE_MAXSIZE = 20000
    PERF_LOG_INTERVAL_SECONDS = 5
    RETENTION_IDLE_QUEUE_DEPTH = 1000
    MAINTENANCE_POLL_INTERVAL_SECONDS = 0.5
    OVERFLOW_STRATEGY_DROP_TRAFFIC = "drop_traffic"
    OVERFLOW_STRATEGY_SYNC_WRITE = "sync_write"
    HOST_FLUSH_BATCH_SIZE = 250
    DOMAIN_FLUSH_BATCH_SIZE = 250
    METRIC_FLUSH_BATCH_SIZE = 32
    WRITE_PRESSURE_CONTINUE_DEPTH = 1000
    DROP_WARNING_INTERVAL_SECONDS = 5
    SQLITE_MAX_VARIABLES = 999
    TRAFFIC_INSERT_COLUMNS = (
        "timestamp",
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "packet_size",
        "packet_count",
        "byte_count",
        "first_seen",
        "last_seen",
    )
    TRAFFIC_INSERT_CHUNK_SIZE = max(1, SQLITE_MAX_VARIABLES // len(TRAFFIC_INSERT_COLUMNS))

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
        self._maintenance_stop_event = Event()
        self._maintenance_wake_event = Event()
        self._maintenance_thread = None
        self._pending_metrics = {}
        self._pending_host_inserts = {}
        self._pending_host_updates = {}
        self._host_update_deadlines = {}
        self._known_hosts = set()
        self._known_domains = set()
        self._pending_domain_updates = {}
        self._retention_due = False
        self._overflow_strategy = str(
            os.environ.get(
                "EXCALIBUR_QUEUE_OVERFLOW_STRATEGY",
                self.OVERFLOW_STRATEGY_DROP_TRAFFIC,
            )
        ).strip().lower()
        self._packet_db_lock_wait_total_ms = 0.0
        self._writer_db_lock_wait_total_ms = 0.0
        self._writer_db_lock_hold_total_ms = 0.0
        self._writer_queue_drain_total_ms = 0.0
        self._writer_traffic_exec_total_ms = 0.0
        self._writer_dns_exec_total_ms = 0.0
        self._writer_host_exec_total_ms = 0.0
        self._writer_domain_exec_total_ms = 0.0
        self._writer_metrics_exec_total_ms = 0.0
        self._writer_commit_total_ms = 0.0
        self._retention_total_ms = 0.0
        self._writer_domain_log_total_ms = 0.0
        self._writer_flush_batches = 0
        self._writer_flushed_traffic_rows = 0
        self._writer_flushed_traffic_packets = 0
        self._writer_flushed_traffic_bytes = 0
        self._writer_flushed_dns_rows = 0
        self._writer_flushed_host_inserts = 0
        self._writer_flushed_host_updates = 0
        self._writer_flushed_domain_updates = 0
        self._writer_flushed_metric_updates = 0
        self._writer_queue_high_watermark = 0
        self._writer_queue_lifetime_high_watermark = 0
        self._writer_fallback_sync_total = 0
        self._writer_fallback_sync_lifetime_total = 0
        self._writer_overflow_drop_total = 0
        self._writer_overflow_drop_lifetime_total = 0
        self._writer_overflow_drop_since_warning = 0
        self._last_drop_warning_at = 0.0
        self._retention_runs_total = 0
        self._retention_purged_rows_total = 0
        self._writer_lock_hold_lifetime_total_ms = 0.0
        self._writer_lock_hold_lifetime_max_ms = 0.0
        self._writer_transaction_lifetime_count = 0
        self._writer_queue_depth_before_flush_max = 0
        self._writer_queue_depth_after_flush_max = 0
        self._writer_domain_log_lifetime_total_ms = 0.0
        self._writer_flushed_traffic_lifetime_total = 0
        self._writer_inserted_traffic_row_lifetime_total = 0
        self._writer_flushed_traffic_bytes_lifetime_total = 0
        self._writer_flushed_dns_lifetime_total = 0
        self._writer_flushed_domain_lifetime_total = 0
        self._writer_traffic_exec_lifetime_total_ms = 0.0
        self._writer_traffic_exec_lifetime_max_ms = 0.0
        self._writer_traffic_exec_lifetime_count = 0
        self._retention_lifetime_total_ms = 0.0
        self._retention_lifetime_max_ms = 0.0
        self._last_perf_log_at = time.monotonic()
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
        if self.async_writes:
            self._prime_async_caches()

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
                        id INTEGER PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        src_ip TEXT NOT NULL,
                        dst_ip TEXT NOT NULL,
                        protocol TEXT NOT NULL,
                        src_port INTEGER,
                        dst_port INTEGER,
                        packet_size INTEGER NOT NULL,
                        packet_count INTEGER NOT NULL DEFAULT 1,
                        byte_count INTEGER NOT NULL DEFAULT 0,
                        first_seen TEXT,
                        last_seen TEXT
                    )
                    """
                )
                self._ensure_column("traffic", "packet_count", "INTEGER NOT NULL DEFAULT 1")
                self._ensure_column("traffic", "byte_count", "INTEGER NOT NULL DEFAULT 0")
                self._ensure_column("traffic", "first_seen", "TEXT")
                self._ensure_column("traffic", "last_seen", "TEXT")
                self.connection.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_aggregated_flow
                    ON traffic (
                        timestamp,
                        src_ip,
                        dst_ip,
                        protocol,
                        src_port,
                        dst_port
                    )
                    WHERE first_seen IS NOT NULL
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

    @staticmethod
    def _traffic_packet_count_sql(column_name="packet_count"):
        return f"COALESCE({column_name}, 1)"

    @staticmethod
    def _traffic_byte_count_sql(packet_size_column="packet_size", byte_count_column="byte_count"):
        return (
            "CASE "
            f"WHEN {byte_count_column} IS NULL OR {byte_count_column} <= 0 "
            f"THEN COALESCE({packet_size_column}, 0) "
            f"ELSE {byte_count_column} "
            "END"
        )

    @staticmethod
    def _traffic_first_seen_sql():
        return "COALESCE(first_seen, timestamp)"

    @staticmethod
    def _traffic_last_seen_sql():
        return "COALESCE(last_seen, timestamp)"

    @staticmethod
    def _normalize_traffic_port(port):
        if port in ("", None):
            return -1
        return int(port)

    @staticmethod
    def _bucket_traffic_timestamp(timestamp):
        timestamp = str(timestamp)
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return timestamp.split(".", 1)[0]
        return parsed.replace(microsecond=0).isoformat()

    def _aggregate_traffic_rows(self, traffic_rows):
        aggregated = {}
        for row in traffic_rows:
            (
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
                packet_size,
            ) = row
            normalized_src_port = self._normalize_traffic_port(src_port)
            normalized_dst_port = self._normalize_traffic_port(dst_port)
            packet_size = int(packet_size or 0)
            bucket_timestamp = self._bucket_traffic_timestamp(timestamp)
            key = (
                bucket_timestamp,
                src_ip,
                dst_ip,
                protocol,
                normalized_src_port,
                normalized_dst_port,
            )
            if key not in aggregated:
                aggregated[key] = {
                    "timestamp": bucket_timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "src_port": normalized_src_port,
                    "dst_port": normalized_dst_port,
                    "packet_size": packet_size,
                    "packet_count": 1,
                    "byte_count": packet_size,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }
                continue
            entry = aggregated[key]
            entry["packet_count"] += 1
            entry["byte_count"] += packet_size
            if timestamp < entry["first_seen"]:
                entry["first_seen"] = timestamp
            if timestamp > entry["last_seen"]:
                entry["last_seen"] = timestamp

        return [
            (
                entry["timestamp"],
                entry["src_ip"],
                entry["dst_ip"],
                entry["protocol"],
                entry["src_port"],
                entry["dst_port"],
                entry["packet_size"],
                entry["packet_count"],
                entry["byte_count"],
                entry["first_seen"],
                entry["last_seen"],
            )
            for entry in aggregated.values()
        ]

    def _prime_async_caches(self):
        with self._lock:
            self._known_hosts = {
                row[0]
                for row in self.connection.execute("SELECT ip_address FROM hosts").fetchall()
                if row[0]
            }
            self._known_domains = {
                row[0]
                for row in self.connection.execute("SELECT domain FROM domains").fetchall()
                if row[0]
            }

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
            print(
                "[Ownership] writer_thread_started "
                f"pid={os.getpid()} "
                f"thread_name={self._writer_thread.name} "
                f"thread_ident={self._writer_thread.ident}",
                flush=True,
            )
            self._ensure_maintenance_thread()

    def _ensure_maintenance_thread(self):
        if not self.async_writes:
            return
        if self._maintenance_thread is not None and self._maintenance_thread.is_alive():
            return
        self._maintenance_stop_event.clear()
        self._maintenance_wake_event.clear()
        self._maintenance_thread = Thread(
            target=self._maintenance_loop,
            name="ExcaliburSQLiteMaintenance",
            daemon=True,
        )
        self._maintenance_thread.start()
        print(
            "[Ownership] maintenance_thread_started "
            f"pid={os.getpid()} "
            f"thread_name={self._maintenance_thread.name} "
            f"thread_ident={self._maintenance_thread.ident}",
            flush=True,
        )

    def _maintenance_loop(self):
        print(
            "[Ownership] maintenance_thread_running "
            f"pid={os.getpid()} "
            f"thread_name={current_thread().name} "
            f"thread_ident={current_thread().ident}",
            flush=True,
        )
        while not self._maintenance_stop_event.wait(
            timeout=self.MAINTENANCE_POLL_INTERVAL_SECONDS
        ):
            self._maintenance_wake_event.wait(timeout=0)
            self._maintenance_wake_event.clear()
            self._run_deferred_retention_if_idle()
        self._run_deferred_retention_if_idle(force=True)

    def _writer_loop(self):
        print(
            "[Ownership] writer_thread_running "
            f"pid={os.getpid()} "
            f"thread_name={current_thread().name} "
            f"thread_ident={current_thread().ident}",
            flush=True,
        )
        # The writer thread batches hot-path packet/DNS writes so packet capture
        # work does not churn SQLite transactions on every event.
        traffic_rows = []
        dns_rows = []
        pending_task_dones = 0
        last_flush = time.monotonic()
        last_metrics_flush = last_flush
        last_domain_flush = last_flush
        last_host_flush = last_flush

        while True:
            queue_depth = self._write_queue.qsize()
            batch_target = self._current_batch_size(queue_depth)
            now = time.monotonic()
            force_flush = self._writer_flush_event.is_set()
            should_block_for_item = (
                not force_flush
                and not traffic_rows
                and not dns_rows
            )
            drained_queue_items = 0
            queue_drain_started_at = None

            if should_block_for_item:
                timeout = max(
                    0.01,
                    self.WRITE_FLUSH_INTERVAL_SECONDS - (time.monotonic() - last_flush),
                )
                try:
                    item = self._write_queue.get(timeout=timeout)
                    queue_drain_started_at = time.perf_counter()
                    drained_queue_items += 1
                    pending_task_dones += 1
                    kind = item["kind"]
                    if kind == "traffic":
                        traffic_rows.append(item["row"])
                    elif kind == "dns":
                        dns_rows.append(item["row"])
                except Empty:
                    item = None
            else:
                item = None
                if queue_depth:
                    queue_drain_started_at = time.perf_counter()

            if item is not None or force_flush or queue_depth:
                while len(traffic_rows) + len(dns_rows) < batch_target:
                    try:
                        drained_item = self._write_queue.get_nowait()
                    except Empty:
                        break
                    drained_queue_items += 1
                    pending_task_dones += 1
                    drained_kind = drained_item["kind"]
                    if drained_kind == "traffic":
                        traffic_rows.append(drained_item["row"])
                    elif drained_kind == "dns":
                        dns_rows.append(drained_item["row"])
                if queue_drain_started_at is not None:
                    with self._state_lock:
                        self._writer_queue_drain_total_ms += (
                            (time.perf_counter() - queue_drain_started_at) * 1000
                        )

            queue_depth_before_flush = self._write_queue.qsize() + drained_queue_items
            should_flush_batches = (
                force_flush
                or len(traffic_rows) >= batch_target
                or len(dns_rows) >= batch_target
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
                flush_stats = self._flush_pending_writes(
                    traffic_rows=traffic_rows,
                    dns_rows=dns_rows,
                    flush_domains=should_flush_domains,
                    flush_hosts=should_flush_hosts,
                    flush_metrics=should_flush_metrics,
                    host_limit=self.HOST_FLUSH_BATCH_SIZE,
                    domain_limit=self.DOMAIN_FLUSH_BATCH_SIZE,
                    metrics_limit=self.METRIC_FLUSH_BATCH_SIZE,
                    queue_depth_before_flush=queue_depth_before_flush,
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
                queue_depth_after_flush = self._write_queue.qsize()
                continue_pressure_drain = (
                    queue_depth_after_flush >= self.WRITE_PRESSURE_CONTINUE_DEPTH
                    or (
                        flush_stats["remaining_side_work"]
                        and queue_depth_after_flush > 0
                    )
                )
                if continue_pressure_drain:
                    self._writer_flush_event.set()
                else:
                    self._writer_flush_event.clear()
                for _ in range(pending_task_dones):
                    self._write_queue.task_done()
                pending_task_dones = 0
                self._record_writer_perf(flush_stats, queue_depth_after_flush)
                self._run_deferred_retention_if_idle()

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
                self._run_deferred_retention_if_idle(force=True)
                break

    def _enqueue_write(self, kind, row):
        self._ensure_writer_thread()
        try:
            self._write_queue.put_nowait({"kind": kind, "row": row})
            with self._state_lock:
                self._writer_queue_high_watermark = max(
                    self._writer_queue_high_watermark,
                    self._write_queue.qsize(),
                )
                self._writer_queue_lifetime_high_watermark = max(
                    self._writer_queue_lifetime_high_watermark,
                    self._write_queue.qsize(),
                )
            return True
        except Full:
            warning_message = None
            should_drop = False
            with self._state_lock:
                if (
                    self.async_writes
                    and kind == "traffic"
                    and self._overflow_strategy == self.OVERFLOW_STRATEGY_DROP_TRAFFIC
                ):
                    self._writer_overflow_drop_total += 1
                    self._writer_overflow_drop_lifetime_total += 1
                    self._writer_overflow_drop_since_warning += 1
                    now = time.monotonic()
                    if (
                        self._last_drop_warning_at == 0.0
                        or now - self._last_drop_warning_at
                        >= self.DROP_WARNING_INTERVAL_SECONDS
                    ):
                        warning_message = (
                            "[WARN] SQLite writer queue full; dropped "
                            f"{self._writer_overflow_drop_since_warning} traffic rows "
                            "since previous warning "
                            f"(total_dropped={self._writer_overflow_drop_lifetime_total})"
                        )
                        self._writer_overflow_drop_since_warning = 0
                        self._last_drop_warning_at = now
                    should_drop = True
                if not should_drop:
                    self._writer_fallback_sync_total += 1
                    self._writer_fallback_sync_lifetime_total += 1
            if should_drop:
                if warning_message is not None:
                    print(warning_message, flush=True)
                return True
            if warning_message is not None:
                print(warning_message, flush=True)
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
        host_limit=None,
        domain_limit=None,
        metrics_limit=None,
        queue_depth_before_flush=0,
    ):
        traffic_rows = list(traffic_rows or [])
        dns_rows = list(dns_rows or [])
        aggregated_traffic_rows = self._aggregate_traffic_rows(traffic_rows) if traffic_rows else []
        traffic_packet_events = len(traffic_rows)
        traffic_insert_rows = len(aggregated_traffic_rows)
        traffic_byte_count = sum(row[8] for row in aggregated_traffic_rows)

        with self._state_lock:
            host_inserts = (
                self._pop_pending_items_locked(self._pending_host_inserts, host_limit)
                if flush_hosts
                else {}
            )

            host_updates = (
                self._pop_pending_items_locked(self._pending_host_updates, host_limit)
                if flush_hosts
                else {}
            )
            for ip_address in host_updates:
                self._host_update_deadlines.pop(ip_address, None)

            domain_updates = (
                self._pop_pending_items_locked(self._pending_domain_updates, domain_limit)
                if flush_domains
                else {}
            )

            metrics = (
                self._pop_pending_items_locked(self._pending_metrics, metrics_limit)
                if flush_metrics
                else {}
            )
            remaining_side_work = bool(
                self._pending_host_inserts
                or self._pending_host_updates
                or self._pending_domain_updates
                or self._pending_metrics
            )

        if not (
            traffic_rows
            or dns_rows
            or host_inserts
            or host_updates
            or domain_updates
            or metrics
        ):
            return {
                "traffic_rows": 0,
                "traffic_packet_events": traffic_packet_events,
                "traffic_insert_rows": traffic_insert_rows,
                "traffic_byte_count": traffic_byte_count,
                "dns_rows": 0,
                "host_inserts": 0,
                "host_updates": 0,
                "domain_updates": 0,
                "metric_updates": 0,
                "queue_depth_before_flush": queue_depth_before_flush,
                "queue_depth_after_flush": self._write_queue.qsize(),
                "remaining_side_work": remaining_side_work,
                "domain_log_ms": 0.0,
                "traffic_exec_ms": 0.0,
            }

        retention_check = False
        domains_to_log = []
        lock_wait_started_at = time.perf_counter()
        with self._lock:
            lock_wait_ms = (time.perf_counter() - lock_wait_started_at) * 1000
            lock_hold_started_at = time.perf_counter()
            self.connection.execute("BEGIN")
            try:
                if aggregated_traffic_rows:
                    traffic_exec_started_at = time.perf_counter()
                    self._insert_traffic_rows_locked(aggregated_traffic_rows)
                    traffic_exec_ms = (time.perf_counter() - traffic_exec_started_at) * 1000
                else:
                    traffic_exec_ms = 0.0
                if aggregated_traffic_rows:
                    self._traffic_insert_counter += len(aggregated_traffic_rows)
                    if self._traffic_insert_counter >= self.TRAFFIC_RETENTION_CHECK_INTERVAL:
                        self._traffic_insert_counter %= self.TRAFFIC_RETENTION_CHECK_INTERVAL
                        retention_check = True

                if dns_rows:
                    dns_exec_started_at = time.perf_counter()
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
                    dns_exec_ms = (time.perf_counter() - dns_exec_started_at) * 1000
                else:
                    dns_exec_ms = 0.0

                if host_inserts:
                    host_exec_started_at = time.perf_counter()
                    self.connection.executemany(
                        """
                        INSERT OR IGNORE INTO hosts (
                            ip_address,
                            mac_address,
                            first_seen,
                            last_seen
                        )
                        VALUES (?, ?, ?, ?)
                        """,
                        [
                            (
                                ip_address,
                                values["mac_address"],
                                values["first_seen"],
                                values["last_seen"],
                            )
                            for ip_address, values in host_inserts.items()
                        ],
                    )
                else:
                    host_exec_started_at = None
                if host_updates:
                    if host_exec_started_at is None:
                        host_exec_started_at = time.perf_counter()
                    self.connection.executemany(
                        """
                        UPDATE hosts
                        SET last_seen = ?
                        WHERE ip_address = ?
                        """,
                        [(timestamp, ip_address) for ip_address, timestamp in host_updates.items()],
                    )
                host_exec_ms = (
                    (time.perf_counter() - host_exec_started_at) * 1000
                    if host_exec_started_at is not None
                    else 0.0
                )

                if domain_updates:
                    domain_exec_started_at = time.perf_counter()
                    domains_to_log = self._flush_domain_updates_locked(domain_updates)
                    domain_exec_ms = (time.perf_counter() - domain_exec_started_at) * 1000
                else:
                    domain_exec_ms = 0.0

                if metrics:
                    metrics_exec_started_at = time.perf_counter()
                    self._flush_metrics_locked(metrics)
                    metrics_exec_ms = (time.perf_counter() - metrics_exec_started_at) * 1000
                else:
                    metrics_exec_ms = 0.0

                commit_started_at = time.perf_counter()
                self.connection.commit()
                commit_ms = (time.perf_counter() - commit_started_at) * 1000
            except Exception:
                self.connection.rollback()
                raise
            lock_hold_ms = (time.perf_counter() - lock_hold_started_at) * 1000

        with self._state_lock:
            self._writer_db_lock_wait_total_ms += lock_wait_ms
            self._writer_db_lock_hold_total_ms += lock_hold_ms
            self._writer_traffic_exec_total_ms += traffic_exec_ms
            self._writer_dns_exec_total_ms += dns_exec_ms
            self._writer_host_exec_total_ms += host_exec_ms
            self._writer_domain_exec_total_ms += domain_exec_ms
            self._writer_metrics_exec_total_ms += metrics_exec_ms
            self._writer_commit_total_ms += commit_ms
            self._writer_lock_hold_lifetime_total_ms += lock_hold_ms
            self._writer_lock_hold_lifetime_max_ms = max(
                self._writer_lock_hold_lifetime_max_ms,
                lock_hold_ms,
            )
            self._writer_transaction_lifetime_count += 1
            self._writer_queue_depth_before_flush_max = max(
                self._writer_queue_depth_before_flush_max,
                queue_depth_before_flush,
            )
            self._writer_queue_depth_after_flush_max = max(
                self._writer_queue_depth_after_flush_max,
                self._write_queue.qsize(),
            )

        domain_log_ms = 0.0
        if domains_to_log:
            domain_log_started_at = time.perf_counter()
            self._append_new_domains(domains_to_log)
            domain_log_ms = (time.perf_counter() - domain_log_started_at) * 1000
            with self._state_lock:
                self._writer_domain_log_total_ms += domain_log_ms
                self._writer_domain_log_lifetime_total_ms += domain_log_ms

        if retention_check:
            with self._state_lock:
                self._retention_due = True
            self._maintenance_wake_event.set()
        return {
            "traffic_rows": len(aggregated_traffic_rows),
            "traffic_packet_events": traffic_packet_events,
            "traffic_insert_rows": traffic_insert_rows,
            "traffic_byte_count": traffic_byte_count,
            "dns_rows": len(dns_rows),
            "host_inserts": len(host_inserts),
            "host_updates": len(host_updates),
            "domain_updates": len(domain_updates),
            "metric_updates": len(metrics),
            "queue_depth_before_flush": queue_depth_before_flush,
            "queue_depth_after_flush": self._write_queue.qsize(),
            "remaining_side_work": remaining_side_work,
            "domain_log_ms": round(domain_log_ms, 3),
            "traffic_exec_ms": round(traffic_exec_ms, 3),
        }

    def _insert_traffic_rows_locked(self, traffic_rows):
        if not traffic_rows:
            return 0
        columns = ", ".join(self.TRAFFIC_INSERT_COLUMNS)
        row_placeholders = "(" + ", ".join(["?"] * len(self.TRAFFIC_INSERT_COLUMNS)) + ")"
        inserted = 0
        for offset in range(0, len(traffic_rows), self.TRAFFIC_INSERT_CHUNK_SIZE):
            chunk = traffic_rows[offset : offset + self.TRAFFIC_INSERT_CHUNK_SIZE]
            placeholders = ", ".join([row_placeholders] * len(chunk))
            params = [value for row in chunk for value in row]
            self.connection.execute(
                f"""
                INSERT INTO traffic ({columns})
                VALUES {placeholders}
                ON CONFLICT(timestamp, src_ip, dst_ip, protocol, src_port, dst_port)
                WHERE first_seen IS NOT NULL
                DO UPDATE SET
                    packet_count = traffic.packet_count + excluded.packet_count,
                    byte_count = traffic.byte_count + excluded.byte_count,
                    packet_size = excluded.packet_size,
                    first_seen = MIN(traffic.first_seen, excluded.first_seen),
                    last_seen = MAX(traffic.last_seen, excluded.last_seen)
                """,
                params,
            )
            inserted += len(chunk)
        return inserted

    def _current_batch_size(self, queue_depth):
        if queue_depth >= int(self.WRITER_QUEUE_MAXSIZE * 0.75):
            return self.WRITE_BATCH_SIZE_CRITICAL
        if queue_depth >= int(self.WRITER_QUEUE_MAXSIZE * 0.25):
            return self.WRITE_BATCH_SIZE_HIGH
        if queue_depth <= max(10, self.WRITE_BATCH_SIZE_LOW):
            return self.WRITE_BATCH_SIZE_LOW
        return self.WRITE_BATCH_SIZE

    def _run_deferred_retention_if_idle(self, force=False):
        with self._state_lock:
            retention_due = self._retention_due
        if not retention_due:
            return 0

        queue_depth = self._write_queue.qsize()
        if not force and queue_depth > self.RETENTION_IDLE_QUEUE_DEPTH:
            return 0

        retention_started_at = time.perf_counter()
        purged = self.enforce_traffic_limit(Config.TRAFFIC_MAX_RECORDS)
        retention_ms = (time.perf_counter() - retention_started_at) * 1000
        with self._state_lock:
            self._retention_due = False
            self._retention_total_ms += retention_ms
            self._retention_lifetime_total_ms += retention_ms
            self._retention_lifetime_max_ms = max(
                self._retention_lifetime_max_ms,
                retention_ms,
            )
            self._retention_runs_total += 1
            self._retention_purged_rows_total += purged
        return purged

    def _flush_domain_updates_locked(self, domain_updates):
        domain_rows = []
        risk_rows = []
        domains_to_log = []
        for domain, state in domain_updates.items():
            domain_rows.append(
                (
                    domain,
                    state["first_seen"],
                    state["last_seen"],
                    state["query_count"],
                )
            )
            risk_result = state["risk_result"]
            risk_rows.append(
                (
                    risk_result["domain"],
                    risk_result["risk_score"],
                    risk_result["risk_level"],
                    "; ".join(risk_result["reasons"]),
                    state["first_seen"],
                    state["last_seen"],
                    state["query_count"],
                )
            )
            if state["is_new"]:
                domains_to_log.append(domain)

        if domain_rows:
            self.connection.executemany(
                """
                INSERT INTO domains (domain, first_seen, last_seen, query_count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    query_count = domains.query_count + excluded.query_count
                """,
                domain_rows,
            )
        if risk_rows:
            self.connection.executemany(
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
                risk_rows,
            )
        return domains_to_log

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

    def _record_writer_perf(self, flush_stats, queue_depth):
        with self._state_lock:
            self._writer_flush_batches += 1
            self._writer_flushed_traffic_rows += flush_stats["traffic_insert_rows"]
            self._writer_flushed_traffic_packets += flush_stats["traffic_packet_events"]
            self._writer_flushed_traffic_bytes += flush_stats["traffic_byte_count"]
            self._writer_flushed_dns_rows += flush_stats["dns_rows"]
            self._writer_flushed_host_inserts += flush_stats["host_inserts"]
            self._writer_flushed_host_updates += flush_stats["host_updates"]
            self._writer_flushed_domain_updates += flush_stats["domain_updates"]
            self._writer_flushed_metric_updates += flush_stats["metric_updates"]
            self._writer_flushed_traffic_lifetime_total += flush_stats["traffic_packet_events"]
            self._writer_inserted_traffic_row_lifetime_total += flush_stats["traffic_insert_rows"]
            self._writer_flushed_traffic_bytes_lifetime_total += flush_stats["traffic_byte_count"]
            self._writer_flushed_dns_lifetime_total += flush_stats["dns_rows"]
            self._writer_flushed_domain_lifetime_total += flush_stats["domain_updates"]
            self._writer_traffic_exec_lifetime_total_ms += flush_stats["traffic_exec_ms"]
            self._writer_traffic_exec_lifetime_max_ms = max(
                self._writer_traffic_exec_lifetime_max_ms,
                flush_stats["traffic_exec_ms"],
            )
            if flush_stats["traffic_insert_rows"] or flush_stats["traffic_packet_events"]:
                self._writer_traffic_exec_lifetime_count += 1
            self._writer_queue_high_watermark = max(
                self._writer_queue_high_watermark,
                queue_depth,
            )
            self._writer_queue_lifetime_high_watermark = max(
                self._writer_queue_lifetime_high_watermark,
                queue_depth,
            )
            now = time.monotonic()
            if now - self._last_perf_log_at < self.PERF_LOG_INTERVAL_SECONDS:
                return
            snapshot = {
                "packet_db_lock_wait_ms": round(self._packet_db_lock_wait_total_ms, 3),
                "writer_db_lock_wait_ms": round(self._writer_db_lock_wait_total_ms, 3),
                "writer_db_lock_hold_ms": round(self._writer_db_lock_hold_total_ms, 3),
                "queue_drain_ms": round(self._writer_queue_drain_total_ms, 3),
                "traffic_exec_ms": round(self._writer_traffic_exec_total_ms, 3),
                "dns_exec_ms": round(self._writer_dns_exec_total_ms, 3),
                "host_exec_ms": round(self._writer_host_exec_total_ms, 3),
                "domain_exec_ms": round(self._writer_domain_exec_total_ms, 3),
                "metrics_exec_ms": round(self._writer_metrics_exec_total_ms, 3),
                "commit_ms": round(self._writer_commit_total_ms, 3),
                "domain_log_ms": round(self._writer_domain_log_total_ms, 3),
                "retention_ms": round(self._retention_total_ms, 3),
                "queue_depth": queue_depth,
                "queue_high_watermark": self._writer_queue_lifetime_high_watermark,
                "queue_depth_before_flush_max": self._writer_queue_depth_before_flush_max,
                "queue_depth_after_flush_max": self._writer_queue_depth_after_flush_max,
                "flush_batches": self._writer_flush_batches,
                "traffic_packets": self._writer_flushed_traffic_packets,
                "traffic_rows": self._writer_flushed_traffic_rows,
                "traffic_bytes": self._writer_flushed_traffic_bytes,
                "dns_rows": self._writer_flushed_dns_rows,
                "host_inserts": self._writer_flushed_host_inserts,
                "host_updates": self._writer_flushed_host_updates,
                "domain_updates": self._writer_flushed_domain_updates,
                "metric_updates": self._writer_flushed_metric_updates,
                "fallback_sync_writes": self._writer_fallback_sync_total,
                "dropped_traffic_rows": self._writer_overflow_drop_total,
                "retention_runs": self._retention_runs_total,
                "retention_purged_rows": self._retention_purged_rows_total,
            }
            self._writer_db_lock_wait_total_ms = 0.0
            self._writer_db_lock_hold_total_ms = 0.0
            self._writer_queue_drain_total_ms = 0.0
            self._writer_traffic_exec_total_ms = 0.0
            self._writer_dns_exec_total_ms = 0.0
            self._writer_host_exec_total_ms = 0.0
            self._writer_domain_exec_total_ms = 0.0
            self._writer_metrics_exec_total_ms = 0.0
            self._writer_commit_total_ms = 0.0
            self._writer_domain_log_total_ms = 0.0
            self._retention_total_ms = 0.0
            self._writer_flush_batches = 0
            self._writer_flushed_traffic_rows = 0
            self._writer_flushed_traffic_packets = 0
            self._writer_flushed_traffic_bytes = 0
            self._writer_flushed_dns_rows = 0
            self._writer_flushed_host_inserts = 0
            self._writer_flushed_host_updates = 0
            self._writer_flushed_domain_updates = 0
            self._writer_flushed_metric_updates = 0
            self._writer_queue_high_watermark = queue_depth
            self._writer_queue_depth_before_flush_max = 0
            self._writer_queue_depth_after_flush_max = 0
            self._writer_fallback_sync_total = 0
            self._writer_overflow_drop_total = 0
            self._retention_runs_total = 0
            self._retention_purged_rows_total = 0
            self._last_perf_log_at = now
        print(
            "[DBPERF] "
            f"packet_db_lock_wait_ms={snapshot['packet_db_lock_wait_ms']} "
            f"writer_db_lock_wait_ms={snapshot['writer_db_lock_wait_ms']} "
            f"writer_db_lock_hold_ms={snapshot['writer_db_lock_hold_ms']} "
            f"queue_drain_ms={snapshot['queue_drain_ms']} "
            f"traffic_exec_ms={snapshot['traffic_exec_ms']} "
            f"dns_exec_ms={snapshot['dns_exec_ms']} "
            f"host_exec_ms={snapshot['host_exec_ms']} "
            f"domain_exec_ms={snapshot['domain_exec_ms']} "
            f"metrics_exec_ms={snapshot['metrics_exec_ms']} "
            f"commit_ms={snapshot['commit_ms']} "
            f"domain_log_ms={snapshot['domain_log_ms']} "
            f"retention_ms={snapshot['retention_ms']} "
            f"queue_depth={snapshot['queue_depth']} "
            f"queue_high_watermark={snapshot['queue_high_watermark']} "
            "queue_depth_before_flush_max="
            f"{snapshot['queue_depth_before_flush_max']} "
            "queue_depth_after_flush_max="
            f"{snapshot['queue_depth_after_flush_max']} "
            f"flush_batches={snapshot['flush_batches']} "
            f"traffic_packets={snapshot['traffic_packets']} "
            f"traffic_rows={snapshot['traffic_rows']} "
            f"traffic_bytes={snapshot['traffic_bytes']} "
            f"dns_rows={snapshot['dns_rows']} "
            f"host_inserts={snapshot['host_inserts']} "
            f"host_updates={snapshot['host_updates']} "
            f"domain_updates={snapshot['domain_updates']} "
            f"metric_updates={snapshot['metric_updates']} "
            f"fallback_sync_writes={snapshot['fallback_sync_writes']} "
            f"dropped_traffic_rows={snapshot['dropped_traffic_rows']} "
            f"retention_runs={snapshot['retention_runs']} "
            f"retention_purged_rows={snapshot['retention_purged_rows']}",
            flush=True,
        )

    def get_async_perf_snapshot(self):
        with self._state_lock:
            snapshot = {
                "packet_db_lock_wait_ms": round(self._packet_db_lock_wait_total_ms, 3),
                "writer_db_lock_wait_ms": round(self._writer_db_lock_wait_total_ms, 3),
                "writer_db_lock_hold_ms": round(self._writer_db_lock_hold_total_ms, 3),
                "writer_db_lock_hold_max_ms": round(self._writer_lock_hold_lifetime_max_ms, 3),
                "queue_depth": self._write_queue.qsize(),
            }
            self._packet_db_lock_wait_total_ms = 0.0
            return snapshot

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

    def record_traffic_write_failure(self):
        self._add_pending_metric("traffic_write_failures", 1)

    def _domain_exists(self, normalized_domain):
        lock_wait_started_at = time.perf_counter()
        with self._lock:
            lock_wait_ms = (time.perf_counter() - lock_wait_started_at) * 1000
            with self._state_lock:
                self._packet_db_lock_wait_total_ms += lock_wait_ms
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

    def record_host_seen(self, ip_address, mac_address, timestamp):
        if not self.async_writes:
            if self.host_exists(ip_address):
                return self.update_host_last_seen(ip_address, timestamp)
            return self.add_host(ip_address, mac_address, timestamp, timestamp)

        now = time.monotonic()
        with self._state_lock:
            if ip_address not in self._known_hosts:
                self._known_hosts.add(ip_address)
                self._pending_host_inserts[ip_address] = {
                    "mac_address": mac_address,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }
                self._host_update_deadlines[ip_address] = (
                    now + self.HOST_UPDATE_DEBOUNCE_SECONDS
                )
                self._record_write_metrics(
                    "hosts_added",
                    self._estimate_bytes(ip_address, mac_address, timestamp, timestamp),
                    time.perf_counter(),
                )
                self._ensure_writer_thread()
                return 1

            pending_insert = self._pending_host_inserts.get(ip_address)
            if pending_insert is not None:
                pending_insert["last_seen"] = timestamp
                if mac_address and not pending_insert.get("mac_address"):
                    pending_insert["mac_address"] = mac_address
                self._ensure_writer_thread()
                return 1

            deadline = self._host_update_deadlines.get(ip_address)
            self._pending_host_updates[ip_address] = timestamp
            if deadline is None or now >= deadline:
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
        normalized_src_port = self._normalize_traffic_port(src_port)
        normalized_dst_port = self._normalize_traffic_port(dst_port)
        if not self.async_writes:
            started_at = time.perf_counter()
            with self._lock:
                with self.connection:
                    self._insert_traffic_rows_locked(
                        [
                            (
                                timestamp,
                                src_ip,
                                dst_ip,
                                protocol,
                                normalized_src_port,
                                normalized_dst_port,
                                packet_size,
                                1,
                                packet_size,
                                timestamp,
                                timestamp,
                            )
                        ]
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
                    self._traffic_insert_counter += 1

            if self._traffic_insert_counter >= self.TRAFFIC_RETENTION_CHECK_INTERVAL:
                self._traffic_insert_counter = 0
                self.enforce_traffic_limit(Config.TRAFFIC_MAX_RECORDS)
            return None
        started_at = time.perf_counter()
        row = (
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            normalized_src_port,
            normalized_dst_port,
            packet_size,
        )
        self._record_write_metrics(
            "traffic_records_written",
            self._estimate_bytes(*row),
            started_at,
        )
        self._enqueue_write("traffic", row)
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
        perf_stats=None,
    ):
        perf_stats = perf_stats if perf_stats is not None else {}
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
                    perf_stats["dns_row_ms"] = perf_stats.get("dns_row_ms", 0.0) + (
                        (time.perf_counter() - started_at) * 1000
                    )
                domain_started_at = time.perf_counter()
                risk_result = self.upsert_domain(
                    normalized_domain,
                    timestamp,
                    client_ip=client_ip,
                    dns_server_ip=dns_server_ip,
                    perf_stats=perf_stats,
                )
                perf_stats["domain_ms"] = perf_stats.get("domain_ms", 0.0) + (
                    (time.perf_counter() - domain_started_at) * 1000
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
        perf_stats["dns_row_ms"] = perf_stats.get("dns_row_ms", 0.0) + (
            (time.perf_counter() - started_at) * 1000
        )
        if not self._enqueue_write("dns", row):
            self._flush_pending_writes(
                traffic_rows=[],
                dns_rows=[row],
                flush_domains=False,
                flush_hosts=False,
                flush_metrics=False,
            )
        domain_started_at = time.perf_counter()
        risk_result = self.upsert_domain(
            normalized_domain,
            timestamp,
            client_ip=client_ip,
            dns_server_ip=dns_server_ip,
            perf_stats=perf_stats,
        )
        perf_stats["domain_ms"] = perf_stats.get("domain_ms", 0.0) + (
            (time.perf_counter() - domain_started_at) * 1000
        )
        return {
            "id": None,
            "domain_risk": risk_result,
        }

    def upsert_domain(
        self,
        domain,
        timestamp,
        client_ip=None,
        dns_server_ip=None,
        perf_stats=None,
    ):
        perf_stats = perf_stats if perf_stats is not None else {}
        normalized_domain = self._normalize_domain(domain)
        risk_started_at = time.perf_counter()
        risk_result = self.analyze_domain_risk(normalized_domain)
        perf_stats["domain_risk_ms"] = perf_stats.get("domain_risk_ms", 0.0) + (
            (time.perf_counter() - risk_started_at) * 1000
        )
        if not self.async_writes:
            with self._lock:
                lookup_started_at = time.perf_counter()
                existing_domain = self.connection.execute(
                    """
                    SELECT id
                    FROM domains
                    WHERE domain = ?
                    """,
                    (normalized_domain,),
                ).fetchone()
                perf_stats["domain_lookup_ms"] = perf_stats.get("domain_lookup_ms", 0.0) + (
                    (time.perf_counter() - lookup_started_at) * 1000
                )

                with self.connection:
                    if existing_domain:
                        update_started_at = time.perf_counter()
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
                        perf_stats["domain_write_ms"] = perf_stats.get("domain_write_ms", 0.0) + (
                            (time.perf_counter() - update_started_at) * 1000
                        )
                        return risk_result

                    insert_started_at = time.perf_counter()
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
                perf_stats["domain_write_ms"] = perf_stats.get("domain_write_ms", 0.0) + (
                    (time.perf_counter() - insert_started_at) * 1000
                )
                return risk_result
        should_create_alert = False
        with self._state_lock:
            state_started_at = time.perf_counter()
            domain_state = self._pending_domain_updates.get(normalized_domain)
            if domain_state is None:
                is_new = normalized_domain not in self._known_domains
                domain_state = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "query_count": 1,
                    "risk_result": risk_result,
                    "is_new": is_new,
                }
                self._pending_domain_updates[normalized_domain] = domain_state
                self._known_domains.add(normalized_domain)
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
            perf_stats["domain_state_ms"] = perf_stats.get("domain_state_ms", 0.0) + (
                (time.perf_counter() - state_started_at) * 1000
            )

        self._ensure_writer_thread()
        if should_create_alert:
            alert_started_at = time.perf_counter()
            self._create_domain_risk_alert_if_needed(
                risk_result,
                timestamp,
                client_ip,
                dns_server_ip,
            )
            perf_stats["domain_alert_ms"] = perf_stats.get("domain_alert_ms", 0.0) + (
                (time.perf_counter() - alert_started_at) * 1000
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

    def count_traffic_packets(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                f"SELECT COALESCE(SUM({self._traffic_packet_count_sql()}), 0) FROM traffic"
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return int(row[0] or 0)

    def count_traffic_bytes(self):
        self._flush_for_read()
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                f"SELECT COALESCE(SUM({self._traffic_byte_count_sql()}), 0) FROM traffic"
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return int(row[0] or 0)

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
                SELECT
                    timestamp,
                    src_ip,
                    dst_ip,
                    protocol,
                    NULLIF(src_port, -1) AS src_port,
                    NULLIF(dst_port, -1) AS dst_port,
                    packet_size,
                    COALESCE(packet_count, 1) AS packet_count,
                    CASE
                        WHEN byte_count IS NULL OR byte_count <= 0 THEN COALESCE(packet_size, 0)
                        ELSE byte_count
                    END AS byte_count,
                    COALESCE(first_seen, timestamp) AS first_seen,
                    COALESCE(last_seen, timestamp) AS last_seen
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
            "first_seen",
            "last_seen",
            "src_ip",
            "dst_ip",
            "protocol",
            "src_port",
            "dst_port",
            "packet_size",
            "packet_count",
            "byte_count",
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

        service_expression = service_case_sql("NULLIF(dst_port, -1)")
        where_clause, params = self._build_traffic_where_clause(
            search,
            filters,
            service_expression=service_expression,
        )
        count_query = f"SELECT COUNT(*) FROM traffic {where_clause}"
        select_query = f"""
            SELECT
                timestamp,
                COALESCE(first_seen, timestamp) AS first_seen,
                COALESCE(last_seen, timestamp) AS last_seen,
                src_ip,
                dst_ip,
                protocol,
                NULLIF(src_port, -1) AS src_port,
                NULLIF(dst_port, -1) AS dst_port,
                {service_expression} AS service,
                packet_size,
                COALESCE(packet_count, 1) AS packet_count,
                CASE
                    WHEN byte_count IS NULL OR byte_count <= 0 THEN COALESCE(packet_size, 0)
                    ELSE byte_count
                END AS byte_count
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
            "src_port": "NULLIF(src_port, -1)",
            "dst_port": "NULLIF(dst_port, -1)",
        }
        for key, column in filter_columns.items():
            value = filters.get(key)
            if value in (None, ""):
                continue
            clauses.append(f"{column} = ?")
            if key in {"src_port", "dst_port"}:
                params.append(int(value))
            else:
                params.append(value)

        if search:
            search_value = f"%{search}%"
            clauses.append(
                f"""
                (
                    src_ip LIKE ?
                    OR dst_ip LIKE ?
                    OR protocol LIKE ?
                    OR CAST(NULLIF(src_port, -1) AS TEXT) LIKE ?
                    OR CAST(NULLIF(dst_port, -1) AS TEXT) LIKE ?
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
                SELECT
                    timestamp,
                    src_ip,
                    dst_ip,
                    protocol,
                    NULLIF(src_port, -1) AS src_port,
                    NULLIF(dst_port, -1) AS dst_port,
                    packet_size,
                    COALESCE(packet_count, 1) AS packet_count,
                    CASE
                        WHEN byte_count IS NULL OR byte_count <= 0 THEN COALESCE(packet_size, 0)
                        ELSE byte_count
                    END AS byte_count,
                    COALESCE(first_seen, timestamp) AS first_seen,
                    COALESCE(last_seen, timestamp) AS last_seen
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
            traffic_record_count = self._count_table("traffic")
            traffic_packet_count = self._count_traffic_packets_locked()
            traffic_byte_count = self._count_traffic_bytes_locked()
            counts = {
                "traffic": traffic_record_count,
                "traffic_packets": traffic_packet_count,
                "traffic_bytes": traffic_byte_count,
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
                "traffic_write_failures": int(metrics.get("traffic_write_failures", 0)),
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
                    "traffic_packets": counts["traffic_packets"],
                    "traffic_bytes": counts["traffic_bytes"],
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
                    "current_packet_count": counts["traffic_packets"],
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
            self._log_system_health_refresh(
                process=process,
                selection_source=_SENSOR_PROCESS_SELECTION_SOURCE,
                raw_cpu_percent=raw_cpu_percent,
                memory_rss_bytes=int(memory_info.rss),
                thread_count=int(thread_count),
                create_time=create_time,
            )
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
        global _SENSOR_PROCESS_HANDLE, _SENSOR_PROCESS_PID, _SENSOR_PROCESS_CREATE_TIME
        global _SENSOR_PROCESS_SELECTION_SOURCE

        if _SENSOR_PROCESS_HANDLE is not None:
            try:
                if (
                    _SENSOR_PROCESS_HANDLE.is_running()
                    and _SENSOR_PROCESS_CREATE_TIME is not None
                    and _SENSOR_PROCESS_HANDLE.create_time() == _SENSOR_PROCESS_CREATE_TIME
                ):
                    _SENSOR_PROCESS_SELECTION_SOURCE = "cached_process"
                    return _SENSOR_PROCESS_HANDLE
            except (psutil.Error, OSError):
                _SENSOR_PROCESS_HANDLE = None
                _SENSOR_PROCESS_PID = None
                _SENSOR_PROCESS_CREATE_TIME = None
                _SENSOR_PROCESS_SELECTION_SOURCE = None
            else:
                _SENSOR_PROCESS_HANDLE = None
                _SENSOR_PROCESS_PID = None
                _SENSOR_PROCESS_CREATE_TIME = None
                _SENSOR_PROCESS_SELECTION_SOURCE = None

        windows_candidates = []
        matching_processes = []

        for process in psutil.process_iter(["pid", "cmdline", "exe", "name"]):
            try:
                if os.name == "nt" and Database._is_windows_process_debug_candidate(process.info):
                    windows_candidates.append(Database._copy_process_info(process.info))
                if Database._is_sensor_process_info(process.info):
                    matching_processes.append(process)
            except (psutil.Error, OSError):
                continue

        selected_process = None
        selection_reason = "process_enumeration_fallback"
        if os.name == "nt":
            selected_process, service_selection_reason = Database._sensor_process_from_windows_service(
                windows_candidates
            )
            if selected_process is not None:
                selection_reason = service_selection_reason or "windows_service_lookup"

        if selected_process is None and matching_processes:
            selected_process = Database._select_sensor_process_candidate(
                matching_processes
            )

        if selected_process is not None:
            _SENSOR_PROCESS_HANDLE = selected_process
            _SENSOR_PROCESS_PID = selected_process.pid
            _SENSOR_PROCESS_CREATE_TIME = selected_process.create_time()
            _SENSOR_PROCESS_SELECTION_SOURCE = selection_reason
            _SENSOR_PROCESS_HANDLE.cpu_percent(interval=None)
            if os.name == "nt":
                Database._print_windows_sensor_process_debug(
                    Database._copy_process_info(getattr(selected_process, "info", {}) or {
                        "pid": selected_process.pid,
                        "exe": getattr(selected_process, "exe", lambda: None)(),
                        "cmdline": getattr(selected_process, "cmdline", lambda: [])(),
                        "name": getattr(selected_process, "name", lambda: None)(),
                    }),
                    windows_candidates,
                    selection_reason=selection_reason,
                )
            return _SENSOR_PROCESS_HANDLE

        raise psutil.NoSuchProcess(_SENSOR_PROCESS_PID or os.getpid())

    @staticmethod
    def _sensor_process_from_windows_service(candidate_infos):
        win_service_get = getattr(psutil, "win_service_get", None)
        if win_service_get is None:
            return None, None
        try:
            service = win_service_get(_WINDOWS_SENSOR_SERVICE_NAME)
            service_info = service.as_dict()
            print(
                "[SystemHealth] Windows service lookup: "
                f"name={_WINDOWS_SENSOR_SERVICE_NAME} "
                f"status={service_info.get('status')} "
                f"pid={service_info.get('pid')}",
                flush=True,
            )
        except (AttributeError, psutil.Error, OSError):
            print(
                "[SystemHealth] Windows service lookup failed for "
                f"{_WINDOWS_SENSOR_SERVICE_NAME}",
                flush=True,
            )
            return None, None

        pid = service_info.get("pid")
        status = str(service_info.get("status") or "").lower()
        if not pid or status != "running":
            return None, None

        try:
            root_process = psutil.Process(pid)
            root_info = root_process.as_dict(attrs=["pid", "cmdline", "exe", "name"])
            if Database._is_windows_process_debug_candidate(root_info):
                candidate_infos.append(Database._copy_process_info(root_info))
            root_process.info = root_info

            matching_descendants = []
            for descendant, depth in Database._walk_process_descendants(root_process):
                try:
                    info = descendant.as_dict(attrs=["pid", "cmdline", "exe", "name"])
                    descendant.info = info
                    descendant._service_tree_depth = depth
                    if Database._is_windows_process_debug_candidate(info):
                        candidate_infos.append(Database._copy_process_info(info))
                    if Database._is_sensor_process_info(info):
                        matching_descendants.append(descendant)
                except (psutil.Error, OSError):
                    continue

            if matching_descendants:
                return (
                    Database._select_sensor_process_candidate(matching_descendants),
                    "windows_service_child_worker",
                )
            if Database._is_sensor_process_info(root_info):
                return root_process, "windows_service_lookup"
        except (psutil.Error, OSError):
            return None, None
        return None, None

    @staticmethod
    def _walk_process_descendants(process):
        descendants = []

        def visit(node, depth):
            try:
                children = node.children()
            except (psutil.Error, OSError):
                return
            if not isinstance(children, (list, tuple)):
                return
            for child in children:
                descendants.append((child, depth))
                visit(child, depth + 1)

        visit(process, 1)
        return descendants

    def _log_system_health_refresh(
        self,
        process,
        selection_source,
        raw_cpu_percent,
        memory_rss_bytes,
        thread_count,
        create_time,
    ):
        try:
            exe_path = process.exe()
        except (psutil.Error, OSError):
            exe_path = None
        try:
            cmdline = process.cmdline()
        except (psutil.Error, OSError):
            cmdline = []
        if not isinstance(cmdline, (list, tuple)):
            cmdline = [str(cmdline)]
        try:
            parent = process.parent()
        except (psutil.Error, OSError):
            parent = None
        try:
            children = process.children()
        except (psutil.Error, OSError):
            children = []
        if not isinstance(children, (list, tuple)):
            children = []

        parent_pid = None
        parent_exe = None
        if parent is not None:
            try:
                parent_pid = parent.pid
                parent_exe = parent.exe()
            except (psutil.Error, OSError):
                parent_pid = getattr(parent, "pid", None)
                parent_exe = None

        child_pids = []
        child_names = []
        for child in children:
            child_pids.append(getattr(child, "pid", None))
            try:
                child_names.append(child.name())
            except (psutil.Error, OSError):
                child_names.append(None)

        print("[SystemHealth] Refresh sample:", flush=True)
        print(f"[SystemHealth]   Selection source: {selection_source}", flush=True)
        print(f"[SystemHealth]   PID: {process.pid}", flush=True)
        print(f"[SystemHealth]   Executable path: {exe_path}", flush=True)
        print(f"[SystemHealth]   Command line: {' '.join(cmdline)}", flush=True)
        print(f"[SystemHealth]   Parent PID: {parent_pid}", flush=True)
        print(f"[SystemHealth]   Parent executable: {parent_exe}", flush=True)
        print(f"[SystemHealth]   Child PIDs: {child_pids}", flush=True)
        print(f"[SystemHealth]   Child executable names: {child_names}", flush=True)
        print(f"[SystemHealth]   Create time: {create_time}", flush=True)
        print(f"[SystemHealth]   RSS bytes: {memory_rss_bytes}", flush=True)
        print(
            f"[SystemHealth]   RSS MB: {self._bytes_to_mb(memory_rss_bytes)}",
            flush=True,
        )
        print(f"[SystemHealth]   Thread count: {thread_count}", flush=True)
        print(f"[SystemHealth]   CPU percent raw: {raw_cpu_percent}", flush=True)

    @staticmethod
    def _select_sensor_process_candidate(processes):
        def score(process):
            info = getattr(process, "info", {}) or {}
            cmdline = Database._normalized_cmdline(info)
            exe = str(info.get("exe") or "").lower().replace("\\", "/")
            exact_main = "excalibur/main.py" in cmdline
            module_main = "-m excalibur.main" in cmdline
            venv_python = "/.venv/" in exe or "\\.venv\\" in str(info.get("exe") or "")
            cmdline_len = len(info.get("cmdline") or [])
            depth = int(getattr(process, "_service_tree_depth", 0) or 0)
            return (
                depth,
                1 if exact_main else 0,
                1 if module_main else 0,
                1 if venv_python else 0,
                cmdline_len,
                -int(info.get("pid") or 0),
            )

        for process in processes:
            if not hasattr(process, "info"):
                try:
                    process.info = process.as_dict(attrs=["pid", "cmdline", "exe", "name"])
                except (psutil.Error, OSError):
                    process.info = {"pid": process.pid, "cmdline": [], "exe": None, "name": None}
        return max(processes, key=score)

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
    def _print_windows_sensor_process_debug(
        selected_info,
        candidate_infos,
        selection_reason="process_enumeration_fallback",
    ):
        print("[SystemHealth] Selected sensor process on Windows:", flush=True)
        print(f"[SystemHealth]   Selection reason: {selection_reason}", flush=True)
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
        with self._lock:
            metrics = self._get_metric_values()
            reconciled_values = {}
            with self.connection:
                metric_counts = {
                    "traffic_records_written": self._count_traffic_packets_locked(),
                    "dns_queries_written": self._count_table("dns_queries"),
                    "unique_domains_discovered": self._count_table("domains"),
                    "alerts_written": self._count_table("alerts"),
                    "hosts_added": self._count_table("hosts"),
                }
                for metric_name, current_count in metric_counts.items():
                    current_metric = metrics.get(metric_name, 0)
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

    def _count_traffic_packets_locked(self):
        row = self.connection.execute(
            f"SELECT COALESCE(SUM({self._traffic_packet_count_sql()}), 0) FROM traffic"
        ).fetchone()
        return int(row[0] or 0)

    def _count_traffic_bytes_locked(self):
        row = self.connection.execute(
            f"SELECT COALESCE(SUM({self._traffic_byte_count_sql()}), 0) FROM traffic"
        ).fetchone()
        return int(row[0] or 0)

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

    def _append_new_domains(self, domains):
        unique_domains = list(dict.fromkeys(domains))
        if not unique_domains:
            return
        log_path = self.runtime_data_dir / "domains.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as log_file:
            for domain in unique_domains:
                log_file.write(f"{domain}\n")

    @staticmethod
    def _pop_pending_items_locked(mapping, limit):
        if not mapping:
            return {}
        if limit is None or limit <= 0 or len(mapping) <= limit:
            items = dict(mapping)
            mapping.clear()
            return items
        keys = list(islice(mapping.keys(), limit))
        items = {key: mapping.pop(key) for key in keys}
        return items

    def get_async_writer_benchmark_stats(self):
        with self._state_lock:
            flush_count = self._writer_transaction_lifetime_count
            traffic_flush_count = self._writer_traffic_exec_lifetime_count
            return {
                "flush_count": flush_count,
                "lock_hold_total_ms": round(self._writer_lock_hold_lifetime_total_ms, 3),
                "lock_hold_max_ms": round(self._writer_lock_hold_lifetime_max_ms, 3),
                "lock_hold_avg_ms": round(
                    self._writer_lock_hold_lifetime_total_ms / flush_count, 3
                )
                if flush_count
                else 0.0,
                "queue_high_watermark": self._writer_queue_high_watermark,
                "final_queue_depth": self._write_queue.qsize(),
                "dropped_rows_total": self._writer_overflow_drop_lifetime_total,
                "domain_log_total_ms": round(self._writer_domain_log_lifetime_total_ms, 3),
                "traffic_packet_events_total": self._writer_flushed_traffic_lifetime_total,
                "traffic_rows_total": self._writer_inserted_traffic_row_lifetime_total,
                "traffic_bytes_total": self._writer_flushed_traffic_bytes_lifetime_total,
                "dns_rows_total": self._writer_flushed_dns_lifetime_total,
                "domain_updates_total": self._writer_flushed_domain_lifetime_total,
                "traffic_exec_total_ms": round(self._writer_traffic_exec_lifetime_total_ms, 3),
                "traffic_exec_max_ms": round(self._writer_traffic_exec_lifetime_max_ms, 3),
                "traffic_exec_avg_ms": round(
                    self._writer_traffic_exec_lifetime_total_ms / traffic_flush_count,
                    3,
                )
                if traffic_flush_count
                else 0.0,
                "retention_total_ms": round(self._retention_lifetime_total_ms, 3),
                "retention_max_ms": round(self._retention_lifetime_max_ms, 3),
                "fallback_sync_writes": self._writer_fallback_sync_lifetime_total,
            }

    def close(self):
        if self._writer_thread is not None and self._writer_thread.is_alive():
            self._writer_stop_event.set()
            self._writer_flush_event.set()
            self._writer_thread.join(timeout=5)
        if self._maintenance_thread is not None and self._maintenance_thread.is_alive():
            self._maintenance_stop_event.set()
            self._maintenance_wake_event.set()
            self._maintenance_thread.join(timeout=5)
        self._flush_pending_writes(
            traffic_rows=[],
            dns_rows=[],
            flush_domains=True,
            flush_hosts=True,
            flush_metrics=True,
        )
        self._run_deferred_retention_if_idle(force=True)
        with self._lock:
            self.connection.close()
