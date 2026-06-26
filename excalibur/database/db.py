import json
import os
import sqlite3
import time
from pathlib import Path
from threading import RLock

from excalibur.config import Config
from excalibur.detection.domain_risk import DomainRiskAnalyzer
from excalibur.events import AlertEvent
from excalibur.service_lookup import service_case_sql


class Database:
    TRAFFIC_RETENTION_CHECK_INTERVAL = 1000

    def __init__(self, db_path="excalibur.sqlite", config=None):
        self.db_path = Path(db_path)
        self.runtime_data_dir = Path(os.environ.get("EXCALIBUR_DATA_DIR", "data"))
        self.config = config or Config.load()
        self.domain_risk_analyzer = DomainRiskAnalyzer(self.config)
        self._lock = RLock()
        self._traffic_insert_counter = 0
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
                self.connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
                    ON alerts (source_ip)
                    """
                )
                self._ensure_column("alerts", "source_ip", "TEXT")
                self._ensure_column("alerts", "destination_ip", "TEXT")
                self._ensure_column("alerts", "context_json", "TEXT")
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

    def upsert_domain(self, domain, timestamp, client_ip=None, dns_server_ip=None):
        normalized_domain = self._normalize_domain(domain)
        risk_result = self.analyze_domain_risk(normalized_domain)
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
                        "risk_score": self.domain_risk_analyzer.alert_threshold,
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
                        "risk_score": self.domain_risk_analyzer.alert_threshold,
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
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                "SELECT COUNT(*) FROM dns_queries"
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def get_domain_count(self):
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute("SELECT COUNT(*) FROM domains").fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def get_risky_domain_count(self):
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                "SELECT COUNT(*) FROM domain_risk WHERE risk_level != 'None'"
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def count_hosts(self):
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute("SELECT COUNT(*) FROM hosts").fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def count_traffic(self):
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute("SELECT COUNT(*) FROM traffic").fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def get_traffic_count(self):
        return self.count_traffic()

    def count_alerts(self):
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute("SELECT COUNT(*) FROM alerts").fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return row[0]

    def count_alerts_between(self, start_timestamp, end_timestamp):
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
        with self._lock:
            started_at = time.perf_counter()
            row = self.connection.execute(
                "SELECT COALESCE(SUM(hits), 0) FROM rule_stats"
            ).fetchone()
            self._record_read_metrics("dashboard_queries_executed", [row], started_at)
            return int(row[0] or 0)

    def get_top_rule_stats(self, limit=10):
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
        with self._lock:
            return self.connection.execute(
                """
                SELECT src_ip, unique_port_count, in_cooldown, last_alert_time
                FROM portscan_debug
                ORDER BY unique_port_count DESC, src_ip ASC
                """
            ).fetchall()

    def get_system_health(self):
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
                "writes": {
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
                },
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
        with self._lock:
            return self.connection.execute(
                """
                SELECT rule_name, hits, alerts_generated, last_triggered
                FROM rule_stats
                ORDER BY rule_name ASC
                """
            ).fetchall()

    def reconcile_system_metrics(self):
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
        self._increment_metric(metric_name, 1)
        self._increment_metric("total_writes", 1)
        self._increment_metric("sqlite_bytes_written", estimated_bytes)
        self._increment_metric("write_latency_total", elapsed)
        self._increment_metric("write_latency_count", 1)
        self._ensure_metric_start_time()

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
        self._increment_metric("domains_log_bytes_written", len(f"{domain}\n".encode("utf-8")))

    def close(self):
        with self._lock:
            self.connection.close()
