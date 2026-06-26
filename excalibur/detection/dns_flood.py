from collections import defaultdict

from excalibur.detection.base import RuleDetector


class DNSFloodDetector(RuleDetector):
    def __init__(self, database, rule=None, global_config=None, own_ips=None):
        super().__init__(database, rule, global_config=global_config, own_ips=own_ips)
        self._queries_by_source = defaultdict(self._new_window)

    def process_dns_query(self, dns_info):
        if not self.enabled:
            return

        client_ip = dns_info.get("client_ip")
        if not client_ip:
            return
        if self._is_globally_excluded(client_ip):
            return

        timestamp = self._parse_timestamp(dns_info.get("timestamp"))
        queries = self._queries_by_source[client_ip]
        queries.append((timestamp, None))
        self._prune(queries, timestamp)

        count = len(queries)
        if count < self.threshold or self._is_in_cooldown(client_ip, timestamp):
            return

        self.database.create_alert(
            timestamp=timestamp.isoformat(),
            severity=self.severity,
            title="Possible DNS Flood",
            description=(
                f"Source IP {client_ip} made {count} DNS queries within "
                f"{self.window_seconds} seconds."
            ),
            source_ip=client_ip,
            destination_ip=dns_info.get("dns_server_ip"),
            context={
                "rule": {
                    "name": "DNS Flood",
                    "pack": "builtin",
                    "tags": ["dns", "volume"],
                    "event_type": "dns",
                    "thresholds": {
                        "dns_queries": self.threshold,
                    },
                    "window_seconds": self.window_seconds,
                },
                "evidence": {
                    "observed": {
                        "dns_queries": count,
                    },
                    "thresholds": {
                        "dns_queries": self.threshold,
                    },
                    "window_seconds": self.window_seconds,
                },
            },
        )
        self._mark_alerted(client_ip, timestamp)
