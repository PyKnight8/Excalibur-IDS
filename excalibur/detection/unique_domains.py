from collections import defaultdict

from excalibur.detection.base import RuleDetector


class UniqueDomainDetector(RuleDetector):
    def __init__(self, database, rule=None, global_config=None, own_ips=None):
        super().__init__(database, rule, global_config=global_config, own_ips=own_ips)
        self._domains_by_source = defaultdict(self._new_window)

    def process_dns_query(self, dns_info):
        if not self.enabled:
            return

        client_ip = dns_info.get("client_ip")
        query_name = dns_info.get("query_name")
        if not client_ip or not query_name:
            return
        if self._is_globally_excluded(client_ip):
            return

        timestamp = self._parse_timestamp(dns_info.get("timestamp"))
        domain = str(query_name).strip().rstrip(".").lower()
        domains = self._domains_by_source[client_ip]
        domains.append((timestamp, domain))
        self._prune(domains, timestamp)

        unique_count = len({domain_name for _, domain_name in domains})
        if unique_count < self.threshold or self._is_in_cooldown(client_ip, timestamp):
            return

        self.database.create_alert(
            timestamp=timestamp.isoformat(),
            severity=self.severity,
            title="Excessive Unique DNS Queries",
            description=(
                f"Source IP {client_ip} queried {unique_count} unique domains "
                f"within {self.window_seconds} seconds."
            ),
            source_ip=client_ip,
            destination_ip=dns_info.get("dns_server_ip"),
            context={
                "rule": {
                    "name": "Excessive Unique Domains",
                    "pack": "builtin",
                    "tags": ["dns", "domains"],
                    "event_type": "dns",
                    "thresholds": {
                        "unique_domains": self.threshold,
                    },
                    "window_seconds": self.window_seconds,
                },
                "evidence": {
                    "observed": {
                        "unique_domains": unique_count,
                    },
                    "thresholds": {
                        "unique_domains": self.threshold,
                    },
                    "window_seconds": self.window_seconds,
                },
            },
        )
        self._mark_alerted(client_ip, timestamp)
