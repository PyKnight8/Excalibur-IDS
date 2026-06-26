from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network


class PortScanDetector:
    def __init__(
        self,
        database,
        window_seconds=60,
        threshold=20,
        cooldown_seconds=300,
        config=None,
        rule=None,
        global_config=None,
        own_ips=None,
    ):
        config = config or {}
        rule = rule or {}
        global_config = global_config or {}
        portscan_config = config.get("portscan", {})
        monitored_networks = config.get(
            "monitored_networks",
            portscan_config.get(
                "monitored_networks",
                ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            ),
        )

        self.database = database
        self.global_config = global_config
        self.own_ips = {str(ip).strip() for ip in (own_ips or [])}
        self.name = rule.get("name", "Port Scan")
        self.enabled = bool(rule.get("enabled", portscan_config.get("enabled", True)))
        self.window = timedelta(
            seconds=int(
                rule.get(
                    "window_seconds",
                    portscan_config.get("window_seconds", window_seconds),
                )
            )
        )
        self.threshold = int(rule.get("threshold", portscan_config.get("threshold", threshold)))
        self.cooldown = timedelta(
            seconds=int(
                rule.get(
                    "cooldown_seconds",
                    portscan_config.get("cooldown_seconds", cooldown_seconds),
                )
            )
        )
        self.severity = rule.get("severity", "Medium")
        self.window_seconds = int(self.window.total_seconds())
        self.max_dst_port = int(
            rule.get(
                "max_dst_port",
                portscan_config.get("max_dst_port", 10000),
            )
        )
        self.excluded_sources = {
            str(source).strip() for source in portscan_config.get("excluded_sources", [])
        }
        self.excluded_sources.update(
            str(source).strip() for source in global_config.get("excluded_sources", [])
        )
        self.monitored_networks = [
            ip_network(network) for network in monitored_networks
        ]
        self._ports_by_source_target = defaultdict(deque)
        self._last_alert_by_source = {}

    def process_packet(self, packet_info):
        if not self.enabled:
            return

        src_ip = packet_info.get("src_ip")
        dst_port = packet_info.get("dst_port")
        dst_ip = packet_info.get("dst_ip")
        if not src_ip or not dst_ip or dst_port is None:
            return
        if packet_info.get("protocol") != "TCP":
            return
        if packet_info.get("tcp_flags") != "S":
            return
        try:
            dst_port = int(dst_port)
        except (TypeError, ValueError):
            return
        if dst_port > self.max_dst_port:
            return
        if self._is_excluded_source(src_ip):
            return
        if self._is_own_ip(src_ip):
            return
        if not self._is_monitored_source(src_ip):
            return

        timestamp = self._parse_timestamp(packet_info.get("timestamp"))
        key = (src_ip, dst_ip)
        source_ports = self._ports_by_source_target[key]
        source_ports.append((timestamp, dst_port))
        self._prune_old_ports(source_ports, timestamp)

        unique_port_count = len({port for _, port in source_ports})
        in_cooldown = self._is_in_cooldown(key, timestamp)
        self._record_debug_state(src_ip, unique_port_count, in_cooldown)

        if unique_port_count < self.threshold:
            return

        if in_cooldown:
            return

        self.database.create_alert(
            timestamp=timestamp.isoformat(),
            severity=self.severity,
            title="Possible Port Scan",
            description=(
                f"Source IP {src_ip} contacted destination IP {dst_ip} on "
                f"{unique_port_count} unique destination ports within "
                f"{self.window_seconds} seconds."
            ),
            source_ip=src_ip,
            destination_ip=dst_ip,
            context={
                "rule": {
                    "name": "Port Scan",
                    "pack": "builtin",
                    "tags": ["recon", "portscan"],
                    "event_type": "packet",
                    "thresholds": {
                        "unique_dst_ports": self.threshold,
                    },
                    "window_seconds": self.window_seconds,
                },
                "evidence": {
                    "observed": {
                        "unique_dst_ports": unique_port_count,
                    },
                    "thresholds": {
                        "unique_dst_ports": self.threshold,
                    },
                    "window_seconds": self.window_seconds,
                },
            },
        )
        self._last_alert_by_source[key] = timestamp
        self._record_debug_state(src_ip, unique_port_count, True)

    def _prune_old_ports(self, source_ports, timestamp):
        cutoff = timestamp - self.window
        while source_ports and source_ports[0][0] < cutoff:
            source_ports.popleft()

    def _is_in_cooldown(self, src_ip, timestamp):
        last_alert = self._last_alert_by_source.get(src_ip)
        return last_alert is not None and timestamp - last_alert < self.cooldown

    def _parse_timestamp(self, timestamp):
        if isinstance(timestamp, datetime):
            parsed = timestamp
        elif timestamp:
            parsed = datetime.fromisoformat(str(timestamp))
        else:
            parsed = datetime.now(timezone.utc)

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _is_monitored_source(self, src_ip):
        try:
            source_address = ip_address(src_ip)
        except ValueError:
            return False
        return any(source_address in network for network in self.monitored_networks)

    def _is_excluded_source(self, src_ip):
        return str(src_ip).strip() in self.excluded_sources

    def _is_own_ip(self, src_ip):
        return str(src_ip).strip() in self.own_ips

    def _record_debug_state(self, src_ip, unique_port_count, in_cooldown):
        last_alert = self._last_alert_by_source.get(src_ip)
        last_alert_time = last_alert.isoformat() if last_alert else None
        if hasattr(self.database, "update_portscan_debug_state"):
            self.database.update_portscan_debug_state(
                src_ip=src_ip,
                unique_port_count=unique_port_count,
                in_cooldown=in_cooldown,
                last_alert_time=last_alert_time,
            )
