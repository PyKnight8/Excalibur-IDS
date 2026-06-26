from collections import defaultdict
from ipaddress import ip_address, ip_network

from excalibur.detection.base import RuleDetector


class HostSweepDetector(RuleDetector):
    def __init__(
        self,
        database,
        rule=None,
        global_config=None,
        own_ips=None,
        monitored_networks=None,
    ):
        super().__init__(database, rule, global_config=global_config, own_ips=own_ips)
        self._hosts_by_source_port = defaultdict(self._new_window)
        monitored_networks = monitored_networks or [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
        self.monitored_networks = [
            ip_network(network) for network in monitored_networks
        ]

    def process_packet(self, packet_info):
        if not self.enabled:
            return

        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")
        if not src_ip or not dst_ip or dst_port is None:
            return
        if self._is_globally_excluded(src_ip) or self._is_own_ip(src_ip):
            return
        if not self._is_monitored_destination(dst_ip):
            return

        timestamp = self._parse_timestamp(packet_info.get("timestamp"))
        key = (src_ip, dst_port)
        hosts = self._hosts_by_source_port[key]
        hosts.append((timestamp, dst_ip))
        self._prune(hosts, timestamp)

        unique_count = len({host for _, host in hosts})
        if unique_count < self.threshold or self._is_in_cooldown(key, timestamp):
            return

        self.database.create_alert(
            timestamp=timestamp.isoformat(),
            severity=self.severity,
            title="Possible Host Sweep",
            description=(
                f"Source IP {src_ip} contacted {unique_count} unique hosts on "
                f"port {dst_port} within {self.window_seconds} seconds."
            ),
            source_ip=src_ip,
            destination_ip=dst_ip,
            context={
                "rule": {
                    "name": "Host Sweep",
                    "pack": "builtin",
                    "tags": ["recon", "host_sweep"],
                    "event_type": "packet",
                    "thresholds": {
                        "unique_dst_ips": self.threshold,
                    },
                    "window_seconds": self.window_seconds,
                },
                "evidence": {
                    "observed": {
                        "dst_port": dst_port,
                        "unique_dst_ips": unique_count,
                    },
                    "thresholds": {
                        "unique_dst_ips": self.threshold,
                    },
                    "window_seconds": self.window_seconds,
                },
            },
        )
        self._mark_alerted(key, timestamp)

    def _is_monitored_destination(self, dst_ip):
        if not self.monitored_networks:
            return True
        try:
            destination = ip_address(dst_ip)
        except ValueError:
            return False
        return any(destination in network for network in self.monitored_networks)
