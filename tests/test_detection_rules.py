from datetime import datetime, timedelta, timezone
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.database import Database
from excalibur.detection.dns_flood import DNSFloodDetector
from excalibur.detection.host_sweep import HostSweepDetector
from excalibur.detection.manager import DetectorManager
from excalibur.detection.portscan import PortScanDetector
from excalibur.detection.rules_config import RulesConfig
from excalibur.detection.unique_domains import UniqueDomainDetector


class DetectionRulesTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.database = Database(Path(self.temp_dir.name) / "rules.sqlite")
        self.base_time = datetime(2026, 6, 9, 10, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_dns_flood_triggers_alert(self):
        detector = DNSFloodDetector(self.database, self._rule("dns_flood", threshold=3))

        for index in range(3):
            detector.process_dns_query(self._dns_info(index))

        alerts = self.database.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "Possible DNS Flood")
        self.assertIn("made 3 DNS queries", alerts[0]["description"])
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.10")
        self.assertEqual(alerts[0]["destination_ip"], "10.0.0.1")
        context = json.loads(alerts[0]["context_json"])
        self.assertEqual(context["rule"]["name"], "DNS Flood")
        self.assertEqual(context["rule"]["pack"], "builtin")
        self.assertEqual(context["rule"]["thresholds"]["dns_queries"], 3)
        self.assertEqual(context["evidence"]["observed"]["dns_queries"], 3)
        self.assertEqual(context["evidence"]["window_seconds"], 60)

    def test_dns_flood_below_threshold_does_not_alert(self):
        detector = DNSFloodDetector(self.database, self._rule("dns_flood", threshold=3))

        for index in range(2):
            detector.process_dns_query(self._dns_info(index))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_unique_domain_threshold_triggers_alert(self):
        detector = UniqueDomainDetector(
            self.database,
            self._rule("unique_domains", threshold=3),
        )

        for index in range(3):
            detector.process_dns_query(self._dns_info(index, query_name=f"d{index}.example"))

        alerts = self.database.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "Excessive Unique DNS Queries")
        self.assertIn("queried 3 unique domains", alerts[0]["description"])
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.10")
        self.assertEqual(alerts[0]["destination_ip"], "10.0.0.1")
        context = json.loads(alerts[0]["context_json"])
        self.assertEqual(context["rule"]["name"], "Excessive Unique Domains")
        self.assertEqual(context["rule"]["pack"], "builtin")
        self.assertEqual(context["rule"]["thresholds"]["unique_domains"], 3)
        self.assertEqual(context["evidence"]["observed"]["unique_domains"], 3)
        self.assertEqual(context["evidence"]["window_seconds"], 60)

    def test_repeated_same_domain_does_not_count_as_unique(self):
        detector = UniqueDomainDetector(
            self.database,
            self._rule("unique_domains", threshold=3),
        )

        for index in range(5):
            detector.process_dns_query(self._dns_info(index, query_name="same.example"))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_host_sweep_triggers_alert(self):
        detector = HostSweepDetector(self.database, self._rule("host_sweep", threshold=3))

        for index in range(3):
            detector.process_packet(self._packet_info(index, dst_ip=f"10.0.0.{index + 1}"))

        alerts = self.database.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "Possible Host Sweep")
        self.assertIn("contacted 3 unique hosts on port 445", alerts[0]["description"])
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.10")
        self.assertEqual(alerts[0]["destination_ip"], "10.0.0.3")
        context = json.loads(alerts[0]["context_json"])
        self.assertEqual(context["rule"]["name"], "Host Sweep")
        self.assertEqual(context["rule"]["pack"], "builtin")
        self.assertEqual(context["rule"]["thresholds"]["unique_dst_ips"], 3)
        self.assertEqual(context["evidence"]["observed"]["unique_dst_ips"], 3)
        self.assertEqual(context["evidence"]["observed"]["dst_port"], 445)
        self.assertEqual(context["evidence"]["window_seconds"], 60)

    def test_host_sweep_below_threshold_does_not_alert(self):
        detector = HostSweepDetector(self.database, self._rule("host_sweep", threshold=3))

        for index in range(2):
            detector.process_packet(self._packet_info(index, dst_ip=f"10.0.0.{index + 1}"))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_disabled_rule_does_not_run(self):
        manager = DetectorManager(
            self.database,
            rules={"rules": [self._rule("dns_flood", threshold=1, enabled=False)]},
        )

        manager.process_dns_query(self._dns_info(0))

        self.assertEqual(manager.detectors, [])
        self.assertEqual(self.database.count_alerts(), 0)

    def test_startup_inventory_lists_builtin_detectors(self):
        output = StringIO()

        with redirect_stdout(output):
            DetectorManager(
                self.database,
                rules={
                    "global": {"exclude_own_ips": False},
                    "rules": [
                        self._rule("portscan", threshold=1),
                        self._rule("host_sweep", threshold=1),
                    ],
                },
                signature_rules_dir=Path(self.temp_dir.name) / "rules",
            )

        text = output.getvalue()
        self.assertIn("Built-in Detectors:", text)
        self.assertIn("* PortScanDetector", text)
        self.assertIn("* HostSweepDetector", text)

    def test_custom_threshold_from_rules_is_respected(self):
        manager = DetectorManager(
            self.database,
            rules={"rules": [self._rule("dns_flood", threshold=2)]},
        )

        manager.process_dns_query(self._dns_info(0))
        self.assertEqual(self.database.count_alerts(), 0)
        manager.process_dns_query(self._dns_info(1))
        self.assertEqual(self.database.count_alerts(), 1)

    def test_cooldown_prevents_duplicate_alerts(self):
        detector = DNSFloodDetector(
            self.database,
            self._rule("dns_flood", threshold=2, cooldown_seconds=300),
        )

        detector.process_dns_query(self._dns_info(0))
        detector.process_dns_query(self._dns_info(1))
        detector.process_dns_query(
            self._dns_info(2, timestamp=self.base_time + timedelta(seconds=30))
        )
        detector.process_dns_query(
            self._dns_info(3, timestamp=self.base_time + timedelta(seconds=31))
        )

        self.assertEqual(self.database.count_alerts(), 1)

    def test_rules_yaml_missing_creates_default_rules(self):
        rules_path = Path(self.temp_dir.name) / "rules.yaml"

        rules = RulesConfig.load(rules_path)

        self.assertTrue(rules_path.exists())
        self.assertEqual(len(rules["rules"]), 4)
        self.assertEqual(rules["rules"][0]["type"], "portscan")

    def test_own_ip_does_not_trigger_port_scan_alert(self):
        manager = DetectorManager(
            self.database,
            rules={"global": {"exclude_own_ips": True}, "rules": [self._rule("portscan", threshold=3)]},
            config={"monitored_networks": ["10.0.0.0/8"]},
            own_ips=["10.0.0.10"],
        )

        for port in range(1, 4):
            manager.process(self._portscan_packet(port, src_ip="10.0.0.10", dst_ip="10.0.0.1"))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_own_ip_does_not_trigger_host_sweep_alert(self):
        manager = DetectorManager(
            self.database,
            rules={"global": {"exclude_own_ips": True}, "rules": [self._rule("host_sweep", threshold=3)]},
            config={"monitored_networks": ["10.0.0.0/8"]},
            own_ips=["10.0.0.10"],
        )

        for index in range(3):
            manager.process(self._packet_info(index, dst_ip=f"10.0.0.{index + 1}"))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_non_own_monitored_ip_still_triggers_port_scan(self):
        manager = DetectorManager(
            self.database,
            rules={"global": {"exclude_own_ips": True}, "rules": [self._rule("portscan", threshold=3)]},
            config={"monitored_networks": ["10.0.0.0/8"]},
            own_ips=["10.0.0.99"],
        )

        for port in range(1, 4):
            manager.process(self._portscan_packet(port, src_ip="10.0.0.10", dst_ip="10.0.0.1"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_non_own_monitored_ip_still_triggers_host_sweep(self):
        manager = DetectorManager(
            self.database,
            rules={"global": {"exclude_own_ips": True}, "rules": [self._rule("host_sweep", threshold=3)]},
            config={"monitored_networks": ["10.0.0.0/8"]},
            own_ips=["10.0.0.99"],
        )

        for index in range(3):
            manager.process(self._packet_info(index, dst_ip=f"10.0.0.{index + 1}"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_excluded_source_never_triggers_any_detector(self):
        manager = DetectorManager(
            self.database,
            rules={
                "global": {"excluded_sources": ["10.0.0.10"], "exclude_own_ips": False},
                "rules": [
                    self._rule("portscan", threshold=2),
                    self._rule("host_sweep", threshold=2),
                    self._rule("dns_flood", threshold=2),
                    self._rule("unique_domains", threshold=2),
                ],
            },
            config={"monitored_networks": ["10.0.0.0/8"]},
        )

        for index in range(3):
            manager.process(self._portscan_packet(index + 1, src_ip="10.0.0.10", dst_ip="10.0.0.1"))
            manager.process(self._packet_info(index, dst_ip=f"10.0.0.{index + 1}"))
            manager.process_dns_query(self._dns_info(index, query_name=f"d{index}.example"))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_non_excluded_source_still_triggers_detectors(self):
        manager = DetectorManager(
            self.database,
            rules={
                "global": {"excluded_sources": ["10.0.0.99"], "exclude_own_ips": False},
                "rules": [
                    self._rule("portscan", threshold=2),
                    self._rule("host_sweep", threshold=2),
                    self._rule("dns_flood", threshold=2),
                    self._rule("unique_domains", threshold=2),
                ],
            },
            config={"monitored_networks": ["10.0.0.0/8"]},
        )

        for index in range(2):
            manager.process(self._portscan_packet(index + 1, src_ip="10.0.0.10", dst_ip="10.0.0.1"))
            manager.process(self._packet_info(index, dst_ip=f"10.0.1.{index + 1}"))
            manager.process_dns_query(self._dns_info(index, query_name=f"d{index}.example"))

        self.assertEqual(self.database.count_alerts(), 4)

    def test_private_to_public_host_sweep_does_not_trigger(self):
        detector = HostSweepDetector(
            self.database,
            self._rule("host_sweep", threshold=3),
            monitored_networks=["10.0.0.0/8"],
        )

        for index in range(3):
            detector.process_packet(self._packet_info(index, dst_ip=f"93.184.216.{index + 1}", dst_port=443))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_port_443_public_cdn_traffic_does_not_trigger_host_sweep(self):
        detector = HostSweepDetector(
            self.database,
            self._rule("host_sweep", threshold=3),
            monitored_networks=["10.0.0.0/8"],
        )

        for index in range(10):
            detector.process_packet(self._packet_info(index, dst_ip=f"34.100.0.{index + 1}", dst_port=443))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_port_scan_tracks_source_destination_pair(self):
        detector = PortScanDetector(
            self.database,
            config={"monitored_networks": ["10.0.0.0/8"]},
            rule=self._rule("portscan", threshold=3),
        )

        for index, destination in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3"]):
            detector.process_packet(
                self._portscan_packet(80 + index, src_ip="10.0.0.10", dst_ip=destination)
            )
        self.assertEqual(self.database.count_alerts(), 0)

        for port in range(1, 4):
            detector.process_packet(self._portscan_packet(port, src_ip="10.0.0.10", dst_ip="10.0.0.50"))
        self.assertEqual(self.database.count_alerts(), 1)
        self.assertIn("destination IP 10.0.0.50", self.database.get_alerts()[0]["description"])

    def _rule(
        self,
        rule_type,
        threshold,
        enabled=True,
        window_seconds=60,
        cooldown_seconds=300,
    ):
        return {
            "name": rule_type,
            "type": rule_type,
            "enabled": enabled,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "cooldown_seconds": cooldown_seconds,
            "severity": "Medium",
        }

    def _dns_info(self, index, query_name=None, timestamp=None):
        timestamp = timestamp or self.base_time + timedelta(seconds=index)
        return {
            "timestamp": timestamp.isoformat(),
            "client_ip": "10.0.0.10",
            "dns_server_ip": "10.0.0.1",
            "query_name": query_name or f"example{index}.com",
            "query_type": "A",
        }

    def _packet_info(self, index, dst_ip, dst_port=445):
        return {
            "timestamp": (self.base_time + timedelta(seconds=index)).isoformat(),
            "src_ip": "10.0.0.10",
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "src_port": 50000 + index,
            "dst_port": dst_port,
            "packet_size": 60,
        }

    def _portscan_packet(self, dst_port, src_ip, dst_ip):
        return {
            "timestamp": self.base_time.isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": dst_port,
            "packet_size": 60,
            "tcp_flags": "S",
        }


if __name__ == "__main__":
    unittest.main()
