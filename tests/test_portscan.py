from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.database import Database
from excalibur.detection.portscan import PortScanDetector


class PortScanDetectorTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.database = Database(Path(self.temp_dir.name) / "test.sqlite")
        self.detector = PortScanDetector(self.database)
        self.base_time = datetime(2026, 6, 8, 10, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_no_alert_below_threshold(self):
        for port in range(1, 20):
            self.detector.process_packet(self._packet_info(port))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_alert_at_threshold(self):
        for port in range(1, 21):
            self.detector.process_packet(self._packet_info(port))

        alerts = self.database.get_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "Medium")
        self.assertEqual(alerts[0]["title"], "Possible Port Scan")
        self.assertIn("20 unique destination ports", alerts[0]["description"])
        self.assertEqual(alerts[0]["source_ip"], "10.0.0.10")
        self.assertEqual(alerts[0]["destination_ip"], "10.0.0.1")
        context = json.loads(alerts[0]["context_json"])
        self.assertEqual(context["rule"]["name"], "Port Scan")
        self.assertEqual(context["rule"]["pack"], "builtin")
        self.assertEqual(context["rule"]["thresholds"]["unique_dst_ports"], 20)
        self.assertEqual(context["evidence"]["observed"]["unique_dst_ports"], 20)
        self.assertEqual(context["evidence"]["window_seconds"], 60)

    def test_non_syn_packets_do_not_count(self):
        detector = PortScanDetector(
            self.database,
            config={
                "portscan": {
                    "enabled": True,
                    "threshold": 3,
                    "window_seconds": 60,
                    "cooldown_seconds": 300,
                },
                "monitored_networks": ["10.0.0.0/8"],
            },
        )

        for port in range(1, 4):
            detector.process_packet(self._packet_info(port, tcp_flags="A"))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_high_destination_ports_do_not_count(self):
        detector = PortScanDetector(
            self.database,
            config={
                "portscan": {
                    "enabled": True,
                    "threshold": 3,
                    "window_seconds": 60,
                    "cooldown_seconds": 300,
                },
                "monitored_networks": ["10.0.0.0/8"],
            },
        )

        for port in range(17404, 17407):
            detector.process_packet(self._packet_info(port))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_no_duplicate_alert_within_cooldown(self):
        for port in range(1, 21):
            self.detector.process_packet(self._packet_info(port))

        for port in range(21, 41):
            self.detector.process_packet(
                self._packet_info(port, timestamp=self.base_time + timedelta(seconds=30))
            )

        self.assertEqual(self.database.count_alerts(), 1)

    def test_private_ip_inside_monitored_network_triggers_detection(self):
        detector = PortScanDetector(
            self.database,
            config={
                "portscan": {
                    "enabled": True,
                    "threshold": 3,
                    "window_seconds": 60,
                    "cooldown_seconds": 300,
                },
                "monitored_networks": ["10.0.0.0/8"],
            },
        )

        for port in range(1, 4):
            detector.process_packet(self._packet_info(port, src_ip="10.1.2.3"))

        self.assertEqual(self.database.count_alerts(), 1)

    def test_public_ip_outside_monitored_network_is_ignored(self):
        detector = PortScanDetector(
            self.database,
            config={
                "portscan": {
                    "enabled": True,
                    "threshold": 3,
                    "window_seconds": 60,
                    "cooldown_seconds": 300,
                },
                "monitored_networks": ["10.0.0.0/8"],
            },
        )

        for port in range(1, 10):
            detector.process_packet(self._packet_info(port, src_ip="8.8.8.8"))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_custom_threshold_is_respected(self):
        detector = PortScanDetector(
            self.database,
            config={
                "portscan": {
                    "enabled": True,
                    "threshold": 5,
                    "window_seconds": 60,
                    "cooldown_seconds": 300,
                },
                "monitored_networks": ["10.0.0.0/8"],
            },
        )

        for port in range(1, 5):
            detector.process_packet(self._packet_info(port))
        self.assertEqual(self.database.count_alerts(), 0)

        detector.process_packet(self._packet_info(5))
        self.assertEqual(self.database.count_alerts(), 1)

    def test_excluded_source_never_triggers_alert(self):
        detector = PortScanDetector(
            self.database,
            config={
                "portscan": {
                    "enabled": True,
                    "threshold": 3,
                    "window_seconds": 60,
                    "cooldown_seconds": 300,
                    "excluded_sources": ["10.0.0.10"],
                },
                "monitored_networks": ["10.0.0.0/8"],
            },
        )

        for port in range(1, 10):
            detector.process_packet(self._packet_info(port, src_ip="10.0.0.10"))

        self.assertEqual(self.database.count_alerts(), 0)

    def test_non_excluded_monitored_source_still_triggers_alert(self):
        detector = PortScanDetector(
            self.database,
            config={
                "portscan": {
                    "enabled": True,
                    "threshold": 3,
                    "window_seconds": 60,
                    "cooldown_seconds": 300,
                    "excluded_sources": ["10.0.0.11"],
                },
                "monitored_networks": ["10.0.0.0/8"],
            },
        )

        for port in range(1, 4):
            detector.process_packet(self._packet_info(port, src_ip="10.0.0.10"))

        self.assertEqual(self.database.count_alerts(), 1)

    def _packet_info(self, dst_port, timestamp=None, src_ip="10.0.0.10", tcp_flags="S"):
        timestamp = timestamp or self.base_time
        return {
            "timestamp": timestamp.isoformat(),
            "src_ip": src_ip,
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "src_port": 12345,
            "dst_port": dst_port,
            "packet_size": 60,
            "tcp_flags": tcp_flags,
        }


if __name__ == "__main__":
    unittest.main()
