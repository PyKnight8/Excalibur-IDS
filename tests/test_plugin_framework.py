from pathlib import Path
from tempfile import TemporaryDirectory
import io
import unittest
from contextlib import redirect_stdout

from excalibur.database import Database
from excalibur.events import AlertEvent, PacketEvent
from excalibur.plugins import EventBus, PluginManager

try:
    from scapy.all import DNS, DNSQR, IP, UDP
except ImportError:  # pragma: no cover - depends on local test environment
    DNS = DNSQR = IP = UDP = None


class EventBusTest(unittest.TestCase):
    def test_emit_continues_after_handler_failure(self):
        event_bus = EventBus()
        received = []

        def failing_handler(event):
            raise RuntimeError("boom")

        def receiving_handler(event):
            received.append(event.event_type)

        event_bus.subscribe("packet_event", failing_handler)
        event_bus.subscribe("packet_event", receiving_handler)

        output = io.StringIO()
        with redirect_stdout(output):
            event_bus.emit(
                PacketEvent(
                    timestamp="2026-06-18T10:00:00+00:00",
                    src_ip="10.0.0.10",
                    dst_ip="10.0.0.1",
                    protocol="TCP",
                    src_port=12345,
                    dst_port=80,
                    packet_size=60,
                )
            )

        self.assertEqual(received, ["packet_event"])
        self.assertIn("failed for packet_event", output.getvalue())


class PluginManagerTest(unittest.TestCase):
    def test_loads_plugin_and_delivers_events(self):
        with TemporaryDirectory() as temp_dir:
            plugins_dir = Path(temp_dir) / "plugins"
            plugin_dir = plugins_dir / "collector"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.yaml").write_text(
                "\n".join(
                    [
                        "name: Collector",
                        "id: collector",
                        "version: 1.0.0",
                        "entrypoint: plugin.py",
                        "enabled: true",
                    ]
                ),
                encoding="utf-8",
            )
            (plugin_dir / "plugin.py").write_text(
                "\n".join(
                    [
                        "from excalibur.plugins.base import Plugin",
                        "",
                        "class Plugin(Plugin):",
                        "    name = 'Collector'",
                        "",
                        "    def __init__(self):",
                        "        self.received_events = []",
                        "",
                        "    def handle_event(self, event, context):",
                        "        self.received_events.append(event.event_type)",
                    ]
                ),
                encoding="utf-8",
            )

            event_bus = EventBus()
            manager = PluginManager(event_bus, plugins_dir)
            manager.load_plugins()

            event_bus.emit(
                PacketEvent(
                    timestamp="2026-06-18T10:00:00+00:00",
                    src_ip="10.0.0.10",
                    dst_ip="10.0.0.1",
                    protocol="TCP",
                    src_port=12345,
                    dst_port=80,
                    packet_size=60,
                )
            )

            self.assertEqual(len(manager.plugins), 1)
            self.assertEqual(
                manager.plugins[0].instance.received_events,
                ["packet_event"],
            )

    def test_test_plugin_logs_received_alert_events(self):
        event_bus = EventBus()
        manager = PluginManager(event_bus, Path("plugins"))
        output = io.StringIO()

        with redirect_stdout(output):
            manager.load_plugins()
            event_bus.emit(
                AlertEvent(
                    timestamp="2026-06-18T10:00:00+00:00",
                    alert_id=42,
                    title="SMB Recon Activity",
                    severity="High",
                    description="Source contacted many hosts via SMB.",
                    source_ip="10.0.2.10",
                )
            )

        log_output = output.getvalue()
        self.assertIn("Loaded plugin 'Alert Logger'", log_output)
        self.assertIn("Alert Logger received alert_event for alert #42", log_output)

    def test_skips_invalid_plugin_metadata(self):
        with TemporaryDirectory() as temp_dir:
            plugins_dir = Path(temp_dir) / "plugins"
            plugin_dir = plugins_dir / "broken"
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "plugin.yaml").write_text(
                "\n".join(
                    [
                        "name: Broken",
                        "id: broken",
                        "entrypoint: plugin.py",
                    ]
                ),
                encoding="utf-8",
            )

            manager = PluginManager(EventBus(), plugins_dir)
            manager.load_plugins()

            self.assertEqual(manager.plugins, [])


class PacketSnifferPluginIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.database = Database(Path(self.temp_dir.name) / "test.sqlite")

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_sniffer_emits_packet_and_dns_events(self):
        if IP is None:
            self.skipTest("scapy is not installed")

        from excalibur.sensor.sniffer import PacketSniffer

        event_bus = EventBus()
        received_event_types = []
        event_bus.subscribe("*", lambda event: received_event_types.append(event.event_type))

        sniffer = PacketSniffer(
            database=self.database,
            packet_log_interval=None,
            event_bus=event_bus,
        )
        sniffer.detector_manager = _CollectingDetectorManager()
        packet = (
            IP(src="10.0.0.10", dst="10.0.0.1")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="Example.COM.", qtype="A"))
        )

        sniffer._handle_packet(packet)

        self.assertIn("packet_event", received_event_types)
        self.assertIn("dns_event", received_event_types)


class AlertEventIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.database = Database(Path(self.temp_dir.name) / "test.sqlite")

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_create_alert_emits_alert_event_after_successful_insert(self):
        event_bus = EventBus()
        received_alerts = []
        event_bus.subscribe("alert_event", lambda event: received_alerts.append(event))
        self.database.set_event_bus(event_bus)

        alert_id = self.database.create_alert(
            "2026-06-18T10:00:00+00:00",
            "High",
            "SMB Recon Activity",
            "Source contacted many hosts via SMB.",
            source_ip="10.0.2.10",
            destination_ip="10.0.2.1",
            context={"rule": {"name": "SMB Recon"}},
        )

        self.assertEqual(self.database.count_alerts(), 1)
        self.assertEqual(len(received_alerts), 1)
        self.assertEqual(received_alerts[0].alert_id, alert_id)
        self.assertEqual(received_alerts[0].event_type, "alert_event")
        self.assertEqual(received_alerts[0].title, "SMB Recon Activity")
        self.assertEqual(received_alerts[0].source_ip, "10.0.2.10")


class _CollectingDetectorManager:
    def process(self, packet_info):
        return None

    def process_dns_query(self, dns_info):
        return None


if __name__ == "__main__":
    unittest.main()
