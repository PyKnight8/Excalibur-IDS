from pathlib import Path
from tempfile import TemporaryDirectory
import os
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from scapy.all import DNS, DNSQR, IP, TCP, UDP

from excalibur.database import Database
from excalibur.dashboard.app import create_app
from excalibur.sensor.sniffer import PacketSniffer


class DNSCollectionTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir.name)
        self.database = Database(Path(self.temp_dir.name) / "test.sqlite")

    def tearDown(self):
        self.database.close()
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def test_log_dns_query_normalizes_and_tracks_domain_once(self):
        self.database.log_dns_query(
            timestamp="2026-06-08T10:00:00+00:00",
            client_ip="10.0.0.10",
            dns_server_ip="10.0.0.1",
            query_name="Example.COM.",
            query_type="A",
        )
        self.database.log_dns_query(
            timestamp="2026-06-08T10:01:00+00:00",
            client_ip="10.0.0.10",
            dns_server_ip="10.0.0.1",
            query_name="example.com",
            query_type="A",
        )

        dns_queries = self.database.get_dns_queries(limit=100)
        domains, domain_total = self.database.get_domains()
        domains_log = Path("data") / "domains.log"

        self.assertEqual(len(dns_queries), 2)
        self.assertEqual(domain_total, 1)
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0]["domain"], "example.com")
        self.assertEqual(domains[0]["query_count"], 2)
        self.assertEqual(domains_log.read_text(encoding="utf-8").splitlines(), ["example.com"])

    def test_log_dns_query_stores_response_code(self):
        self.database.log_dns_query(
            timestamp="2026-06-08T10:00:00+00:00",
            client_ip="10.0.0.10",
            dns_server_ip="10.0.0.1",
            query_name="missing.example.",
            query_type="A",
            dns_rcode="NXDOMAIN",
        )

        dns_queries = self.database.get_dns_queries(limit=100)

        self.assertEqual(dns_queries[0]["dns_rcode"], "NXDOMAIN")

    def test_sniffer_marks_dns_traffic_and_collects_query(self):
        sniffer = PacketSniffer(database=self.database, packet_log_interval=None)
        packet = (
            IP(src="10.0.0.10", dst="10.0.0.1")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="Example.COM.", qtype="A"))
        )

        sniffer._handle_packet(packet)

        traffic_rows, traffic_total = self.database.get_traffic()
        dns_queries = self.database.get_dns_queries(limit=100)
        domains, domain_total = self.database.get_domains()

        self.assertEqual(traffic_total, 1)
        self.assertEqual(traffic_rows[0]["protocol"], "DNS")
        self.assertEqual(len(dns_queries), 1)
        self.assertEqual(dns_queries[0]["query_name"], "example.com")
        self.assertEqual(domain_total, 1)
        self.assertEqual(domains[0]["domain"], "example.com")

    def test_sniffer_collects_dns_response_code(self):
        sniffer = PacketSniffer(database=self.database, packet_log_interval=None)
        processed_dns_queries = []
        sniffer.detector_manager = _CollectingDetectorManager(
            processed_packets=[],
            processed_dns_queries=processed_dns_queries,
        )
        packet = (
            IP(src="10.0.0.1", dst="10.0.0.10")
            / UDP(sport=53, dport=53000)
            / DNS(qr=1, rcode=3, qd=DNSQR(qname="Missing.EXAMPLE.", qtype="A"))
        )

        sniffer._handle_packet(packet)

        dns_queries = self.database.get_dns_queries(limit=100)
        self.assertEqual(processed_dns_queries[0]["client_ip"], "10.0.0.10")
        self.assertEqual(processed_dns_queries[0]["dns_server_ip"], "10.0.0.1")
        self.assertEqual(processed_dns_queries[0]["dns_rcode"], "NXDOMAIN")
        self.assertEqual(dns_queries[0]["query_name"], "missing.example")
        self.assertEqual(dns_queries[0]["dns_rcode"], "NXDOMAIN")

    def test_sniffer_exposes_tcp_flags_to_packet_events(self):
        sniffer = PacketSniffer(database=self.database, packet_log_interval=None)
        processed_packets = []
        sniffer.detector_manager = _CollectingDetectorManager(processed_packets)
        packet = IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=53000, dport=80, flags="S")

        sniffer._handle_packet(packet)

        self.assertEqual(processed_packets[0]["protocol"], "TCP")
        self.assertEqual(processed_packets[0]["tcp_flags"], "S")

    def test_sniffer_logs_packet_callback_exceptions(self):
        sniffer = PacketSniffer(database=self.database, packet_log_interval=None)
        sniffer.database.log_traffic = Mock(side_effect=RuntimeError("write failed"))
        packet = IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=53000, dport=80, flags="S")

        with patch("builtins.print") as print_mock:
            sniffer._handle_packet(packet)

        printed_lines = [" ".join(str(arg) for arg in call.args) for call in print_mock.call_args_list]
        self.assertTrue(any("Traffic storage failed" in line for line in printed_lines))
        self.assertFalse(any("Packet callback failed" in line for line in printed_lines))

    def test_sniffer_continues_detectors_and_packet_event_after_traffic_write_failure(self):
        sniffer = PacketSniffer(database=self.database, packet_log_interval=None)
        processed_packets = []
        sniffer.detector_manager = _CollectingDetectorManager(processed_packets)
        packet_events = []
        sniffer.event_bus = _CollectingEventBus(packet_events)
        sniffer.database.log_traffic = Mock(side_effect=RuntimeError("write failed"))
        packet = IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=53000, dport=80, flags="S")

        with patch("builtins.print") as print_mock:
            sniffer._handle_packet(packet)

        printed_lines = [" ".join(str(arg) for arg in call.args) for call in print_mock.call_args_list]
        health = self.database.get_system_health()

        self.assertEqual(len(processed_packets), 1)
        self.assertEqual(processed_packets[0]["src_ip"], "10.0.0.10")
        self.assertEqual(len(packet_events), 1)
        self.assertEqual(packet_events[0].event_type, "packet_event")
        self.assertEqual(packet_events[0].tcp_flags, "S")
        self.assertTrue(any("Traffic storage failed" in line for line in printed_lines))
        self.assertFalse(any("Packet callback failed" in line for line in printed_lines))
        self.assertEqual(health["writes"]["traffic_write_failures"], 1)

    def test_sniffer_continues_dns_event_after_traffic_write_failure(self):
        sniffer = PacketSniffer(database=self.database, packet_log_interval=None)
        processed_packets = []
        processed_dns_queries = []
        emitted_events = []
        sniffer.detector_manager = _CollectingDetectorManager(
            processed_packets=processed_packets,
            processed_dns_queries=processed_dns_queries,
        )
        sniffer.event_bus = _CollectingEventBus(emitted_events)
        sniffer.database.log_traffic = Mock(side_effect=RuntimeError("write failed"))
        packet = (
            IP(src="10.0.0.10", dst="10.0.0.1")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="Example.COM.", qtype="A"))
        )

        with patch("builtins.print") as print_mock:
            sniffer._handle_packet(packet)

        printed_lines = [" ".join(str(arg) for arg in call.args) for call in print_mock.call_args_list]
        health = self.database.get_system_health()
        event_types = [event.event_type for event in emitted_events]

        self.assertEqual(len(processed_packets), 1)
        self.assertEqual(len(processed_dns_queries), 1)
        self.assertEqual(processed_dns_queries[0]["query_name"], "Example.COM.")
        self.assertEqual(event_types, ["packet_event", "dns_event"])
        self.assertEqual(emitted_events[1].query_name, "Example.COM.")
        self.assertTrue(any("Traffic storage failed" in line for line in printed_lines))
        self.assertFalse(any("Packet callback failed" in line for line in printed_lines))
        self.assertEqual(health["writes"]["traffic_write_failures"], 1)

    def test_sniffer_warns_when_no_packets_arrive_on_selected_interface(self):
        sniffer = PacketSniffer(database=self.database, interface="Ethernet", packet_log_interval=None)
        sniffer._last_interface_inventory = [
            {
                "name": "Ethernet",
                "description": "Primary Ethernet",
                "ips": ["192.168.1.10"],
                "mac": "00:11:22:33:44:55",
                "is_up": True,
            },
            {
                "name": "Wi-Fi",
                "description": "Wireless Adapter",
                "ips": ["10.0.0.20"],
                "mac": "66:77:88:99:AA:BB",
                "is_up": True,
            },
        ]

        with patch("builtins.print") as print_mock:
            sniffer._warn_if_inactive(sniffer.INACTIVITY_WARNING_SECONDS, 0)

        printed_lines = [" ".join(str(arg) for arg in call.args) for call in print_mock.call_args_list]
        self.assertTrue(any("No packets observed on selected interface" in line for line in printed_lines))
        self.assertTrue(any("Alternate active interface candidate" in line for line in printed_lines))

    def test_sniffer_resolves_effective_interface_for_asyncsniffer(self):
        sniffer = PacketSniffer(database=self.database, interface=None, packet_log_interval=None)
        fake_iface = SimpleNamespace(
            network_name=r"\\Device\\NPF_{TEST-GUID}",
            name="Wi-Fi",
            description="Wireless Adapter",
            ip="192.168.1.25",
        )

        with patch("excalibur.sensor.sniffer.get_working_if", return_value=fake_iface):
            with patch("excalibur.sensor.sniffer.resolve_iface", return_value=fake_iface):
                resolved = sniffer._resolve_effective_interface()

        self.assertEqual(resolved, r"\\Device\\NPF_{TEST-GUID}")
        self.assertEqual(sniffer.interface, r"\\Device\\NPF_{TEST-GUID}")
        self.assertEqual(sniffer._sniffer_kwargs()["iface"], r"\\Device\\NPF_{TEST-GUID}")

    def test_dns_dashboard_routes_render(self):
        self.database.log_dns_query(
            timestamp="2026-06-08T10:00:00+00:00",
            client_ip="10.0.0.10",
            dns_server_ip="10.0.0.1",
            query_name="Example.COM.",
            query_type="A",
        )

        app = create_app(Path(self.temp_dir.name) / "test.sqlite")
        client = app.test_client()

        dns_response = client.get("/dns?search=example&sort_by=query_name&sort_order=ASC")
        domains_response = client.get("/domains?search=example&sort_by=query_count&sort_order=DESC")
        log_response = client.get("/domains/log")

        self.assertEqual(dns_response.status_code, 200)
        self.assertIn("example.com", dns_response.get_data(as_text=True))
        self.assertEqual(domains_response.status_code, 200)
        self.assertIn("example.com", domains_response.get_data(as_text=True))
        self.assertEqual(log_response.status_code, 200)
        self.assertIn("example.com", log_response.get_data(as_text=True))


class _CollectingDetectorManager:
    def __init__(self, processed_packets, processed_dns_queries=None):
        self.processed_packets = processed_packets
        self.processed_dns_queries = processed_dns_queries if processed_dns_queries is not None else []

    def process(self, packet_info):
        self.processed_packets.append(packet_info)

    def process_dns_query(self, dns_info):
        self.processed_dns_queries.append(dns_info)


class _CollectingEventBus:
    def __init__(self, events):
        self.events = events

    def emit(self, event):
        self.events.append(event)


if __name__ == "__main__":
    unittest.main()
