from pathlib import Path
from tempfile import TemporaryDirectory
import os
import unittest

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


if __name__ == "__main__":
    unittest.main()
