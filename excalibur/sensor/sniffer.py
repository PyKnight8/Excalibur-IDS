from datetime import datetime, timezone
from threading import Event, Lock, Thread

from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, AsyncSniffer

from excalibur.database import Database
from excalibur.detection import DetectorManager
from excalibur.events import DnsEvent, PacketEvent


DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class PacketSniffer:
    def __init__(
        self,
        database=None,
        interface=None,
        packet_log_interval=100,
        config=None,
        rules=None,
        signature_rules_dir="rules",
        event_bus=None,
    ):
        self.database = database or Database()
        self.interface = interface
        self.total_packets = 0
        self.packet_count = 0
        self.packet_log_interval = packet_log_interval
        self.detector_manager = DetectorManager(
            self.database,
            config=config,
            rules=rules,
            signature_rules_dir=signature_rules_dir,
        )
        self._sniffer = None
        self._stats_thread = None
        self._stats_lock = Lock()
        self._packets_last_second = 0
        self.current_pps = 0
        self._stop_event = Event()
        self.event_bus = event_bus

    def start(self):
        self._stop_event.clear()
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
        )
        self._stats_thread = Thread(target=self._print_stats, daemon=True)
        self._stats_thread.start()
        self._sniffer.start()

    def stop(self):
        self._stop_event.set()
        if self._sniffer is not None and self._sniffer.running:
            self._sniffer.stop()
        self._sniffer = None
        if self._stats_thread is not None and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=1)
        self._stats_thread = None

    def run(self):
        self.start()
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=0.5)
        except KeyboardInterrupt:
            self.stop()

    def _handle_packet(self, packet):
        if IP not in packet:
            return

        timestamp = datetime.now(timezone.utc).isoformat()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = self._extract_source_mac(packet)
        src_port = None
        dst_port = None
        tcp_flags = None
        protocol = self._extract_protocol(packet)

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if self.database.host_exists(src_ip):
            self.database.update_host_last_seen(src_ip, timestamp)
        else:
            self.database.add_host(src_ip, src_mac, timestamp, timestamp)

        packet_info = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": len(packet),
        }
        if protocol == "TCP" and tcp_flags is not None:
            packet_info["tcp_flags"] = tcp_flags

        self.database.log_traffic(
            timestamp=packet_info["timestamp"],
            src_ip=packet_info["src_ip"],
            dst_ip=packet_info["dst_ip"],
            protocol=packet_info["protocol"],
            src_port=packet_info["src_port"],
            dst_port=packet_info["dst_port"],
            packet_size=packet_info["packet_size"],
        )
        dns_info = self._collect_dns_query(packet, packet_info)
        if dns_info:
            self.detector_manager.process_dns_query(dns_info)
        self.detector_manager.process(packet_info)
        self._emit_plugin_events(packet_info, dns_info, src_mac)

        self._record_packet()
        if (
            self.packet_log_interval
            and self.packet_count % self.packet_log_interval == 0
        ):
            print(f"[+] Packets captured: {self.packet_count}", flush=True)

    def _record_packet(self):
        with self._stats_lock:
            self.total_packets += 1
            self.packet_count = self.total_packets
            self._packets_last_second += 1

    def _print_stats(self):
        seconds_since_print = 0
        while not self._stop_event.wait(timeout=1):
            with self._stats_lock:
                self.current_pps = self._packets_last_second
                self._packets_last_second = 0
                total_packets = self.total_packets
                current_pps = self.current_pps

            seconds_since_print += 1
            if seconds_since_print >= 5:
                print("[STATS]", flush=True)
                print(f"pps={current_pps}", flush=True)
                print(f"total_packets={total_packets}", flush=True)
                seconds_since_print = 0

    def _extract_protocol(self, packet):
        if DNS in packet and DNSQR in packet:
            return "DNS"
        if TCP in packet:
            return "TCP"
        if UDP in packet:
            return "UDP"
        return str(packet[IP].proto)

    def _extract_source_mac(self, packet):
        if Ether in packet:
            return packet[Ether].src
        return None

    def _collect_dns_query(self, packet, packet_info):
        if DNS not in packet or DNSQR not in packet:
            return None

        dns_layer = packet[DNS]
        if dns_layer.qr == 0:
            client_ip = packet_info["src_ip"]
            dns_server_ip = packet_info["dst_ip"]
            dns_rcode = None
        elif dns_layer.qr == 1:
            client_ip = packet_info["dst_ip"]
            dns_server_ip = packet_info["src_ip"]
            dns_rcode = self._dns_rcode_name(dns_layer.rcode)
        else:
            return None

        query = packet[DNSQR]
        query_name = self._decode_dns_name(query.qname)
        query_type = query.get_field("qtype").i2repr(query, query.qtype)
        dns_info = {
            "timestamp": packet_info["timestamp"],
            "client_ip": client_ip,
            "dns_server_ip": dns_server_ip,
            "query_name": query_name,
            "query_type": query_type,
            "dns_rcode": dns_rcode,
        }
        dns_result = self.database.log_dns_query(
            **dns_info,
        )
        domain_risk = (dns_result or {}).get("domain_risk", {})
        if domain_risk:
            dns_info.update(
                {
                    "risk_score": domain_risk.get("risk_score", 0),
                    "risk_level": domain_risk.get("risk_level", "None"),
                    "risk_reasons": ", ".join(domain_risk.get("reasons", [])),
                }
            )
        return dns_info

    def _decode_dns_name(self, query_name):
        if isinstance(query_name, bytes):
            return query_name.decode("utf-8", errors="ignore")
        return str(query_name)

    def _emit_plugin_events(self, packet_info, dns_info, src_mac):
        if self.event_bus is None:
            return

        packet_event = PacketEvent(
            timestamp=packet_info["timestamp"],
            src_ip=packet_info["src_ip"],
            dst_ip=packet_info["dst_ip"],
            protocol=packet_info["protocol"],
            src_port=packet_info.get("src_port"),
            dst_port=packet_info.get("dst_port"),
            packet_size=packet_info.get("packet_size", 0),
            src_mac=src_mac,
            tcp_flags=packet_info.get("tcp_flags"),
        )
        self.event_bus.emit(packet_event)

        if dns_info:
            self.event_bus.emit(
                DnsEvent(
                    timestamp=dns_info["timestamp"],
                    client_ip=dns_info["client_ip"],
                    dns_server_ip=dns_info["dns_server_ip"],
                    query_name=dns_info["query_name"],
                    query_type=dns_info["query_type"],
                    dns_rcode=dns_info.get("dns_rcode"),
                    risk_score=dns_info.get("risk_score"),
                    risk_level=dns_info.get("risk_level"),
                    risk_reasons=dns_info.get("risk_reasons"),
                )
            )

    def _dns_rcode_name(self, rcode):
        try:
            numeric_rcode = int(rcode)
        except (TypeError, ValueError):
            return f"RCODE_{rcode}"
        return DNS_RCODE_NAMES.get(numeric_rcode, f"RCODE_{numeric_rcode}")
