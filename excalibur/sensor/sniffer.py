from datetime import datetime, timezone
import os
import socket
import time
import traceback
from threading import Event, Lock, Thread, current_thread

import psutil
from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, AsyncSniffer, conf
from scapy.interfaces import get_working_if, resolve_iface

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
    STATS_LOG_INTERVAL_SECONDS = 5
    INACTIVITY_WARNING_SECONDS = 15
    CALLBACK_STAGES = (
        "counter",
        "host",
        "traffic",
        "dns",
        "detectors",
        "plugins",
        "full",
    )

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
        self._callback_entries_total = 0
        self._callback_entries_last_second = 0
        self._callback_completions_total = 0
        self._callback_completions_last_second = 0
        self._callback_failures_total = 0
        self._callback_failures_last_second = 0
        self._packets_last_second = 0
        self._callback_duration_total = 0.0
        self._callback_duration_samples = 0
        self._perf_stage_totals_ms = {}
        self.current_pps = 0
        self._stop_event = Event()
        self.event_bus = event_bus
        self._startup_logged = False
        self._inactivity_warning_emitted = False
        self._callback_owner_logged = False
        self._last_interface_inventory = []
        self._effective_interface = None
        self._effective_interface_details = None
        configured_stage = str(
            os.environ.get("EXCALIBUR_CALLBACK_STAGE", "full")
        ).strip().lower()
        self.callback_stage = (
            configured_stage if configured_stage in self.CALLBACK_STAGES else "full"
        )

    def start(self):
        self._stop_event.clear()
        self._startup_logged = False
        self._inactivity_warning_emitted = False
        self._resolve_effective_interface()
        self._log_startup_diagnostics()
        self._log_runtime_owner("before_asyncsniffer_init")
        sniffer_kwargs = self._sniffer_kwargs()
        print(f"[Capture] AsyncSniffer parameters: {sniffer_kwargs}", flush=True)
        try:
            self._sniffer = AsyncSniffer(**sniffer_kwargs)
        except Exception as exc:
            print(f"[ERROR] AsyncSniffer initialization failed: {exc}", flush=True)
            print(traceback.format_exc(), flush=True)
            raise
        self._stats_thread = Thread(
            target=self._print_stats,
            name="ExcaliburStatsThread",
            daemon=True,
        )
        self._stats_thread.start()
        try:
            print("[Capture] Starting AsyncSniffer", flush=True)
            self._sniffer.start()
        except Exception as exc:
            print(f"[ERROR] AsyncSniffer start failed: {exc}", flush=True)
            print(traceback.format_exc(), flush=True)
            raise
        print(
            "[Capture] AsyncSniffer started "
            f"running={getattr(self._sniffer, 'running', None)} "
            f"alive={self._sniffer_thread_alive()} "
            f"thread_name={getattr(getattr(self._sniffer, 'thread', None), 'name', None)} "
            f"thread_ident={getattr(getattr(self._sniffer, 'thread', None), 'ident', None)}",
            flush=True,
        )
        self._log_runtime_owner("after_asyncsniffer_start")

    def stop(self):
        self._stop_event.set()
        if self._sniffer is not None:
            print(
                "[Capture] Stopping AsyncSniffer "
                f"running={getattr(self._sniffer, 'running', None)} "
                f"alive={self._sniffer_thread_alive()}",
                flush=True,
            )
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
        started_at = time.perf_counter()
        if not self._callback_owner_logged:
            print(
                "[Ownership] asyncsniffer_callback_thread "
                f"pid={os.getpid()} thread_name={current_thread().name} "
                f"thread_ident={current_thread().ident}",
                flush=True,
            )
            self._callback_owner_logged = True
        self._record_callback_entry()
        stage_timings = {}
        try:
            if self.callback_stage == "counter":
                self._record_packet()
                self._record_callback_completion()
                return

            parse_started_at = time.perf_counter()
            if IP not in packet:
                self._record_stage_timing(
                    stage_timings,
                    "packet_parse_ms",
                    (time.perf_counter() - parse_started_at) * 1000,
                )
                self._record_callback_completion()
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
            self._record_stage_timing(
                stage_timings,
                "packet_parse_ms",
                (time.perf_counter() - parse_started_at) * 1000,
            )

            host_started_at = time.perf_counter()
            self.database.record_host_seen(src_ip, src_mac, timestamp)
            self._record_stage_timing(
                stage_timings,
                "host_ms",
                (time.perf_counter() - host_started_at) * 1000,
            )
            if self.callback_stage == "host":
                self._record_packet()
                self._record_callback_completion()
                return

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

            traffic_started_at = time.perf_counter()
            try:
                self.database.log_traffic(
                    timestamp=packet_info["timestamp"],
                    src_ip=packet_info["src_ip"],
                    dst_ip=packet_info["dst_ip"],
                    protocol=packet_info["protocol"],
                    src_port=packet_info["src_port"],
                    dst_port=packet_info["dst_port"],
                    packet_size=packet_info["packet_size"],
                )
            except Exception as exc:
                print(
                    "[ERROR] Traffic storage failed: "
                    f"src={packet_info['src_ip']} "
                    f"dst={packet_info['dst_ip']} "
                    f"protocol={packet_info['protocol']} "
                    f"src_port={packet_info['src_port']} "
                    f"dst_port={packet_info['dst_port']} "
                    f"error={exc}",
                    flush=True,
                )
                print(traceback.format_exc(), flush=True)
                if hasattr(self.database, "record_traffic_write_failure"):
                    self.database.record_traffic_write_failure()
            self._record_stage_timing(
                stage_timings,
                "traffic_db_ms",
                (time.perf_counter() - traffic_started_at) * 1000,
            )
            if self.callback_stage == "traffic":
                self._record_packet()
                self._record_callback_completion()
                return

            dns_info = self._collect_dns_query(packet, packet_info, stage_timings)
            if self.callback_stage == "dns":
                self._record_packet()
                self._record_callback_completion()
                return

            detectors_started_at = time.perf_counter()
            if dns_info:
                self._process_detector_dns(dns_info, stage_timings)
            self._process_detector_packet(packet_info, stage_timings)
            self._record_stage_timing(
                stage_timings,
                "detectors_ms",
                (time.perf_counter() - detectors_started_at) * 1000,
            )
            if self.callback_stage == "detectors":
                self._record_packet()
                self._record_callback_completion()
                return

            plugins_started_at = time.perf_counter()
            self._emit_plugin_events(packet_info, dns_info, src_mac)
            self._record_stage_timing(
                stage_timings,
                "plugins_ms",
                (time.perf_counter() - plugins_started_at) * 1000,
            )
            if self.callback_stage == "plugins":
                self._record_packet()
                self._record_callback_completion()
                return

            stats_started_at = time.perf_counter()
            self._record_packet()
            if (
                self.packet_log_interval
                and self.packet_count % self.packet_log_interval == 0
            ):
                print(f"[+] Packets captured: {self.packet_count}", flush=True)
            self._record_stage_timing(
                stage_timings,
                "metrics_ms",
                (time.perf_counter() - stats_started_at) * 1000,
            )
            self._record_callback_completion()
        except Exception as exc:
            print(f"[ERROR] Packet callback failed: {exc}", flush=True)
            print(traceback.format_exc(), flush=True)
            self._record_callback_failure()
        finally:
            total_elapsed_ms = (time.perf_counter() - started_at) * 1000
            known_ms = sum(stage_timings.values())
            self._record_stage_timing(
                stage_timings,
                "other_ms",
                max(0.0, total_elapsed_ms - known_ms),
            )
            self._record_callback_duration(total_elapsed_ms)
            self._record_stage_totals(stage_timings)

    def _record_callback_entry(self):
        with self._stats_lock:
            self._callback_entries_total += 1
            self._callback_entries_last_second += 1

    def _record_callback_completion(self):
        with self._stats_lock:
            self._callback_completions_total += 1
            self._callback_completions_last_second += 1

    def _record_callback_failure(self):
        with self._stats_lock:
            self._callback_failures_total += 1
            self._callback_failures_last_second += 1

    def _record_packet(self):
        with self._stats_lock:
            self.total_packets += 1
            self.packet_count = self.total_packets
            self._packets_last_second += 1

    def _record_callback_duration(self, elapsed_ms):
        with self._stats_lock:
            self._callback_duration_total += elapsed_ms
            self._callback_duration_samples += 1

    def _record_stage_totals(self, stage_timings):
        with self._stats_lock:
            for name, value in stage_timings.items():
                self._perf_stage_totals_ms[name] = (
                    self._perf_stage_totals_ms.get(name, 0.0) + value
                )

    @staticmethod
    def _record_stage_timing(stage_timings, name, elapsed_ms):
        stage_timings[name] = stage_timings.get(name, 0.0) + elapsed_ms

    def _print_stats(self):
        print(
            "[Ownership] stats_thread_started "
            f"pid={os.getpid()} thread_name={current_thread().name} "
            f"thread_ident={current_thread().ident}",
            flush=True,
        )
        seconds_since_print = 0
        window_callback_entries = 0
        window_callback_completions = 0
        window_callback_failures = 0
        window_completed_packets = 0
        window_callback_duration_total = 0.0
        window_callback_duration_samples = 0
        window_perf_stage_totals_ms = {}
        while not self._stop_event.wait(timeout=1):
            with self._stats_lock:
                callback_entries = self._callback_entries_last_second
                self._callback_entries_last_second = 0
                callback_completions = self._callback_completions_last_second
                self._callback_completions_last_second = 0
                callback_failures = self._callback_failures_last_second
                self._callback_failures_last_second = 0
                self.current_pps = self._packets_last_second
                self._packets_last_second = 0
                total_packets = self.total_packets
                current_pps = self.current_pps
                callback_duration_total = self._callback_duration_total
                callback_duration_samples = self._callback_duration_samples
                self._callback_duration_total = 0.0
                self._callback_duration_samples = 0
                perf_stage_totals_ms = self._perf_stage_totals_ms
                self._perf_stage_totals_ms = {}

            window_callback_entries += callback_entries
            window_callback_completions += callback_completions
            window_callback_failures += callback_failures
            window_completed_packets += current_pps
            window_callback_duration_total += callback_duration_total
            window_callback_duration_samples += callback_duration_samples
            for key, value in perf_stage_totals_ms.items():
                window_perf_stage_totals_ms[key] = (
                    window_perf_stage_totals_ms.get(key, 0.0) + value
                )

            seconds_since_print += 1
            if seconds_since_print >= self.STATS_LOG_INTERVAL_SECONDS:
                db_perf = None
                get_async_perf_snapshot = getattr(
                    self.database, "get_async_perf_snapshot", None
                )
                if callable(get_async_perf_snapshot):
                    db_perf = get_async_perf_snapshot()
                average_callback_ms = 0.0
                if window_callback_duration_samples:
                    average_callback_ms = round(
                        window_callback_duration_total / window_callback_duration_samples,
                        3,
                    )
                average_callbacks_per_second = round(
                    window_callback_entries / self.STATS_LOG_INTERVAL_SECONDS,
                    3,
                )
                average_completed_packets_per_second = round(
                    window_completed_packets / self.STATS_LOG_INTERVAL_SECONDS,
                    3,
                )
                print("[STATS]", flush=True)
                print(
                    f"callback_entries_5s={window_callback_entries}",
                    flush=True,
                )
                print(
                    f"callback_completions_5s={window_callback_completions}",
                    flush=True,
                )
                print(
                    f"callback_failures_5s={window_callback_failures}",
                    flush=True,
                )
                print(
                    f"completed_packets_5s={window_completed_packets}",
                    flush=True,
                )
                print(
                    f"avg_callbacks_per_second_5s={average_callbacks_per_second}",
                    flush=True,
                )
                print(
                    "avg_completed_packets_per_second_5s="
                    f"{average_completed_packets_per_second}",
                    flush=True,
                )
                print(f"total_packets={total_packets}", flush=True)
                print(
                    "[Capture] callback_rate "
                    f"interval_seconds={self.STATS_LOG_INTERVAL_SECONDS} "
                    f"callbacks_5s={window_callback_entries} "
                    f"completed_packets_5s={window_completed_packets} "
                    f"avg_callbacks_per_second={average_callbacks_per_second} "
                    "avg_completed_packets_per_second="
                    f"{average_completed_packets_per_second} "
                    f"avg_callback_ms={average_callback_ms} "
                    f"total_packets={total_packets}",
                    flush=True,
                )
                print("[PERF]", flush=True)
                print(f"callbacks_entered_5s={window_callback_entries}", flush=True)
                print(
                    f"callbacks_completed_5s={window_callback_completions}",
                    flush=True,
                )
                print(f"callbacks_failed_5s={window_callback_failures}", flush=True)
                print(
                    f"completed_packets_5s={window_completed_packets}",
                    flush=True,
                )
                print(
                    f"avg_callbacks_per_second_5s={average_callbacks_per_second}",
                    flush=True,
                )
                print(
                    "avg_completed_packets_per_second_5s="
                    f"{average_completed_packets_per_second}",
                    flush=True,
                )
                print(f"avg_callback_ms={average_callback_ms}", flush=True)
                for key in [
                    "packet_parse_ms",
                    "host_ms",
                    "traffic_db_ms",
                    "dns_ms",
                    "dns_row_ms",
                    "domain_ms",
                    "domain_risk_ms",
                    "domain_lookup_ms",
                    "domain_state_ms",
                    "domain_write_ms",
                    "domain_alert_ms",
                    "detectors_ms",
                    "detectors_builtin_ms",
                    "detectors_signature_ms",
                    "plugins_ms",
                    "metrics_ms",
                    "other_ms",
                ]:
                    print(
                        f"{key}={round(window_perf_stage_totals_ms.get(key, 0.0), 3)}",
                        flush=True,
                    )
                if db_perf is not None:
                    print(
                        "[DBPERF] "
                        f"packet_db_lock_wait_ms={db_perf['packet_db_lock_wait_ms']} "
                        f"writer_db_lock_wait_ms={db_perf['writer_db_lock_wait_ms']} "
                        f"writer_db_lock_hold_ms={db_perf['writer_db_lock_hold_ms']} "
                        f"queue_depth={db_perf['queue_depth']}",
                        flush=True,
                    )
                self._warn_if_inactive(seconds_since_print, total_packets)
                seconds_since_print = 0
                window_callback_entries = 0
                window_callback_completions = 0
                window_callback_failures = 0
                window_completed_packets = 0
                window_callback_duration_total = 0.0
                window_callback_duration_samples = 0
                window_perf_stage_totals_ms = {}

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

    def _collect_dns_query(self, packet, packet_info, perf_stats=None):
        perf_stats = perf_stats if perf_stats is not None else {}
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
        dns_started_at = time.perf_counter()
        dns_result = self.database.log_dns_query(
            **dns_info,
            perf_stats=perf_stats,
        )
        self._record_stage_timing(
            perf_stats,
            "dns_ms",
            (time.perf_counter() - dns_started_at) * 1000,
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

    def _process_detector_packet(self, packet_info, perf_stats):
        try:
            self.detector_manager.process(packet_info, perf_stats=perf_stats)
        except TypeError as exc:
            if "perf_stats" not in str(exc):
                raise
            self.detector_manager.process(packet_info)

    def _process_detector_dns(self, dns_info, perf_stats):
        try:
            self.detector_manager.process_dns_query(dns_info, perf_stats=perf_stats)
        except TypeError as exc:
            if "perf_stats" not in str(exc):
                raise
            self.detector_manager.process_dns_query(dns_info)

    def _dns_rcode_name(self, rcode):
        try:
            numeric_rcode = int(rcode)
        except (TypeError, ValueError):
            return f"RCODE_{rcode}"
        return DNS_RCODE_NAMES.get(numeric_rcode, f"RCODE_{numeric_rcode}")

    def _sniffer_kwargs(self):
        return {
            "iface": self._effective_interface,
            "prn": self._handle_packet,
            "store": False,
        }

    def _log_startup_diagnostics(self):
        if self._startup_logged:
            return
        self._startup_logged = True
        self._last_interface_inventory = self._capture_interface_inventory()
        print(
            f"[Capture] Scapy conf.iface raw={repr(getattr(conf, 'iface', None))}",
            flush=True,
        )
        print(
            f"[Capture] Scapy conf.iface str={str(getattr(conf, 'iface', None))}",
            flush=True,
        )
        print(
            f"[Capture] Startup platform={os.name} pid={os.getpid()} cwd={os.getcwd()}",
            flush=True,
        )
        print(f"[Capture] callback_stage={self.callback_stage!r}", flush=True)
        if not self._last_interface_inventory:
            print("[Capture] No interfaces discovered by Scapy/psutil", flush=True)
        for entry in self._last_interface_inventory:
            print(
                "[Capture] Interface "
                f"name={entry['name']!r} "
                f"network_name={entry['network_name']!r} "
                f"description={entry['description']!r} "
                f"guid={entry['guid']!r} "
                f"index={entry['index']!r} "
                f"ips={entry['ips']} "
                f"mac={entry['mac']!r} "
                f"is_up={entry['is_up']} "
                f"repr={entry['repr']!r}",
                flush=True,
            )
        selected_interface = self._selected_interface_label()
        print(f"[Capture] Selected capture interface: {selected_interface!r}", flush=True)
        if self._effective_interface_details:
            print(
                "[Capture] Effective interface details "
                f"name={self._effective_interface_details.get('name')!r} "
                f"network_name={self._effective_interface_details.get('network_name')!r} "
                f"description={self._effective_interface_details.get('description')!r} "
                f"ip={self._effective_interface_details.get('ip')!r}",
                flush=True,
            )
        self._log_wireless_candidates()
        if os.name == "nt":
            self._log_windows_adapter_visibility(selected_interface)

    def _capture_interface_inventory(self):
        inventory = {}
        for entry in self._scapy_interfaces():
            key = self._inventory_key(entry.get("name"), entry.get("description"))
            inventory[key] = {
                "name": entry.get("name"),
                "network_name": entry.get("network_name"),
                "description": entry.get("description"),
                "guid": entry.get("guid"),
                "index": entry.get("index"),
                "repr": entry.get("repr"),
                "ips": [],
                "mac": None,
                "is_up": None,
            }

        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        link_family = getattr(psutil, "AF_LINK", object())
        for name, addresses in net_if_addrs.items():
            key = self._inventory_key(name, None)
            item = inventory.setdefault(
                key,
                {
                    "name": name,
                    "description": "",
                    "ips": [],
                    "mac": None,
                    "is_up": None,
                },
            )
            stats = net_if_stats.get(name)
            item["is_up"] = getattr(stats, "isup", None)
            for address in addresses:
                if address.family in {socket.AF_INET, socket.AF_INET6} and address.address:
                    item["ips"].append(address.address)
                elif address.family == link_family and address.address:
                    item["mac"] = address.address

        normalized = []
        for item in inventory.values():
            normalized.append(
                {
                    "name": item.get("name") or "",
                    "network_name": item.get("network_name") or "",
                    "description": item.get("description") or "",
                    "guid": item.get("guid"),
                    "index": item.get("index"),
                    "repr": item.get("repr") or "",
                    "ips": sorted(dict.fromkeys(item.get("ips") or [])),
                    "mac": item.get("mac"),
                    "is_up": item.get("is_up"),
                }
            )
        return sorted(
            normalized,
            key=lambda item: (
                str(item.get("name") or "").lower(),
                str(item.get("description") or "").lower(),
            ),
        )

    def _scapy_interfaces(self):
        interfaces = []
        try:
            scapy_ifaces = self._scapy_ifaces_dict()
            values = scapy_ifaces.values() if scapy_ifaces is not None else []
            for iface in values:
                interfaces.append(
                    {
                        "name": str(
                            getattr(iface, "network_name", None)
                            or getattr(iface, "name", None)
                            or ""
                        ),
                        "network_name": str(getattr(iface, "network_name", None) or ""),
                        "description": str(getattr(iface, "description", None) or ""),
                        "guid": str(getattr(iface, "guid", None) or ""),
                        "index": getattr(iface, "index", None),
                        "ip": str(getattr(iface, "ip", None) or ""),
                        "repr": repr(iface),
                    }
                )
        except Exception as exc:
            print(f"[WARN] Failed to enumerate Scapy interfaces: {exc}", flush=True)
            print(traceback.format_exc(), flush=True)
        return interfaces

    def _scapy_ifaces_dict(self):
        scapy_ifaces = getattr(conf, "ifaces", None)
        if scapy_ifaces is not None and list(scapy_ifaces.values()):
            return scapy_ifaces
        try:
            import scapy.interfaces as scapy_interfaces

            scapy_ifaces = getattr(scapy_interfaces, "ifaces", None)
            if scapy_ifaces is not None and list(scapy_ifaces.values()):
                return scapy_ifaces
            if scapy_ifaces is not None:
                scapy_ifaces.reload()
                return scapy_ifaces
        except Exception as exc:
            print(f"[WARN] Failed to access Scapy interface dictionary: {exc}", flush=True)
            print(traceback.format_exc(), flush=True)
        return scapy_ifaces

    def _selected_interface_label(self):
        if self._effective_interface is not None:
            return str(self._effective_interface)
        if self.interface is not None:
            return str(self.interface)
        return str(getattr(conf, "iface", None) or "")

    def _resolve_effective_interface(self):
        if self._effective_interface_details is not None:
            return self._effective_interface

        candidate = self.interface
        if candidate is None:
            candidate = getattr(conf, "iface", None)
        if candidate is None:
            candidate = get_working_if()

        if candidate is None:
            self._effective_interface = None
            self._effective_interface_details = {}
            return None

        try:
            resolved = resolve_iface(candidate)
            self._effective_interface = str(
                getattr(resolved, "network_name", None) or resolved
            )
            self._effective_interface_details = {
                "name": str(getattr(resolved, "name", None) or ""),
                "network_name": self._effective_interface,
                "description": str(getattr(resolved, "description", None) or ""),
                "ip": str(getattr(resolved, "ip", None) or ""),
            }
        except Exception as exc:
            self._effective_interface = str(candidate)
            self._effective_interface_details = {
                "name": "",
                "network_name": self._effective_interface,
                "description": "",
                "ip": "",
            }
            print(
                "[WARN] Failed to resolve effective Scapy interface "
                f"{candidate!r}: {exc}",
                flush=True,
            )
            print(traceback.format_exc(), flush=True)

        self.interface = self._effective_interface
        return self._effective_interface

    def _log_windows_adapter_visibility(self, selected_interface):
        active_interfaces = [
            entry
            for entry in self._last_interface_inventory
            if entry.get("is_up") and self._is_active_candidate(entry)
        ]
        print(
            f"[Capture][Windows] active_adapter_candidates={len(active_interfaces)}",
            flush=True,
        )
        for entry in active_interfaces:
            visible = self._entry_matches_selected(entry, selected_interface)
            print(
                "[Capture][Windows] adapter_visibility "
                f"name={entry['name']!r} "
                f"description={entry['description']!r} "
                f"visible_to_scapy={bool(entry['name'] or entry['description'])} "
                f"matches_selected={visible}",
                flush=True,
            )
        if selected_interface and not any(
            self._entry_matches_selected(entry, selected_interface)
            for entry in self._last_interface_inventory
        ):
            print(
                "[WARN] Selected capture interface was not found in discovered interface inventory",
                flush=True,
            )

    def _log_wireless_candidates(self):
        wireless_entries = [
            entry
            for entry in self._last_interface_inventory
            if self._is_wireless_candidate(entry)
        ]
        if not wireless_entries:
            return
        print(
            f"[Capture] Wireless/Npcap candidates discovered={len(wireless_entries)}",
            flush=True,
        )
        for entry in wireless_entries:
            print(
                "[Capture] Wireless candidate "
                f"name={entry['name']!r} "
                f"description={entry['description']!r} "
                f"ips={entry['ips']} "
                f"is_up={entry['is_up']}",
                flush=True,
            )

    def _warn_if_inactive(self, seconds_since_start, total_packets):
        if self._inactivity_warning_emitted:
            return
        if total_packets > 0:
            return
        if seconds_since_start < self.INACTIVITY_WARNING_SECONDS:
            return
        other_interfaces = [
            entry
            for entry in self._last_interface_inventory
            if self._is_active_candidate(entry)
            and not self._entry_matches_selected(entry, self._selected_interface_label())
        ]
        if other_interfaces:
            print(
                "[WARN] No packets observed on selected interface after "
                f"{seconds_since_start} seconds while other active interfaces exist",
                flush=True,
            )
            for entry in other_interfaces:
                print(
                    "[WARN] Alternate active interface candidate "
                    f"name={entry['name']!r} description={entry['description']!r} "
                    f"ips={entry['ips']}",
                    flush=True,
                )
        else:
            print(
                "[WARN] No packets observed on selected interface after "
                f"{seconds_since_start} seconds",
                flush=True,
            )
        self._inactivity_warning_emitted = True

    def _sniffer_thread_alive(self):
        thread = getattr(self._sniffer, "thread", None)
        if thread is None:
            return None
        is_alive = getattr(thread, "is_alive", None)
        if callable(is_alive):
            return is_alive()
        return None

    @staticmethod
    def _inventory_key(name, description):
        return (
            str(name or "").strip().lower(),
            str(description or "").strip().lower(),
        )

    @staticmethod
    def _is_active_candidate(entry):
        if not entry.get("is_up"):
            return False
        if entry.get("ips"):
            return any(
                ip
                for ip in entry["ips"]
                if not str(ip).startswith("127.") and str(ip) != "::1"
            )
        return bool(entry.get("name") or entry.get("description"))

    @staticmethod
    def _entry_matches_selected(entry, selected_interface):
        selected = str(selected_interface or "").strip().lower()
        if not selected:
            return False
        name = str(entry.get("name") or "").strip().lower()
        description = str(entry.get("description") or "").strip().lower()
        return selected in {name, description} or selected in name or selected in description

    @staticmethod
    def _is_wireless_candidate(entry):
        text = " ".join(
            [
                str(entry.get("name") or ""),
                str(entry.get("description") or ""),
            ]
        ).lower()
        return any(token in text for token in ("wi-fi", "wifi", "wireless", "wlan"))

    def _log_runtime_owner(self, label):
        try:
            process = psutil.Process(os.getpid())
            children = process.children()
        except (psutil.Error, OSError) as exc:
            print(f"[Ownership] {label} failed: {exc}", flush=True)
            return
        print(
            f"[Ownership] {label} "
            f"pid={process.pid} "
            f"exe={self._safe_process_call(process.exe)} "
            f"cmdline={' '.join(self._safe_process_call(process.cmdline, []) or [])} "
            f"children={[getattr(child, 'pid', None) for child in children]}",
            flush=True,
        )

    @staticmethod
    def _safe_process_call(func, default=None):
        try:
            return func()
        except (psutil.Error, OSError):
            return default
