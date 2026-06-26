from excalibur.detection.dns_flood import DNSFloodDetector
from excalibur.detection.host_sweep import HostSweepDetector
from excalibur.detection.own_ips import discover_own_ips
from excalibur.detection.portscan import PortScanDetector
from excalibur.detection.rules_config import RulesConfig
from excalibur.detection.signature_engine import SignatureEngine
from excalibur.detection.unique_domains import UniqueDomainDetector


class DetectorManager:
    DETECTOR_TYPES = {
        "portscan": PortScanDetector,
        "dns_flood": DNSFloodDetector,
        "unique_domains": UniqueDomainDetector,
        "host_sweep": HostSweepDetector,
    }

    def __init__(
        self,
        database,
        detectors=None,
        config=None,
        rules=None,
        rules_path="rules.yaml",
        signature_rules_dir="rules",
        signature_engine=None,
        own_ips=None,
    ):
        self.database = database
        self.config = config or {}
        self.rules = rules or RulesConfig.load(rules_path)
        self.global_config = self.rules.get("global", {})
        self.own_ips = self._load_own_ips(own_ips)
        self.detectors = detectors if detectors is not None else self._build_detectors()
        self._print_builtin_detector_inventory()
        self.signature_engine = (
            signature_engine
            if signature_engine is not None
            else SignatureEngine(
                self.database,
                rules_dir=signature_rules_dir,
            )
        )

    def register(self, detector):
        self.detectors.append(detector)

    def process(self, packet_info):
        for detector in self.detectors:
            process_packet = getattr(detector, "process_packet", None)
            if process_packet:
                process_packet(packet_info)
        self.signature_engine.process_packet(packet_info)

    def process_dns_query(self, dns_info):
        for detector in self.detectors:
            process_dns_query = getattr(detector, "process_dns_query", None)
            if process_dns_query:
                process_dns_query(dns_info)
        self.signature_engine.process_dns_query(dns_info)

    def _build_detectors(self):
        detectors = []
        for rule in self.rules.get("rules", []):
            if not rule.get("enabled", True):
                continue

            rule_type = rule.get("type")
            detector_class = self.DETECTOR_TYPES.get(rule_type)
            if detector_class is None:
                print(f"[WARN] Unknown detector rule type ignored: {rule_type}", flush=True)
                continue

            if detector_class is PortScanDetector:
                detectors.append(
                    detector_class(
                        self.database,
                        config=self.config,
                        rule=rule,
                        global_config=self.global_config,
                        own_ips=self.own_ips,
                    )
                )
            elif detector_class is HostSweepDetector:
                detectors.append(
                    detector_class(
                        self.database,
                        rule=rule,
                        global_config=self.global_config,
                        own_ips=self.own_ips,
                        monitored_networks=self.config.get("monitored_networks", []),
                    )
                )
            else:
                detectors.append(
                    detector_class(
                        self.database,
                        rule=rule,
                        global_config=self.global_config,
                        own_ips=self.own_ips,
                    )
                )
        return detectors

    def _load_own_ips(self, own_ips):
        if not self.global_config.get("exclude_own_ips", True):
            return []
        discovered_ips = own_ips if own_ips is not None else discover_own_ips()
        print("[DETECTION] Own IP exclusion enabled", flush=True)
        print(f"[DETECTION] Own IPs: {', '.join(discovered_ips)}", flush=True)
        return discovered_ips

    def _print_builtin_detector_inventory(self):
        print("Built-in Detectors:", flush=True)
        if not self.detectors:
            print("* None", flush=True)
            return
        for detector in self.detectors:
            print(f"* {detector.__class__.__name__}", flush=True)
