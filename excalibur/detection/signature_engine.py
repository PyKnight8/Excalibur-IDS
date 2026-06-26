from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
import json
import os
import re


class SignatureValidationError(ValueError):
    pass


class SignatureEngine:
    DEBUG_DNS_EVENTS = os.environ.get("EXCALIBUR_ERL_DEBUG_DNS", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    DEBUG_RULES = os.environ.get("EXCALIBUR_ERL_DEBUG_RULES", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    DEBUG_ALERTS = os.environ.get("EXCALIBUR_ERL_DEBUG_ALERTS", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    PACKET_FIELDS = {
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "packet_size",
        "tcp_flags",
    }
    DNS_FIELDS = {
        "client_ip",
        "dns_server_ip",
        "query_name",
        "query_type",
        "risk_score",
        "risk_level",
        "risk_reasons",
        "dns_rcode",
    }
    MATCH_OPERATORS = {
        "in",
        "in_networks",
        "contains",
        "contains_any",
        "endswith",
        "endswith_any",
        "gt",
        "gte",
        "lt",
        "lte",
        "regex",
        "startswith",
    }
    AGGREGATES = {"count", "unique_dst_ips", "unique_dst_ports", "unique_domains"}
    AGGREGATE_OPERATORS = {"gte"}
    SEVERITIES = {"Low", "Medium", "High"}

    DEFAULT_SIGNATURES = [
        {
            "name": "SMB Recon",
            "enabled": True,
            "event": "packet",
            "match": {
                "protocol": "TCP",
                "dst_port": 445,
            },
            "aggregate": {
                "unique_dst_ips": {
                    "gte": 20,
                },
                "within_seconds": 60,
            },
            "alert": {
                "severity": "High",
                "title": "SMB Recon Activity",
                "description": "Source contacted many hosts via SMB.",
            },
        },
    ]

    RULE_PACK_NAMES = [
        "recon.yaml",
        "dns.yaml",
        "ad.yaml",
        "databases.yaml",
        "web.yaml",
        "browser.yaml",
    ]

    def __init__(
        self,
        database,
        rules_dir="rules",
        signatures=None,
    ):
        self.database = database
        self.rules_dir = rules_dir
        config = signatures if signatures is not None else self.load(rules_dir)
        self.source_inventory = config.get("source_inventory", {})
        self.rules = self.compile(config)

    @classmethod
    def load(cls, rules_dir="rules"):
        rules_path = Path(rules_dir)
        cls.create_default_rule_packs(rules_path)
        cls._fail_if_legacy_signatures_exist()

        loaded_signatures = []
        source_inventory = {
            "rule_packs": [],
        }
        for rule_file in sorted(rules_path.glob("*.yaml")):
            parsed = cls.parse(
                rule_file.read_text(encoding="utf-8"),
                source_name=rule_file.name,
                allow_empty=True,
            )
            for signature in parsed.get("signatures", []):
                signature["_rule_pack"] = rule_file.name
                loaded_signatures.append(signature)
            print(
                f"[RULES] Loaded {rule_file.name} ({len(parsed.get('signatures', []))} rules)",
                flush=True,
            )
            source_inventory["rule_packs"].append(
                {
                    "path": rule_file.name,
                    "count": len(parsed.get("signatures", [])),
                }
            )

        cls._print_source_inventory(source_inventory)
        return {"signatures": loaded_signatures, "source_inventory": source_inventory}

    @staticmethod
    def _print_source_inventory(source_inventory):
        print("Legacy Signatures:", flush=True)
        print("* 0 rules loaded", flush=True)
        print("Rule Packs:", flush=True)
        for rule_pack in source_inventory.get("rule_packs", []):
            print(
                f"* {rule_pack['path']} ({rule_pack['count']})",
                flush=True,
            )

    @classmethod
    def _fail_if_legacy_signatures_exist(cls):
        legacy_path = Path("signatures.yaml")
        if not legacy_path.exists():
            return
        parsed = cls.parse(
            legacy_path.read_text(encoding="utf-8"),
            source_name=legacy_path.name,
            allow_empty=True,
        )
        if parsed.get("signatures"):
            raise SignatureValidationError(
                "Legacy signatures.yaml contains rules. "
                "Migrate them into rules/*.yaml and remove signatures.yaml."
            )

    @classmethod
    def create_default_rule_packs(cls, rules_dir="rules"):
        rules_path = Path(rules_dir)
        rules_path.mkdir(parents=True, exist_ok=True)
        defaults = {
            "recon.yaml": {"signatures": [signature.copy() for signature in cls.DEFAULT_SIGNATURES]},
            "dns.yaml": {"signatures": []},
            "ad.yaml": {"signatures": []},
            "databases.yaml": {"signatures": []},
            "web.yaml": {"signatures": []},
            "browser.yaml": {"signatures": []},
        }
        for file_name in cls.RULE_PACK_NAMES:
            path = rules_path / file_name
            if not path.exists():
                path.write_text(
                    cls.to_yaml(defaults[file_name], allow_empty=True),
                    encoding="utf-8",
                )

    @classmethod
    def default_yaml(cls):
        return cls.to_yaml({"signatures": [signature.copy() for signature in cls.DEFAULT_SIGNATURES]})

    @classmethod
    def parse(cls, text, source_name="rule pack", allow_empty=False):
        root = _SimpleYamlParser(text).parse()
        if "signatures" not in root:
            raise SignatureValidationError(f"{source_name} must contain a signatures section.")
        cls.validate(root, source_name=source_name, allow_empty=allow_empty)
        return root

    @classmethod
    def to_yaml(cls, config, allow_empty=False):
        cls.validate(config, allow_empty=allow_empty)
        lines = ["signatures:"]
        for signature in config["signatures"]:
            lines.append(f"  - name: {cls._format_scalar(signature['name'])}")
            lines.append(f"    enabled: {cls._format_scalar(signature.get('enabled', True))}")
            lines.append(f"    event: {cls._format_scalar(signature.get('event') or cls._infer_event_type(signature))}")
            if signature.get("tags"):
                lines.append("    tags:")
                for tag in signature["tags"]:
                    lines.append(f"      - {cls._format_scalar(tag)}")
            if "group_by" in signature:
                lines.append(f"    group_by: {cls._format_scalar(signature['group_by'])}")
            if "cooldown_seconds" in signature:
                lines.append(f"    cooldown_seconds: {cls._format_scalar(signature['cooldown_seconds'])}")
            match = signature.get("match", {})
            if match:
                lines.append("    match:")
                cls._append_mapping(lines, match, indent=6)
            exclude = signature.get("exclude", {})
            if exclude:
                lines.append("    exclude:")
                cls._append_mapping(lines, exclude, indent=6)
            aggregate = signature["aggregate"]
            lines.append("    aggregate:")
            for aggregate_name in [key for key in aggregate if key != "within_seconds"]:
                lines.append(f"      {aggregate_name}:")
                cls._append_mapping(lines, aggregate[aggregate_name], indent=8)
            lines.append(f"      within_seconds: {cls._format_scalar(aggregate['within_seconds'])}")
            lines.append("    alert:")
            alert = signature["alert"]
            for key in ("severity", "title", "description"):
                lines.append(f"      {key}: {cls._format_scalar(alert[key])}")
        return "\n".join(lines) + "\n"

    @classmethod
    def _append_mapping(cls, lines, mapping, indent):
        spaces = " " * indent
        for key, value in mapping.items():
            if isinstance(value, dict):
                lines.append(f"{spaces}{key}:")
                cls._append_mapping(lines, value, indent + 2)
            elif isinstance(value, list):
                lines.append(f"{spaces}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first_key = next(iter(item))
                        first_value = item[first_key]
                        if isinstance(first_value, dict):
                            lines.append(f"{spaces}  - {first_key}:")
                            cls._append_mapping(lines, first_value, indent + 4)
                        else:
                            lines.append(f"{spaces}  - {first_key}: {cls._format_scalar(first_value)}")
                        remaining = {
                            item_key: item_value
                            for item_key, item_value in item.items()
                            if item_key != first_key
                        }
                        if remaining:
                            cls._append_mapping(lines, remaining, indent + 4)
                    else:
                        lines.append(f"{spaces}  - {cls._format_scalar(item)}")
            else:
                lines.append(f"{spaces}{key}: {cls._format_scalar(value)}")

    @staticmethod
    def _format_scalar(value):
        if value is True:
            return "true"
        if value is False:
            return "false"
        return str(value)

    @classmethod
    def validate(cls, config, source_name="rule pack", allow_empty=False):
        signatures = config.get("signatures")
        if not isinstance(signatures, list):
            raise SignatureValidationError(f"{source_name} signatures section must be a list.")
        if not signatures and not allow_empty:
            raise SignatureValidationError(f"{source_name} must contain at least one signature.")

        for index, signature in enumerate(signatures, start=1):
            name = signature.get("name", f"Signature {index}")
            if not isinstance(signature, dict):
                raise SignatureValidationError(f"Rule '{name}': signature must be a mapping.")
            if "alert" not in signature:
                raise SignatureValidationError(f"Rule '{name}': Missing alert section.")
            if "aggregate" not in signature:
                raise SignatureValidationError(f"Rule '{name}': Missing aggregate section.")
            if "cooldown_seconds" in signature and (
                not isinstance(signature["cooldown_seconds"], int)
                or signature["cooldown_seconds"] <= 0
            ):
                raise SignatureValidationError(
                    f"Rule '{name}': cooldown_seconds must be a positive integer."
                )
            if "group_by" in signature and signature["group_by"] not in {"src_ip", "dst_ip"}:
                raise SignatureValidationError(
                    f"Rule '{name}': group_by must be one of: src_ip, dst_ip."
                )
            if "tags" in signature and not (
                isinstance(signature["tags"], list)
                and all(isinstance(tag, str) for tag in signature["tags"])
            ):
                raise SignatureValidationError(f"Rule '{name}': tags must be a list of strings.")

            event_type = signature.get("event") or cls._infer_event_type(signature)
            if event_type not in {"packet", "dns"}:
                raise SignatureValidationError(f"Rule '{name}': Unknown event type '{event_type}'.")

            cls._validate_match(name, event_type, signature.get("match", {}))
            cls._validate_exclude(name, event_type, signature.get("exclude", {}))
            cls._validate_aggregate(name, event_type, signature["aggregate"])
            cls._validate_alert(name, signature["alert"])
        return config

    @classmethod
    def compile(cls, config):
        cls.validate(config, allow_empty=True)
        rules = []
        for signature in config["signatures"]:
            if not signature.get("enabled", True):
                continue
            rules.append(CompiledSignature.from_config(signature))
        return rules

    def process_packet(self, packet_info):
        self._process("packet", packet_info)

    def process_dns_query(self, dns_info):
        if self.DEBUG_DNS_EVENTS:
            print("[ERL DEBUG] DNS Event:", flush=True)
            print(json.dumps(dns_info, indent=2, sort_keys=True, default=str), flush=True)
        self._process("dns", dns_info)

    def _process(self, event_type, event):
        for rule in self.rules:
            if rule.event_type == event_type:
                rule.process(
                    event,
                    self.database,
                    debug_rules=self.DEBUG_RULES and event_type == "dns",
                    debug_alerts=self.DEBUG_ALERTS and event_type == "dns",
                )

    @classmethod
    def _validate_match(cls, name, event_type, match):
        if not isinstance(match, dict):
            raise SignatureValidationError(f"Rule '{name}': match must be a mapping.")

        allowed_fields = cls.PACKET_FIELDS if event_type == "packet" else cls.DNS_FIELDS
        for field, condition in match.items():
            if field in {"any", "all"}:
                cls._validate_logic_match(name, event_type, field, condition)
                continue
            if field == "not":
                cls._validate_not_match(name, event_type, condition)
                continue
            if field not in allowed_fields:
                raise SignatureValidationError(f"Rule '{name}': Unknown match field '{field}'.")
            cls._validate_match_condition(name, field, condition)

    @classmethod
    def _validate_logic_match(cls, name, event_type, operator, condition):
        if not isinstance(condition, list) or not condition:
            raise SignatureValidationError(
                f"Rule '{name}': {operator} must contain at least one match clause."
            )
        for clause in condition:
            if not isinstance(clause, dict) or not clause:
                raise SignatureValidationError(
                    f"Rule '{name}': {operator} entries must be match mappings."
                )
            if "any" in clause or "all" in clause:
                raise SignatureValidationError(
                    f"Rule '{name}': nested any/all blocks are not supported."
                )
            cls._validate_match(name, event_type, clause)

    @classmethod
    def _validate_not_match(cls, name, event_type, condition):
        if not isinstance(condition, dict) or not condition:
            raise SignatureValidationError(f"Rule '{name}': not must be a match mapping.")
        if cls._match_contains_not(condition):
            raise SignatureValidationError(f"Rule '{name}': nested not blocks are not supported.")
        cls._validate_match(name, event_type, condition)

    @classmethod
    def _validate_match_condition(cls, name, field, condition):
        if isinstance(condition, dict):
            for operator in condition:
                if operator not in cls.MATCH_OPERATORS:
                    raise SignatureValidationError(
                        f"Rule '{name}': Unknown match operator '{operator}'."
                    )
            if "in_networks" in condition:
                for network in condition["in_networks"]:
                    try:
                        ip_network(str(network), strict=False)
                    except ValueError:
                        raise SignatureValidationError(
                            f"Rule '{name}': Invalid network '{network}'."
                        )
            if "in" in condition and (
                not isinstance(condition["in"], list) or not condition["in"]
            ):
                raise SignatureValidationError(
                    f"Rule '{name}': match operator 'in' requires a non-empty list."
                )
            for operator in {"contains_any", "endswith_any"} & set(condition):
                if not isinstance(condition[operator], list) or not condition[operator]:
                    raise SignatureValidationError(
                        f"Rule '{name}': match operator '{operator}' requires a non-empty list."
                    )
            for operator in {"contains", "endswith", "startswith", "regex"} & set(condition):
                if not isinstance(condition[operator], str) or condition[operator] == "":
                    raise SignatureValidationError(
                        f"Rule '{name}': match operator '{operator}' requires a non-empty string."
                    )
            for operator in {"gt", "gte", "lt", "lte"} & set(condition):
                if not cls._is_number(condition[operator]):
                    raise SignatureValidationError(
                        f"Rule '{name}': match operator '{operator}' requires a number."
                    )
            if "regex" in condition:
                try:
                    re.compile(condition["regex"], re.IGNORECASE)
                except re.error as error:
                    raise SignatureValidationError(
                        f"Rule '{name}': Invalid regex '{condition['regex']}': {error}."
                    )

    @classmethod
    def _validate_exclude(cls, name, event_type, exclude):
        if not exclude:
            return
        if not isinstance(exclude, dict):
            raise SignatureValidationError(f"Rule '{name}': exclude must be a mapping.")

        allowed_fields = cls.PACKET_FIELDS if event_type == "packet" else cls.DNS_FIELDS
        for field, values in exclude.items():
            if field not in allowed_fields:
                raise SignatureValidationError(
                    f"Rule '{name}': Unknown exclude field '{field}'."
                )
            if not isinstance(values, list) or not values:
                raise SignatureValidationError(
                    f"Rule '{name}': exclude field '{field}' must be a non-empty list."
                )
            if field in {"src_ip", "dst_ip", "client_ip", "dns_server_ip"}:
                for value in values:
                    try:
                        if "/" in str(value):
                            ip_network(str(value), strict=False)
                        else:
                            ip_address(str(value))
                    except ValueError:
                        raise SignatureValidationError(
                            f"Rule '{name}': Invalid exclude IP or network '{value}'."
                        )

    @classmethod
    def _validate_aggregate(cls, name, event_type, aggregate):
        if not isinstance(aggregate, dict):
            raise SignatureValidationError(f"Rule '{name}': aggregate must be a mapping.")
        aggregate_names = [key for key in aggregate if key != "within_seconds"]
        if not aggregate_names:
            raise SignatureValidationError(f"Rule '{name}': Missing aggregate threshold.")
        for aggregate_name in aggregate_names:
            if aggregate_name not in cls.AGGREGATES:
                raise SignatureValidationError(
                    f"Rule '{name}': Unknown aggregate '{aggregate_name}'."
                )
            if event_type == "dns" and aggregate_name in {"unique_dst_ips", "unique_dst_ports"}:
                raise SignatureValidationError(
                    f"Rule '{name}': Aggregate '{aggregate_name}' is only valid for packet events."
                )
            if event_type == "packet" and aggregate_name == "unique_domains":
                raise SignatureValidationError(
                    f"Rule '{name}': Aggregate 'unique_domains' is only valid for DNS events."
                )

            threshold = aggregate.get(aggregate_name)
            if not isinstance(threshold, dict):
                raise SignatureValidationError(f"Rule '{name}': Missing aggregate threshold.")
            for operator in threshold:
                if operator not in cls.AGGREGATE_OPERATORS:
                    raise SignatureValidationError(
                        f"Rule '{name}': Unknown aggregate operator '{operator}'."
                    )
            if "gte" not in threshold:
                raise SignatureValidationError(f"Rule '{name}': Missing aggregate threshold.")
            if not isinstance(threshold["gte"], int) or threshold["gte"] <= 0:
                raise SignatureValidationError(f"Rule '{name}': Aggregate gte must be a positive integer.")
        if "within_seconds" not in aggregate:
            raise SignatureValidationError(f"Rule '{name}': Missing within_seconds.")
        if not isinstance(aggregate["within_seconds"], int) or aggregate["within_seconds"] <= 0:
            raise SignatureValidationError(f"Rule '{name}': within_seconds must be a positive integer.")

    @classmethod
    def _validate_alert(cls, name, alert):
        if not isinstance(alert, dict):
            raise SignatureValidationError(f"Rule '{name}': alert must be a mapping.")
        for field in ("severity", "title", "description"):
            if field not in alert:
                raise SignatureValidationError(f"Rule '{name}': alert is missing '{field}'.")
        if alert["severity"] not in cls.SEVERITIES:
            raise SignatureValidationError(
                f"Rule '{name}': Unknown alert severity '{alert['severity']}'."
            )

    @classmethod
    def _infer_event_type(cls, signature):
        match = signature.get("match", {})
        aggregate = signature.get("aggregate", {})
        if "unique_domains" in aggregate:
            return "dns"
        if cls._match_references_dns_fields(match):
            return "dns"
        return "packet"

    @classmethod
    def _match_references_dns_fields(cls, match):
        if not isinstance(match, dict):
            return False
        for field, condition in match.items():
            if field in cls.DNS_FIELDS:
                return True
            if field == "not" and cls._match_references_dns_fields(condition):
                return True
            if field in {"any", "all"} and isinstance(condition, list):
                if any(cls._match_references_dns_fields(clause) for clause in condition):
                    return True
        return False

    @classmethod
    def _match_contains_not(cls, match):
        if not isinstance(match, dict):
            return False
        for field, condition in match.items():
            if field == "not":
                return True
            if field in {"any", "all"} and isinstance(condition, list):
                if any(cls._match_contains_not(clause) for clause in condition):
                    return True
        return False

    @staticmethod
    def _is_number(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool)


@dataclass
class CompiledSignature:
    name: str
    rule_pack: str
    event_type: str
    tags: list
    group_by: str | None
    matchers: list
    exclude_matchers: list
    aggregate_thresholds: dict
    within_seconds: int
    cooldown_seconds: int
    alert: dict

    def __post_init__(self):
        self.events_by_key = defaultdict(deque)
        self.alerted_keys = set()
        self.last_alert_times = {}
        self.processed_events = 0

    @classmethod
    def from_config(cls, signature):
        aggregate = signature["aggregate"]
        return cls(
            name=signature["name"],
            rule_pack=signature.get("_rule_pack", "rules/*.yaml"),
            event_type=signature.get("event") or SignatureEngine._infer_event_type(signature),
            tags=list(signature.get("tags", [])),
            group_by=signature.get("group_by"),
            matchers=compile_matchers(signature.get("match", {})),
            exclude_matchers=compile_exclude_matchers(signature.get("exclude", {})),
            aggregate_thresholds={
                aggregate_name: aggregate[aggregate_name]["gte"]
                for aggregate_name in aggregate
                if aggregate_name != "within_seconds"
            },
            within_seconds=aggregate["within_seconds"],
            cooldown_seconds=signature.get("cooldown_seconds", 0),
            alert=signature["alert"],
        )

    def process(self, event, database, debug_rules=False, debug_alerts=False):
        if debug_rules:
            print(
                f"[ERL DEBUG] Evaluating Rule='{self.name}'",
                flush=True,
            )
            print(
                f"[ERL DEBUG] query_name='{event.get('query_name')}'",
                flush=True,
            )
        matched = self._matches_event(event, debug_rules)
        if debug_rules:
            print(f"[ERL DEBUG] matched={matched}", flush=True)
        if not matched:
            return
        if debug_alerts:
            print(f"[ERL DEBUG] Rule matched: {self.name}", flush=True)
        if any(matcher.matches(event) for matcher in self.exclude_matchers):
            if debug_alerts:
                self._debug_alert_decision(
                    alert_suppressed=True,
                    cooldown_active=False,
                    creating_alert=False,
                    reason="AlertSuppressed",
                )
            return

        timestamp = _parse_timestamp(event.get("timestamp"))
        key = self._source_key(event)
        entries = self.events_by_key[key]
        entries.append((timestamp, self._aggregate_value(event)))
        self._prune(entries, timestamp)
        if debug_alerts:
            self._debug_aggregate_state(entries)
        self.processed_events += 1
        if self.processed_events % 1000 == 0:
            self._prune_all(timestamp)

        if self._thresholds_satisfied(entries):
            context = self._alert_context(entries)
            database.record_rule_hit(self.name, timestamp.isoformat())
            if self.cooldown_seconds > 0:
                last_alert_time = self.last_alert_times.get(key)
                if (
                    last_alert_time is not None
                    and timestamp.timestamp() - last_alert_time.timestamp() < self.cooldown_seconds
                ):
                    if debug_alerts:
                        self._debug_alert_decision(
                            alert_suppressed=True,
                            cooldown_active=True,
                            creating_alert=False,
                            reason="CooldownActive",
                        )
                    return
            elif key in self.alerted_keys:
                if debug_alerts:
                    self._debug_alert_decision(
                        alert_suppressed=True,
                        cooldown_active=False,
                        creating_alert=False,
                        reason="AlreadyTriggered",
                    )
                return
            if debug_alerts:
                self._debug_alert_decision(
                    alert_suppressed=False,
                    cooldown_active=False,
                    creating_alert=True,
                )
            self.alerted_keys.add(key)
            self.last_alert_times[key] = timestamp
            database.record_rule_alert(self.name, timestamp.isoformat())
            database.create_alert(
                timestamp.isoformat(),
                self.alert["severity"],
                self.alert["title"],
                self.alert["description"],
                source_ip=self._alert_source_ip(event),
                destination_ip=self._alert_destination_ip(event),
                context=context,
            )
            if debug_alerts:
                print("[ERL DEBUG] AlertCreated=True", flush=True)
        else:
            if debug_alerts:
                self._debug_alert_decision(
                    alert_suppressed=False,
                    cooldown_active=False,
                    creating_alert=False,
                    reason="ThresholdNotMet",
                )
            if key in self.alerted_keys:
                self.alerted_keys.remove(key)

    def _matches_event(self, event, debug_rules=False):
        if not debug_rules:
            return all(matcher.matches(event) for matcher in self.matchers)
        results = []
        for matcher in self.matchers:
            result = matcher.matches(event)
            results.append(result)
            matcher.debug_match(event, self.name, result)
        return all(results)

    def _debug_aggregate_state(self, entries):
        for aggregate_name, threshold in self.aggregate_thresholds.items():
            current_count = self._current_count(entries, aggregate_name)
            aggregate_satisfied = current_count >= threshold
            print(f"[ERL DEBUG] Aggregate={aggregate_name}", flush=True)
            print(f"[ERL DEBUG] CurrentCount={current_count}", flush=True)
            print(f"[ERL DEBUG] Threshold={threshold}", flush=True)
            print(f"[ERL DEBUG] AggregateSatisfied={aggregate_satisfied}", flush=True)

    def _debug_alert_decision(
        self,
        alert_suppressed,
        cooldown_active,
        creating_alert,
        reason=None,
    ):
        print(f"[ERL DEBUG] AlertSuppressed={alert_suppressed}", flush=True)
        print(f"[ERL DEBUG] CooldownActive={cooldown_active}", flush=True)
        print(f"[ERL DEBUG] CreatingAlert={creating_alert}", flush=True)
        if reason:
            print(f"[ERL DEBUG] Reason={reason}", flush=True)

    def _source_key(self, event):
        if self.group_by == "src_ip":
            return event.get("client_ip") if self.event_type == "dns" else event.get("src_ip")
        if self.group_by == "dst_ip":
            return event.get("dns_server_ip") if self.event_type == "dns" else event.get("dst_ip")
        if self.event_type == "dns":
            return event.get("client_ip")
        return event.get("src_ip")

    def _aggregate_value(self, event):
        return {
            "unique_dst_ips": event.get("dst_ip"),
            "unique_dst_ports": event.get("dst_port"),
            "unique_domains": str(event.get("query_name", "")).strip().rstrip(".").lower(),
        }

    def _prune(self, entries, now):
        cutoff = now.timestamp() - self.within_seconds
        while entries and entries[0][0].timestamp() < cutoff:
            entries.popleft()

    def _prune_all(self, now):
        for key in list(self.events_by_key):
            entries = self.events_by_key[key]
            self._prune(entries, now)
            if not entries:
                del self.events_by_key[key]
                self.alerted_keys.discard(key)

    def _thresholds_satisfied(self, entries):
        return all(
            self._current_count(entries, aggregate_name) >= threshold
            for aggregate_name, threshold in self.aggregate_thresholds.items()
        )

    def _current_count(self, entries, aggregate_name):
        if aggregate_name == "count":
            return len(entries)
        return len(
            {
                values.get(aggregate_name)
                for _, values in entries
                if values.get(aggregate_name) is not None
            }
        )

    def _alert_context(self, entries):
        observed = {}
        if self.group_by:
            observed["group_by"] = self.group_by
        for aggregate_name in self.aggregate_thresholds:
            observed[aggregate_name] = self._current_count(entries, aggregate_name)
        return {
            "rule": {
                "name": self.name,
                "pack": self.rule_pack,
                "tags": list(self.tags),
                "event_type": self.event_type,
                "thresholds": dict(self.aggregate_thresholds),
                "window_seconds": self.within_seconds,
            },
            "evidence": {
                "observed": observed,
                "thresholds": dict(self.aggregate_thresholds),
                "window_seconds": self.within_seconds,
            },
        }

    def _alert_source_ip(self, event):
        if self.event_type == "dns":
            return event.get("client_ip")
        if self.group_by == "dst_ip":
            return None
        return event.get("src_ip")

    def _alert_destination_ip(self, event):
        if self.event_type == "dns":
            return event.get("dns_server_ip")
        if self.group_by == "src_ip":
            return None
        return event.get("dst_ip")


def compile_matchers(match):
    matchers = []
    for field, condition in match.items():
        if field == "any":
            matchers.append(LogicMatcher("any", [compile_matchers(clause) for clause in condition]))
        elif field == "all":
            matchers.append(LogicMatcher("all", [compile_matchers(clause) for clause in condition]))
        elif field == "not":
            matchers.append(NotMatcher(compile_matchers(condition)))
        else:
            matchers.extend(FieldMatcher.compile_all(field, condition))
    return matchers


def compile_exclude_matchers(exclude):
    matchers = []
    for field, values in exclude.items():
        matchers.append(ExcludeMatcher(field, values))
    return matchers


class LogicMatcher:
    def __init__(self, operator, matcher_groups):
        self.operator = operator
        self.matcher_groups = matcher_groups

    def matches(self, event):
        group_results = [
            all(matcher.matches(event) for matcher in matcher_group)
            for matcher_group in self.matcher_groups
        ]
        if self.operator == "all":
            return all(group_results)
        return any(group_results)

    def debug_match(self, event, rule_name, result):
        print(f"[ERL DEBUG] Rule='{rule_name}'", flush=True)
        print(f"[ERL DEBUG] Operator='{self.operator}'", flush=True)
        print(f"[ERL DEBUG] Result={result}", flush=True)
        for matcher_group in self.matcher_groups:
            for matcher in matcher_group:
                matcher.debug_match(event, rule_name, matcher.matches(event))


class NotMatcher:
    def __init__(self, matchers):
        self.matchers = matchers

    def matches(self, event):
        return not all(matcher.matches(event) for matcher in self.matchers)

    def debug_match(self, event, rule_name, result):
        print(f"[ERL DEBUG] Rule='{rule_name}'", flush=True)
        print("[ERL DEBUG] Operator='not'", flush=True)
        print(f"[ERL DEBUG] Result={result}", flush=True)
        for matcher in self.matchers:
            matcher.debug_match(event, rule_name, matcher.matches(event))


class FieldMatcher:
    def __init__(self, field, operator, expected):
        self.field = field
        self.operator = operator
        self.expected = expected
        if SignatureEngine.DEBUG_RULES:
            print(
                "FieldMatcher("
                f"field={field}, "
                f"operator={operator}, "
                f"expected={repr(expected)}"
                ")",
                flush=True,
            )

    @classmethod
    def compile_all(cls, field, condition):
        if isinstance(condition, dict):
            matchers = []
            if "in" in condition:
                matchers.append(cls(field, "in", set(condition["in"])))
            if "in_networks" in condition:
                matchers.append(
                    cls(
                        field,
                        "in_networks",
                        [ip_network(str(network), strict=False) for network in condition["in_networks"]],
                    )
                )
            for operator in (
                "contains",
                "contains_any",
                "endswith",
                "endswith_any",
                "gt",
                "gte",
                "lt",
                "lte",
                "regex",
                "startswith",
            ):
                if operator in condition:
                    expected = condition[operator]
                    if operator == "regex":
                        expected = re.compile(expected, re.IGNORECASE)
                    matchers.append(cls(field, operator, expected))
            return matchers
        return [cls(field, "eq", condition)]

    def matches(self, event):
        value = event.get(self.field)
        if self.operator == "eq":
            return self._normalize(value) == self._normalize(self.expected)
        if self.operator == "in":
            return self._normalize(value) in {self._normalize(item) for item in self.expected}
        if self.operator == "in_networks":
            try:
                parsed_ip = ip_address(str(value))
            except ValueError:
                return False
            return any(parsed_ip in network for network in self.expected)
        if self.operator == "contains":
            normalized_expected = self._normalize(self.expected)
            normalized_value = self._normalize(value)
            result = normalized_expected in normalized_value
            if SignatureEngine.DEBUG_RULES:
                print(f"[ERL DEBUG] contains value type={type(value)}", flush=True)
                print(f"[ERL DEBUG] contains value repr={repr(value)}", flush=True)
                print(f"[ERL DEBUG] contains expected type={type(self.expected)}", flush=True)
                print(f"[ERL DEBUG] contains expected repr={repr(self.expected)}", flush=True)
                print(
                    f"[ERL DEBUG] contains normalized_expected repr={repr(normalized_expected)}",
                    flush=True,
                )
                print(
                    f"[ERL DEBUG] contains normalized_value repr={repr(normalized_value)}",
                    flush=True,
                )
                print(f"[ERL DEBUG] contains result={result}", flush=True)
            return result
        if self.operator == "contains_any":
            normalized_value = self._normalize(value)
            return any(self._normalize(item) in normalized_value for item in self.expected)
        if self.operator == "endswith":
            return self._normalize(value).endswith(self._normalize(self.expected))
        if self.operator == "endswith_any":
            normalized_value = self._normalize(value)
            return any(normalized_value.endswith(self._normalize(item)) for item in self.expected)
        if self.operator == "startswith":
            return self._normalize(value).startswith(self._normalize(self.expected))
        if self.operator == "regex":
            return self.expected.search(str(value or "")) is not None
        if self.operator == "gt":
            return self._compare_number(value, lambda actual, expected: actual > expected)
        if self.operator == "gte":
            return self._compare_number(value, lambda actual, expected: actual >= expected)
        if self.operator == "lt":
            return self._compare_number(value, lambda actual, expected: actual < expected)
        if self.operator == "lte":
            return self._compare_number(value, lambda actual, expected: actual <= expected)
        return False

    def debug_match(self, event, rule_name, result):
        print(f"[ERL DEBUG] Rule='{rule_name}'", flush=True)
        print(f"[ERL DEBUG] Field='{self.field}'", flush=True)
        print(f"[ERL DEBUG] Operator='{self.operator}'", flush=True)
        print(f"[ERL DEBUG] Expected='{self._debug_expected()}'", flush=True)
        print(f"[ERL DEBUG] Actual='{event.get(self.field)}'", flush=True)
        print(f"[ERL DEBUG] Result={result}", flush=True)

    def _normalize(self, value):
        if isinstance(value, str):
            return value.upper()
        return str(value).upper()

    def _compare_number(self, value, comparator):
        try:
            return comparator(float(value), float(self.expected))
        except (TypeError, ValueError):
            return False

    def _debug_expected(self):
        if self.operator == "regex":
            return self.expected.pattern
        return self.expected


class ExcludeMatcher:
    def __init__(self, field, values):
        self.field = field
        self.values = values
        self.networks = []
        self.exact_values = set()
        for value in values:
            if field in {"src_ip", "dst_ip", "client_ip", "dns_server_ip"} and "/" in str(value):
                self.networks.append(ip_network(str(value), strict=False))
            else:
                self.exact_values.add(self._normalize(value))

    def matches(self, event):
        value = event.get(self.field)
        if value is None:
            return False
        normalized_value = self._normalize(value)
        if normalized_value in self.exact_values:
            return True
        if self.networks:
            try:
                parsed_ip = ip_address(str(value))
            except ValueError:
                return False
            return any(parsed_ip in network for network in self.networks)
        return False

    def _normalize(self, value):
        if isinstance(value, str):
            return value.upper()
        return value


class _SimpleYamlParser:
    def __init__(self, text):
        self.lines = []
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].rstrip()
            if line.strip():
                self.lines.append((len(line) - len(line.lstrip(" ")), line.strip()))
        self.index = 0

    def parse(self):
        result = {}
        while self.index < len(self.lines):
            indent, stripped = self.lines[self.index]
            if indent != 0 or not stripped.endswith(":"):
                raise SignatureValidationError("Invalid rule pack structure.")
            key = stripped[:-1]
            self.index += 1
            if key == "signatures":
                result[key] = self._parse_list(indent + 2)
            else:
                result[key] = self._parse_mapping(indent + 2)
        return result

    def _parse_list(self, indent):
        items = []
        while self.index < len(self.lines):
            current_indent, stripped = self.lines[self.index]
            if current_indent < indent:
                break
            if current_indent != indent or not stripped.startswith("- "):
                raise SignatureValidationError("Invalid list item in rule pack.")
            item = {}
            remainder = stripped[2:].strip()
            self.index += 1
            if remainder:
                key, value = self._split_key_value(remainder)
                item[key] = self._parse_scalar(value)
            item.update(self._parse_mapping(indent + 2))
            items.append(item)
        return items

    def _parse_mapping(self, indent):
        mapping = {}
        while self.index < len(self.lines):
            current_indent, stripped = self.lines[self.index]
            if current_indent < indent:
                break
            if current_indent > indent:
                raise SignatureValidationError("Invalid indentation in rule pack.")
            key, value = self._split_key_value(stripped)
            self.index += 1
            if value == "":
                next_indent, next_stripped = self.lines[self.index] if self.index < len(self.lines) else (0, "")
                if next_indent == indent + 2 and next_stripped.startswith("- "):
                    mapping[key] = self._parse_list_values(indent + 2)
                else:
                    mapping[key] = self._parse_mapping(indent + 2)
            else:
                mapping[key] = self._parse_scalar(value)
        return mapping

    def _parse_list_values(self, indent):
        values = []
        while self.index < len(self.lines):
            current_indent, stripped = self.lines[self.index]
            if current_indent < indent:
                break
            if current_indent != indent or not stripped.startswith("- "):
                raise SignatureValidationError("Invalid scalar list in rule pack.")
            item = stripped[2:].strip()
            self.index += 1
            if ": " in item or item.endswith(":"):
                key, value = self._split_key_value(item)
                mapping = {key: self._parse_scalar(value)} if value else {key: self._parse_mapping(indent + 2)}
                if self.index < len(self.lines) and self.lines[self.index][0] == indent + 2:
                    mapping.update(self._parse_mapping(indent + 2))
                values.append(mapping)
            else:
                values.append(self._parse_scalar(item))
        return values

    def _split_key_value(self, text):
        if ":" not in text:
            raise SignatureValidationError("Invalid key/value entry in rule pack.")
        key, value = text.split(":", 1)
        return key.strip(), value.strip()

    def _parse_scalar(self, value):
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            if not inner:
                return []
            return [self._parse_scalar(item.strip()) for item in inner.split(",")]
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            return self._parse_quoted_scalar(value)
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        try:
            return int(value)
        except ValueError:
            return value

    def _parse_quoted_scalar(self, value):
        quote = value[0]
        inner = value[1:-1]
        if quote == "'":
            return inner.replace("''", "'")

        escapes = {
            "0": "\0",
            '"': '"',
            "\\": "\\",
            "/": "/",
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
        }
        result = []
        index = 0
        while index < len(inner):
            character = inner[index]
            if character != "\\":
                result.append(character)
                index += 1
                continue
            index += 1
            if index >= len(inner):
                result.append("\\")
                break
            escaped = inner[index]
            if escaped in escapes:
                result.append(escapes[escaped])
            else:
                result.append("\\" + escaped)
            index += 1
        return "".join(result)


def _parse_timestamp(value):
    if not value:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed
