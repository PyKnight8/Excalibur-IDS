from pathlib import Path


class RulesConfig:
    DEFAULT_GLOBAL = {
        "exclude_own_ips": True,
        "excluded_sources": [""] #["192.168.x.x"], # exclusions
    }
    DEFAULT_RULES = [
        {
            "name": "Port Scan",
            "type": "portscan",
            "enabled": True,
            "threshold": 20,
            "window_seconds": 60,
            "cooldown_seconds": 300,
            "severity": "Medium",
        },
        {
            "name": "DNS Flood",
            "type": "dns_flood",
            "enabled": True,
            "threshold": 500,
            "window_seconds": 60,
            "cooldown_seconds": 300,
            "severity": "Medium",
        },
        {
            "name": "Excessive Unique Domains",
            "type": "unique_domains",
            "enabled": True,
            "threshold": 100,
            "window_seconds": 60,
            "cooldown_seconds": 300,
            "severity": "Medium",
        },
        {
            "name": "Internal Host Sweep",
            "type": "host_sweep",
            "enabled": True,
            "threshold": 20,
            "window_seconds": 60,
            "cooldown_seconds": 300,
            "severity": "Medium",
        },
    ]

    @classmethod
    def load(cls, path="rules.yaml"):
        rules_path = Path(path)
        if not rules_path.exists():
            cls.create_default(rules_path)
            return cls.default_config()
        return cls.parse(rules_path.read_text(encoding="utf-8"))

    @classmethod
    def default_config(cls):
        return {
            "global": {
                "exclude_own_ips": cls.DEFAULT_GLOBAL["exclude_own_ips"],
                "excluded_sources": list(cls.DEFAULT_GLOBAL["excluded_sources"]),
            },
            "rules": [rule.copy() for rule in cls.DEFAULT_RULES],
        }

    @classmethod
    def parse(cls, text):
        config = cls.default_config()
        config["rules"] = []
        current_section = None
        current_list = None
        current_rule = None

        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].rstrip()
            if not line.strip():
                continue

            stripped = line.strip()
            if not line.startswith(" ") and stripped.endswith(":"):
                if current_rule:
                    config["rules"].append(current_rule)
                    current_rule = None
                current_section = stripped[:-1]
                current_list = None
                continue

            if current_section == "global":
                if stripped.endswith(":"):
                    key = stripped[:-1]
                    if key == "excluded_sources":
                        config["global"]["excluded_sources"] = []
                        current_list = "global.excluded_sources"
                    continue
                if current_list == "global.excluded_sources" and stripped.startswith("- "):
                    config["global"]["excluded_sources"].append(stripped[2:].strip())
                    continue
                if ":" in stripped:
                    key, value = stripped.split(":", 1)
                    config["global"][key.strip()] = cls._parse_scalar(value.strip())
                continue

            if current_section == "rules":
                if stripped.startswith(("- ", "* ")):
                    if current_rule:
                        config["rules"].append(current_rule)
                    current_rule = {}
                    item = stripped[2:].strip()
                    if ":" in item:
                        key, value = item.split(":", 1)
                        current_rule[key.strip()] = cls._parse_scalar(value.strip())
                    continue
                if current_rule is not None and ":" in stripped:
                    key, value = stripped.split(":", 1)
                    current_rule[key.strip()] = cls._parse_scalar(value.strip())

        if current_rule:
            config["rules"].append(current_rule)
        if not config["rules"]:
            raise ValueError("rules.yaml must contain at least one rule.")
        return config

    @classmethod
    def validate(cls, text):
        config = cls.parse(text)
        for index, rule in enumerate(config["rules"], start=1):
            if "type" not in rule:
                raise ValueError(f"Rule {index} is missing required field: type")
            if "enabled" in rule and not isinstance(rule["enabled"], bool):
                raise ValueError(f"Rule {index} field 'enabled' must be true or false")
        return config

    @classmethod
    def create_default(cls, path="rules.yaml"):
        Path(path).write_text(cls._default_yaml(), encoding="utf-8")

    @classmethod
    def _default_yaml(cls):
        lines = [
            "global:",
            "  exclude_own_ips: true",
            "  excluded_sources:",
        ]
        lines.extend(f"    - {source}" for source in cls.DEFAULT_GLOBAL["excluded_sources"])
        lines.extend(["", "rules:"])
        for rule in cls.DEFAULT_RULES:
            lines.extend(
                [
                    f"  - name: {rule['name']}",
                    f"    type: {rule['type']}",
                    f"    enabled: {str(rule['enabled']).lower()}",
                    f"    threshold: {rule['threshold']}",
                    f"    window_seconds: {rule['window_seconds']}",
                    f"    cooldown_seconds: {rule['cooldown_seconds']}",
                    f"    severity: {rule['severity']}",
                    "",
                ]
            )
        return "\n".join(lines).rstrip() + "\n"

    @classmethod
    def _parse_rules(cls, text):
        return cls.parse(text)["rules"]

    @staticmethod
    def _parse_scalar(value):
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        try:
            return int(value)
        except ValueError:
            return value
