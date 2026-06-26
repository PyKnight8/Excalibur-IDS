from pathlib import Path


class Config:
    DEFAULT_DATABASE_PATH = "excalibur.sqlite"
    TRAFFIC_MAX_RECORDS = 1000000
    SUPPORTED_TIMEZONES = [
        "UTC",
        "Asia/Amman",
        "Europe/London",
        "America/New_York",
    ]
    DEFAULT_CONFIG = {
        "general": {
            "timezone": "Asia/Amman",
        },
        "database": {
            "path": DEFAULT_DATABASE_PATH,
        },
        "portscan": {
            "enabled": True,
            "threshold": 20,
            "window_seconds": 60,
            "cooldown_seconds": 300,
            "excluded_sources": [],
        },
        "monitored_networks": [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ],
        "notifications": {
            "enabled": False,
            "desktop": {
                "enabled": False,
            },
            "ntfy": {
                "enabled": False,
                "url": "",
                "timeout_seconds": 5,
            },
        },
        "browser_threat_protection": {
            "enabled": True,
            "risk_threshold": 60,
            "suspicious_tlds": [
                "zip",
                "mov",
                "top",
                "xyz",
                "click",
                "icu",
                "cyou",
                "gq",
                "tk",
                "ml",
                "cf",
            ],
            "suspicious_keywords": [
                "login",
                "verify",
                "secure",
                "account",
                "update",
                "wallet",
                "reset",
            ],
        },
    }

    @classmethod
    def load(cls, path="config.yaml"):
        config_path = Path(path)
        if not config_path.exists():
            cls.create_default(config_path)
            return cls._default_config()

        text = config_path.read_text(encoding="utf-8")
        return cls._parse_yaml(text)

    @classmethod
    def save(cls, config, path="config.yaml"):
        config_path = Path(path)
        config_path.write_text(cls._to_yaml(config), encoding="utf-8")

    @classmethod
    def create_default(cls, path="config.yaml"):
        config_path = Path(path)
        config_path.write_text(cls._default_yaml(), encoding="utf-8")

    @classmethod
    def _default_config(cls):
        return {
            "general": cls.DEFAULT_CONFIG["general"].copy(),
            "database": cls.DEFAULT_CONFIG["database"].copy(),
            "portscan": cls.DEFAULT_CONFIG["portscan"].copy(),
            "monitored_networks": list(cls.DEFAULT_CONFIG["monitored_networks"]),
            "notifications": {
                "enabled": cls.DEFAULT_CONFIG["notifications"]["enabled"],
                "desktop": cls.DEFAULT_CONFIG["notifications"]["desktop"].copy(),
                "ntfy": cls.DEFAULT_CONFIG["notifications"]["ntfy"].copy(),
            },
            "browser_threat_protection": {
                "enabled": cls.DEFAULT_CONFIG["browser_threat_protection"]["enabled"],
                "risk_threshold": cls.DEFAULT_CONFIG["browser_threat_protection"]["risk_threshold"],
                "suspicious_tlds": list(
                    cls.DEFAULT_CONFIG["browser_threat_protection"]["suspicious_tlds"]
                ),
                "suspicious_keywords": list(
                    cls.DEFAULT_CONFIG["browser_threat_protection"]["suspicious_keywords"]
                ),
            },
        }

    @classmethod
    def _default_yaml(cls):
        return (
            "general:\n"
            "  timezone: Asia/Amman\n"
            "\n"
            "database:\n"
            f"  path: {cls.DEFAULT_DATABASE_PATH}\n"
            "\n"
            "portscan:\n"
            "  enabled: true\n"
            "  threshold: 20\n"
            "  window_seconds: 60\n"
            "  cooldown_seconds: 300\n"
            "  excluded_sources:\n"
            "\n"
            "monitored_networks:\n"
            "  - 10.0.0.0/8\n"
            "  - 172.16.0.0/12\n"
            "  - 192.168.0.0/16\n"
            "\n"
            "notifications:\n"
            "  enabled: false\n"
            "  desktop:\n"
            "    enabled: false\n"
            "  ntfy:\n"
            "    enabled: false\n"
            '    url: ""\n'
            "    timeout_seconds: 5\n"
            "\n"
            "browser_threat_protection:\n"
            "  enabled: true\n"
            "  risk_threshold: 60\n"
            "  suspicious_tlds:\n"
            "    - zip\n"
            "    - mov\n"
            "    - top\n"
            "    - xyz\n"
            "    - click\n"
            "    - icu\n"
            "    - cyou\n"
            "    - gq\n"
            "    - tk\n"
            "    - ml\n"
            "    - cf\n"
            "  suspicious_keywords:\n"
            "    - login\n"
            "    - verify\n"
            "    - secure\n"
            "    - account\n"
            "    - update\n"
            "    - wallet\n"
            "    - reset\n"
        )

    @classmethod
    def _parse_yaml(cls, text):
        config = cls._default_config()
        section = None
        list_section = None
        subsection = None

        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].rstrip()
            if not line.strip():
                continue

            stripped = line.strip()
            if not line.startswith(" ") and stripped.endswith(":"):
                section = stripped[:-1]
                list_section = section
                subsection = None
                if section == "monitored_networks":
                    config["monitored_networks"] = []
                continue

            if section == "portscan" and stripped.endswith(":"):
                key = stripped[:-1]
                if key == "excluded_sources":
                    config["portscan"]["excluded_sources"] = []
                    list_section = "portscan.excluded_sources"
                continue

            if section == "browser_threat_protection" and stripped.endswith(":"):
                key = stripped[:-1]
                if key in {"suspicious_tlds", "suspicious_keywords"}:
                    config["browser_threat_protection"][key] = []
                    list_section = f"browser_threat_protection.{key}"
                continue

            if section == "notifications" and line.startswith("  ") and not line.startswith("    ") and stripped.endswith(":"):
                subsection = stripped[:-1]
                continue

            if section == "general" and ":" in stripped:
                key, value = stripped.split(":", 1)
                config["general"][key.strip()] = cls._parse_scalar(value.strip())
                continue

            if section == "database" and ":" in stripped:
                key, value = stripped.split(":", 1)
                config["database"][key.strip()] = cls._parse_scalar(value.strip())
                continue

            if section == "portscan" and ":" in stripped:
                key, value = stripped.split(":", 1)
                config["portscan"][key.strip()] = cls._parse_scalar(value.strip())
                continue

            if section == "notifications" and ":" in stripped:
                key, value = stripped.split(":", 1)
                parsed_value = cls._parse_scalar(value.strip())
                if subsection in {"desktop", "ntfy"} and line.startswith("    "):
                    config["notifications"][subsection][key.strip()] = parsed_value
                elif line.startswith("  ") and not line.startswith("    "):
                    config["notifications"][key.strip()] = parsed_value
                continue

            if section == "browser_threat_protection" and ":" in stripped:
                key, value = stripped.split(":", 1)
                config["browser_threat_protection"][key.strip()] = cls._parse_scalar(value.strip())
                continue

            if list_section == "portscan.excluded_sources" and stripped.startswith("- "):
                config["portscan"]["excluded_sources"].append(stripped[2:].strip())
                continue

            if list_section == "monitored_networks" and stripped.startswith("- "):
                config["monitored_networks"].append(stripped[2:].strip())

            if list_section == "browser_threat_protection.suspicious_tlds" and stripped.startswith("- "):
                config["browser_threat_protection"]["suspicious_tlds"].append(stripped[2:].strip())
                continue

            if list_section == "browser_threat_protection.suspicious_keywords" and stripped.startswith("- "):
                config["browser_threat_protection"]["suspicious_keywords"].append(stripped[2:].strip())
                continue

        return config

    @classmethod
    def _to_yaml(cls, config):
        general = config.get("general", {})
        database = cls._merge_database(config.get("database", {}))
        portscan = config.get("portscan", {})
        monitored_networks = config.get("monitored_networks", [])
        notifications = cls._merge_notifications(config.get("notifications", {}))
        browser_threats = cls._merge_browser_threat_protection(
            config.get("browser_threat_protection", {})
        )
        lines = [
            "general:",
            f"  timezone: {general.get('timezone', cls.DEFAULT_CONFIG['general']['timezone'])}",
            "",
            "database:",
            f"  path: {database.get('path', cls.DEFAULT_DATABASE_PATH)}",
            "",
            "portscan:",
            f"  enabled: {str(portscan.get('enabled', True)).lower()}",
            f"  threshold: {portscan.get('threshold', 20)}",
            f"  window_seconds: {portscan.get('window_seconds', 60)}",
            f"  cooldown_seconds: {portscan.get('cooldown_seconds', 300)}",
            "  excluded_sources:",
        ]
        lines.extend(f"    - {source}" for source in portscan.get("excluded_sources", []))
        lines.extend([
            "",
            "monitored_networks:",
        ])
        lines.extend(f"  - {network}" for network in monitored_networks)
        lines.extend([
            "",
            "notifications:",
            f"  enabled: {str(notifications.get('enabled', False)).lower()}",
            "  desktop:",
            f"    enabled: {str(notifications['desktop'].get('enabled', False)).lower()}",
            "  ntfy:",
            f"    enabled: {str(notifications['ntfy'].get('enabled', False)).lower()}",
            f'    url: "{notifications["ntfy"].get("url", "")}"',
            f"    timeout_seconds: {notifications['ntfy'].get('timeout_seconds', 5)}",
            "",
            "browser_threat_protection:",
            f"  enabled: {str(browser_threats.get('enabled', True)).lower()}",
            f"  risk_threshold: {browser_threats.get('risk_threshold', 60)}",
            "  suspicious_tlds:",
        ])
        lines.extend(f"    - {tld}" for tld in browser_threats.get("suspicious_tlds", []))
        lines.append("  suspicious_keywords:")
        lines.extend(
            f"    - {keyword}"
            for keyword in browser_threats.get("suspicious_keywords", [])
        )
        return "\n".join(lines) + "\n"

    @classmethod
    def get_database_path(cls, config):
        return str(
            cls._merge_database((config or {}).get("database", {})).get(
                "path",
                cls.DEFAULT_DATABASE_PATH,
            )
        )

    @classmethod
    def _merge_database(cls, database):
        merged = cls.DEFAULT_CONFIG["database"].copy()
        if database:
            merged.update(database)
        return merged

    @classmethod
    def _merge_notifications(cls, notifications):
        merged = {
            "enabled": cls.DEFAULT_CONFIG["notifications"]["enabled"],
            "desktop": cls.DEFAULT_CONFIG["notifications"]["desktop"].copy(),
            "ntfy": cls.DEFAULT_CONFIG["notifications"]["ntfy"].copy(),
        }
        if notifications:
            merged["enabled"] = notifications.get("enabled", merged["enabled"])
            merged["desktop"].update(notifications.get("desktop", {}))
            merged["ntfy"].update(notifications.get("ntfy", {}))
        return merged

    @classmethod
    def _merge_browser_threat_protection(cls, browser_threats):
        merged = {
            "enabled": cls.DEFAULT_CONFIG["browser_threat_protection"]["enabled"],
            "risk_threshold": cls.DEFAULT_CONFIG["browser_threat_protection"]["risk_threshold"],
            "suspicious_tlds": list(
                cls.DEFAULT_CONFIG["browser_threat_protection"]["suspicious_tlds"]
            ),
            "suspicious_keywords": list(
                cls.DEFAULT_CONFIG["browser_threat_protection"]["suspicious_keywords"]
            ),
        }
        if browser_threats:
            merged["enabled"] = browser_threats.get("enabled", merged["enabled"])
            merged["risk_threshold"] = browser_threats.get(
                "risk_threshold",
                merged["risk_threshold"],
            )
            if browser_threats.get("suspicious_tlds"):
                merged["suspicious_tlds"] = list(browser_threats["suspicious_tlds"])
            if browser_threats.get("suspicious_keywords"):
                merged["suspicious_keywords"] = list(browser_threats["suspicious_keywords"])
        return merged

    @staticmethod
    def _parse_scalar(value):
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        try:
            return int(value)
        except ValueError:
            return value
