import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from excalibur.plugins.base import Plugin


class BaseTransport:
    name = "base"

    def send(self, payload: dict[str, Any]) -> None:
        raise NotImplementedError


class LocalFileTransport(BaseTransport):
    name = "localfile"

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)

    def send(self, payload: dict[str, Any]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")


class TcpTransport(BaseTransport):
    name = "tcp"

    def __init__(self, host: str, port: int, timeout_seconds: int):
        self.host = host
        self.port = port
        self.timeout_seconds = timeout_seconds

    def send(self, payload: dict[str, Any]) -> None:
        with socket.create_connection(
            (self.host, self.port),
            timeout=self.timeout_seconds,
        ) as connection:
            connection.sendall((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))


class Plugin(Plugin):
    name = "Wazuh Forwarder"

    def __init__(self):
        self.enabled = True
        self.transport_name = "localfile"
        self.log_path = "/var/ossec/logs/excalibur-alerts.log"
        self.agent_name = socket.gethostname()
        self.timeout_seconds = 5
        self.tcp_host = ""
        self.tcp_port = 0
        self.transport: BaseTransport | None = None

    def on_startup(self):
        self._load_config()
        self.transport = self._build_transport()
        transport_label = self.transport.name if self.transport is not None else "disabled"
        self._log_info(f"initialized transport={transport_label}")

    def handle_event(self, event, context):
        if self._event_type(event) != "alert_event":
            return
        if not self.enabled or self.transport is None:
            return

        try:
            payload = self._serialize_alert(event)
            self.transport.send(payload)
            self._log_info(
                f"Wazuh alert forwarded rule={payload.get('rule_name', 'unknown')} "
                f"severity={payload.get('severity', 'unknown')}"
            )
        except Exception as exc:
            context.logger.warning(f"Failed to forward alert to Wazuh: {exc}")

    def _load_config(self):
        self.enabled = self._parse_bool(
            os.environ.get("EXCALIBUR_WAZUH_ENABLED"),
            default=True,
        )
        self.transport_name = (
            os.environ.get("EXCALIBUR_WAZUH_TRANSPORT", "localfile").strip().lower()
            or "localfile"
        )
        self.log_path = (
            os.environ.get("EXCALIBUR_WAZUH_LOG_PATH", "/var/ossec/logs/excalibur-alerts.log").strip()
            or "/var/ossec/logs/excalibur-alerts.log"
        )
        self.agent_name = (
            os.environ.get("EXCALIBUR_WAZUH_AGENT_NAME", socket.gethostname()).strip()
            or socket.gethostname()
        )
        self.timeout_seconds = self._parse_positive_int(
            os.environ.get("EXCALIBUR_WAZUH_TIMEOUT_SECONDS"),
            default=5,
        )
        self.tcp_host = os.environ.get("EXCALIBUR_WAZUH_TCP_HOST", "").strip()
        self.tcp_port = self._parse_positive_int(
            os.environ.get("EXCALIBUR_WAZUH_TCP_PORT"),
            default=0,
        )

    def _build_transport(self) -> BaseTransport | None:
        if not self.enabled:
            return None
        if self.transport_name == "localfile":
            return LocalFileTransport(self.log_path)
        if self.transport_name == "tcp":
            if not self.tcp_host or not self.tcp_port:
                self._log_warning("tcp transport requested but host/port are missing; disabling forwarder")
                return None
            return TcpTransport(self.tcp_host, self.tcp_port, self.timeout_seconds)

        self._log_warning(
            f"invalid transport '{self.transport_name}'; falling back to localfile"
        )
        return LocalFileTransport(self.log_path)

    def _serialize_alert(self, event) -> dict[str, Any]:
        context = self._parse_context(self._field(event, "context_json"))
        rule_context = context.get("rule", {}) if isinstance(context, dict) else {}
        evidence_context = context.get("evidence", {}) if isinstance(context, dict) else {}
        observed_context = evidence_context.get("observed", {}) if isinstance(evidence_context, dict) else {}

        rule_name = (
            self._field(event, "rule_name")
            or self._safe_get(rule_context, "name")
            or self._field(event, "title")
            or "Excalibur Alert"
        )
        payload = {
            "source": "excalibur",
            "event_type": "excalibur_alert",
            "agent": self.agent_name,
            "rule_name": rule_name,
            "severity": self._field(event, "severity") or "Unknown",
            "title": self._field(event, "title") or rule_name,
            "description": self._field(event, "description") or "",
            "timestamp": self._field(event, "timestamp") or self._utc_now(),
            "forwarded_at": self._utc_now(),
        }

        self._set_optional(payload, "source_ip", self._field(event, "source_ip"))
        self._set_optional(payload, "destination_ip", self._field(event, "destination_ip"))
        self._set_optional(
            payload,
            "protocol",
            self._field(event, "protocol") or self._safe_get(rule_context, "event_type"),
        )

        destination_port = (
            self._field(event, "destination_port")
            or self._field(event, "dst_port")
            or self._safe_get(observed_context, "destination_port")
            or self._safe_get(observed_context, "dst_port")
        )
        if destination_port not in (None, "", 0):
            payload["destination_port"] = destination_port

        tags = self._field(event, "tags")
        if not isinstance(tags, list):
            tags = self._safe_get(rule_context, "tags")
        if isinstance(tags, list) and tags:
            payload["tags"] = tags

        return payload

    def _field(self, event, field_name: str):
        if isinstance(event, dict):
            return event.get(field_name)
        return getattr(event, field_name, None)

    def _event_type(self, event) -> str:
        if isinstance(event, dict):
            return str(event.get("event_type", ""))
        return str(getattr(event, "event_type", ""))

    def _parse_context(self, context_json):
        if isinstance(context_json, dict):
            return context_json
        if not context_json:
            return {}
        try:
            parsed = json.loads(context_json)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _safe_get(self, mapping, key):
        if isinstance(mapping, dict):
            return mapping.get(key)
        return None

    def _set_optional(self, payload, key, value):
        if value not in (None, ""):
            payload[key] = value

    def _parse_bool(self, value, default: bool) -> bool:
        if value is None:
            return default
        normalized = str(value).strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        return default

    def _parse_positive_int(self, value, default: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed > 0 else default

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _log_info(self, message: str) -> None:
        print(f"[PLUGIN] {self.name} {message}", flush=True)

    def _log_warning(self, message: str) -> None:
        print(f"[PLUGIN] {self.name} {message}", flush=True)
