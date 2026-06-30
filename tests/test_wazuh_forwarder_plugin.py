from dataclasses import dataclass
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from tempfile import TemporaryDirectory
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from excalibur.events import AlertEvent


PLUGIN_PATH = (
    Path(__file__).resolve().parent.parent / "plugins" / "wazuh_forwarder" / "plugin.py"
)


def _load_plugin_module():
    spec = spec_from_file_location("test_wazuh_forwarder_plugin_module", PLUGIN_PATH)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeLogger:
    def __init__(self):
        self.messages = {"info": [], "warning": [], "error": []}

    def info(self, message):
        self.messages["info"].append(message)

    def warning(self, message):
        self.messages["warning"].append(message)

    def error(self, message):
        self.messages["error"].append(message)


class FakeContext:
    def __init__(self):
        self.logger = FakeLogger()

    def emit_event(self, event):
        return None


@dataclass
class AlertObject:
    event_type: str = "alert_event"
    alert_id: int = 42
    title: str = "SMB Recon Activity"
    severity: str = "High"
    description: str = "Source contacted many hosts via SMB."
    source_ip: str | None = "10.0.0.25"
    destination_ip: str | None = "10.0.0.1"
    timestamp: str = "2026-06-23T12:00:00+00:00"
    context_json: str | None = None


class WazuhForwarderPluginTest(unittest.TestCase):
    def setUp(self):
        self.module = _load_plugin_module()
        self.plugin = self.module.Plugin()
        self.context = FakeContext()
        self.temp_dir = TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "excalibur-alerts.log"
        self.original_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_env)
        self.temp_dir.cleanup()

    def test_serialization_from_dict_alert_event(self):
        event = {
            "event_type": "alert_event",
            "title": "Possible DNS Flood",
            "severity": "Medium",
            "description": "Burst of DNS queries detected.",
            "source_ip": "10.0.0.8",
            "destination_ip": "10.0.0.1",
            "timestamp": "2026-06-23T12:00:00+00:00",
            "context_json": json.dumps(
                {
                    "rule": {
                        "name": "DNS Flood",
                        "tags": ["dns", "volume"],
                        "event_type": "dns",
                    }
                }
            ),
        }

        payload = self.plugin._serialize_alert(event)

        self.assertEqual(payload["source"], "excalibur")
        self.assertEqual(payload["event_type"], "excalibur_alert")
        self.assertEqual(payload["rule_name"], "DNS Flood")
        self.assertEqual(payload["severity"], "Medium")
        self.assertEqual(payload["protocol"], "dns")
        self.assertEqual(payload["tags"], ["dns", "volume"])

    def test_serialization_from_object_alert_event(self):
        event = AlertObject(
            context_json=json.dumps(
                {
                    "rule": {
                        "name": "SMB Recon",
                        "tags": ["recon", "smb"],
                        "event_type": "packet",
                    }
                }
            )
        )

        payload = self.plugin._serialize_alert(event)

        self.assertEqual(payload["rule_name"], "SMB Recon")
        self.assertEqual(payload["title"], "SMB Recon Activity")
        self.assertEqual(payload["severity"], "High")
        self.assertEqual(payload["source_ip"], "10.0.0.25")
        self.assertEqual(payload["protocol"], "packet")

    def test_missing_optional_fields(self):
        event = {
            "event_type": "alert_event",
            "title": "Generic Alert",
            "severity": "Low",
            "timestamp": "2026-06-23T12:00:00+00:00",
        }

        payload = self.plugin._serialize_alert(event)

        self.assertNotIn("source_ip", payload)
        self.assertNotIn("destination_ip", payload)
        self.assertNotIn("protocol", payload)
        self.assertNotIn("destination_port", payload)
        self.assertNotIn("tags", payload)

    def test_local_file_transport_writes_jsonl(self):
        transport = self.module.LocalFileTransport(str(self.log_path))
        payload = {"source": "excalibur", "event_type": "excalibur_alert"}

        transport.send(payload)

        written = self.log_path.read_text(encoding="utf-8").strip()
        self.assertEqual(json.loads(written), payload)

    def test_local_file_transport_handles_path_failure_without_crashing_plugin(self):
        class BrokenTransport:
            name = "localfile"

            def send(self, payload):
                raise PermissionError("permission denied")

        self.plugin.enabled = True
        self.plugin.transport = BrokenTransport()

        self.plugin.handle_event(
            AlertEvent(
                timestamp="2026-06-23T12:00:00+00:00",
                title="SMB Recon Activity",
                severity="High",
                description="Source contacted many hosts via SMB.",
            ),
            self.context,
        )

        self.assertIn(
            "Failed to forward alert to Wazuh: permission denied",
            self.context.logger.messages["warning"],
        )

    def test_invalid_transport_falls_back_to_localfile_with_clear_log(self):
        os.environ["EXCALIBUR_WAZUH_TRANSPORT"] = "udp"
        os.environ["EXCALIBUR_WAZUH_LOG_PATH"] = str(self.log_path)
        output = io.StringIO()

        with redirect_stdout(output):
            self.plugin.on_startup()

        self.assertIsInstance(self.plugin.transport, self.module.LocalFileTransport)
        self.assertIn(
            "invalid transport 'udp'; falling back to localfile",
            output.getvalue(),
        )

    def test_alert_event_handler_catches_transport_exceptions(self):
        class FailingTransport:
            name = "tcp"

            def send(self, payload):
                raise RuntimeError("receiver unavailable")

        self.plugin.enabled = True
        self.plugin.transport = FailingTransport()

        self.plugin.handle_event(
            AlertEvent(
                timestamp="2026-06-23T12:00:00+00:00",
                title="SMB Recon Activity",
                severity="High",
                description="Source contacted many hosts via SMB.",
            ),
            self.context,
        )

        self.assertIn(
            "Failed to forward alert to Wazuh: receiver unavailable",
            self.context.logger.messages["warning"],
        )

    def test_non_alert_events_are_ignored(self):
        self.plugin.enabled = True
        self.plugin.transport = self.module.LocalFileTransport(str(self.log_path))

        self.plugin.handle_event({"event_type": "packet_event", "src_ip": "10.0.0.1"}, self.context)

        self.assertFalse(self.log_path.exists())


if __name__ == "__main__":
    unittest.main()
