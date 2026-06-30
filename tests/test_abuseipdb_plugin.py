from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import unittest

import requests

from excalibur.events import AlertEvent, PacketEvent


PLUGIN_PATH = (
    Path(__file__).resolve().parent.parent / "plugins" / "abuseipdb" / "plugin.py"
)


def _load_plugin_class():
    spec = spec_from_file_location("test_abuseipdb_plugin_module", PLUGIN_PATH)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Plugin


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


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


class AbuseIpDbPluginTest(unittest.TestCase):
    def setUp(self):
        plugin_class = _load_plugin_class()
        self.plugin = plugin_class()
        self.plugin.API_KEY = "test-key"
        self.context = FakeContext()

    def test_ignores_non_alert_events(self):
        calls = []
        self.plugin.get_func = lambda *args, **kwargs: calls.append((args, kwargs))

        self.plugin.handle_event(
            PacketEvent(
                timestamp="2026-06-18T10:00:00+00:00",
                src_ip="8.8.8.8",
                dst_ip="1.1.1.1",
                protocol="TCP",
                src_port=12345,
                dst_port=80,
                packet_size=60,
            ),
            self.context,
        )

        self.assertEqual(calls, [])

    def test_prefers_destination_ip_for_lookup(self):
        calls = []

        def fake_get(*args, **kwargs):
            calls.append((args, kwargs))
            return FakeResponse(
                {"data": {"abuseConfidenceScore": 42, "totalReports": 7}}
            )

        self.plugin.get_func = fake_get

        self.plugin.handle_event(
            AlertEvent(
                timestamp="2026-06-18T10:00:00+00:00",
                alert_id=10,
                title="Suspicious Activity",
                severity="High",
                description="Test alert.",
                source_ip="8.8.4.4",
                destination_ip="1.1.1.1",
            ),
            self.context,
        )

        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(args[0], self.plugin.API_URL)
        self.assertEqual(kwargs["headers"]["Key"], "test-key")
        self.assertEqual(kwargs["params"]["ipAddress"], "1.1.1.1")
        self.assertIn(
            "lookup 1.1.1.1 abuseConfidenceScore=42 totalReports=7",
            self.context.logger.messages["info"],
        )

    def test_falls_back_to_source_ip_when_destination_is_not_public(self):
        calls = []

        def fake_get(*args, **kwargs):
            calls.append((args, kwargs))
            return FakeResponse(
                {"data": {"abuseConfidenceScore": 5, "totalReports": 2}}
            )

        self.plugin.get_func = fake_get

        self.plugin.handle_event(
            AlertEvent(
                timestamp="2026-06-18T10:00:00+00:00",
                alert_id=11,
                title="Suspicious Activity",
                severity="Medium",
                description="Test alert.",
                source_ip="8.8.8.8",
                destination_ip="192.168.1.10",
            ),
            self.context,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["params"]["ipAddress"], "8.8.8.8")

    def test_ignores_non_public_addresses(self):
        calls = []
        self.plugin.get_func = lambda *args, **kwargs: calls.append((args, kwargs))

        self.plugin.handle_event(
            AlertEvent(
                timestamp="2026-06-18T10:00:00+00:00",
                alert_id=12,
                title="Private Activity",
                severity="Low",
                description="Test alert.",
                source_ip="10.0.0.5",
                destination_ip="192.168.1.10",
            ),
            self.context,
        )

        self.assertEqual(calls, [])
        self.assertEqual(self.context.logger.messages["info"], [])
        self.assertEqual(self.context.logger.messages["warning"], [])

    def test_handles_network_failures_gracefully(self):
        def failing_get(*args, **kwargs):
            raise requests.ConnectionError("network unavailable")

        self.plugin.get_func = failing_get

        self.plugin.handle_event(
            AlertEvent(
                timestamp="2026-06-18T10:00:00+00:00",
                alert_id=13,
                title="External Activity",
                severity="High",
                description="Test alert.",
                source_ip="8.8.8.8",
            ),
            self.context,
        )

        self.assertIn(
            "AbuseIPDB lookup failed for 8.8.8.8: network unavailable",
            self.context.logger.messages["warning"],
        )

    def test_skips_lookup_when_api_key_is_missing(self):
        calls = []
        self.plugin.API_KEY = ""
        self.plugin.get_func = lambda *args, **kwargs: calls.append((args, kwargs))

        self.plugin.handle_event(
            AlertEvent(
                timestamp="2026-06-18T10:00:00+00:00",
                alert_id=14,
                title="External Activity",
                severity="High",
                description="Test alert.",
                source_ip="8.8.8.8",
            ),
            self.context,
        )

        self.assertEqual(calls, [])
        self.assertIn(
            "skipping AbuseIPDB lookup because ABUSEIPDB_API_KEY is not set",
            self.context.logger.messages["warning"],
        )


if __name__ == "__main__":
    unittest.main()
