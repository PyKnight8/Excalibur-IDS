from importlib.util import module_from_spec, spec_from_file_location
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import io
import json
import unittest
from contextlib import redirect_stdout

import requests

from excalibur.events import AlertEvent, DnsEvent, PacketEvent


PLUGIN_PATH = (
    Path(__file__).resolve().parent.parent / "plugins" / "otx_threat_intel" / "plugin.py"
)


def _load_plugin_class():
    spec = spec_from_file_location("test_otx_plugin_module", PLUGIN_PATH)
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


class OtxThreatIntelPluginTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        plugin_class = _load_plugin_class()
        self.plugin = plugin_class()
        self.plugin.DATA_DIR = Path(self.temp_dir.name) / "data" / "threat_intel" / "otx"
        self.plugin.INDICATORS_PATH = self.plugin.DATA_DIR / "indicators.jsonl"
        self.plugin.METADATA_PATH = self.plugin.DATA_DIR / "metadata.json"
        self.plugin.api_key = "test-key"
        self.plugin.refresh_hours = 24
        self.plugin.max_indicators = 100000
        self.plugin.max_pulses = 100
        self.plugin.now_func = lambda: datetime(2026, 6, 19, 10, 0, 0, tzinfo=timezone.utc)
        self.context = FakeContext()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_plugin_loads_with_no_api_key(self):
        self.plugin.api_key = ""
        self.plugin.on_load()

        output = io.StringIO()
        with redirect_stdout(output):
            self.plugin.on_startup()

        self.assertEqual(self.plugin.ip_indicators, set())
        self.assertIn(
            "OTX API key not configured; using cached indicators only",
            output.getvalue(),
        )

    def test_refresh_skipped_when_cache_is_fresh(self):
        self._write_cache(
            indicators=[{"type": "ip", "value": "8.8.8.8"}],
            metadata={
                "last_successful_update": "2026-06-19T09:00:00+00:00",
                "indicator_count": 1,
                "ip_count": 1,
                "domain_count": 0,
                "url_count": 0,
            },
        )
        calls = []
        self.plugin.get_func = lambda *args, **kwargs: calls.append((args, kwargs))

        self.plugin.on_load()
        output = io.StringIO()
        with redirect_stdout(output):
            self.plugin.on_startup()

        self.assertEqual(calls, [])
        self.assertEqual(self.plugin.ip_indicators, {"8.8.8.8"})
        self.assertIn("cached indicators are fresh; skipping OTX refresh", output.getvalue())

    def test_refresh_attempted_when_cache_is_stale(self):
        self._write_cache(
            indicators=[],
            metadata={
                "last_successful_update": "2026-06-17T09:00:00+00:00",
                "indicator_count": 0,
                "ip_count": 0,
                "domain_count": 0,
                "url_count": 0,
            },
        )
        calls = []

        def fake_get(*args, **kwargs):
            calls.append((args, kwargs))
            return FakeResponse(
                {
                    "results": [
                        {
                            "indicators": [
                                {"type": "IPv4", "indicator": "8.8.8.8"},
                                {"type": "domain", "indicator": "Bad.EXAMPLE."},
                            ]
                        }
                    ],
                    "next": None,
                }
            )

        self.plugin.get_func = fake_get

        self.plugin.on_load()
        output = io.StringIO()
        with redirect_stdout(output):
            self.plugin.on_startup()

        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(kwargs["timeout"], 60)
        metadata = json.loads(self.plugin.METADATA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(metadata["ip_count"], 1)
        self.assertEqual(metadata["domain_count"], 1)
        self.assertEqual(self.plugin.ip_indicators, {"8.8.8.8"})
        self.assertEqual(self.plugin.domain_indicators, {"bad.example"})
        log_output = output.getvalue()
        self.assertIn("starting OTX refresh max_pulses=100 max_indicators=100000", log_output)
        self.assertIn("refresh progress page=1 pulses_processed=1", log_output)
        self.assertIn("refreshed indicators pulses=1 indicators=2", log_output)

    def test_cache_load_behavior(self):
        self._write_cache(
            indicators=[
                {"type": "ip", "value": "8.8.8.8"},
                {"type": "domain", "value": "bad.example"},
                {"type": "url", "value": "https://bad.example/path"},
            ],
            metadata=self.plugin._default_metadata(),
        )

        self.plugin.on_load()

        self.assertEqual(self.plugin.ip_indicators, {"8.8.8.8"})
        self.assertEqual(self.plugin.domain_indicators, {"bad.example"})
        self.assertEqual(self.plugin.url_indicators, {"https://bad.example/path"})

    def test_private_and_invalid_ip_handling(self):
        self.assertIsNone(self.plugin._normalize_public_ip("10.0.0.5"))
        self.assertIsNone(self.plugin._normalize_public_ip("127.0.0.1"))
        self.assertIsNone(self.plugin._normalize_public_ip("not-an-ip"))
        self.assertEqual(self.plugin._normalize_public_ip("8.8.8.8"), "8.8.8.8")

    def test_domain_normalization(self):
        self.assertEqual(self.plugin._normalize_domain("Bad.EXAMPLE."), "bad.example")
        self.assertIsNone(self.plugin._normalize_domain(""))
        self.assertIsNone(self.plugin._normalize_domain("bad example"))

    def test_packet_event_ip_match(self):
        self.plugin.on_load()
        self.plugin.ip_indicators = {"8.8.8.8"}

        self.plugin.handle_event(
            PacketEvent(
                timestamp="2026-06-19T10:00:00+00:00",
                src_ip="10.0.0.10",
                dst_ip="8.8.8.8",
                protocol="TCP",
                src_port=12345,
                dst_port=443,
                packet_size=60,
            ),
            self.context,
        )

        self.assertIn(
            "IOC match type=ip event=packet_event field=destination_ip value=8.8.8.8",
            self.context.logger.messages["info"],
        )

    def test_dns_event_domain_match(self):
        self.plugin.on_load()
        self.plugin.domain_indicators = {"bad.example"}

        self.plugin.handle_event(
            DnsEvent(
                timestamp="2026-06-19T10:00:00+00:00",
                client_ip="10.0.0.10",
                dns_server_ip="10.0.0.1",
                query_name="Bad.EXAMPLE.",
                query_type="A",
            ),
            self.context,
        )

        self.assertIn(
            "IOC match type=domain event=dns_event field=query_name value=bad.example",
            self.context.logger.messages["info"],
        )

    def test_no_network_calls_during_event_handling(self):
        calls = []
        self.plugin.get_func = lambda *args, **kwargs: calls.append((args, kwargs))
        self.plugin.on_load()
        self.plugin.ip_indicators = {"8.8.8.8"}

        self.plugin.handle_event(
            AlertEvent(
                timestamp="2026-06-19T10:00:00+00:00",
                alert_id=21,
                title="External Activity",
                severity="High",
                description="Test alert.",
                destination_ip="8.8.8.8",
            ),
            self.context,
        )

        self.assertEqual(calls, [])

    def test_refresh_failure_keeps_stale_cache(self):
        self._write_cache(
            indicators=[{"type": "ip", "value": "8.8.8.8"}],
            metadata={
                "last_successful_update": "2026-06-17T09:00:00+00:00",
                "indicator_count": 1,
                "ip_count": 1,
                "domain_count": 0,
                "url_count": 0,
            },
        )

        def failing_get(*args, **kwargs):
            raise requests.ConnectionError("otx unavailable")

        self.plugin.get_func = failing_get
        self.plugin.on_load()
        output = io.StringIO()
        with redirect_stdout(output):
            self.plugin.on_startup()

        self.assertEqual(self.plugin.ip_indicators, {"8.8.8.8"})
        self.assertIn(
            "OTX refresh failed; using cached indicators only: otx unavailable",
            output.getvalue(),
        )

    def test_refresh_respects_max_pulses(self):
        self.plugin.max_pulses = 2
        calls = []

        def fake_get(*args, **kwargs):
            calls.append((args, kwargs))
            page = kwargs["params"]["page"]
            return FakeResponse(
                {
                    "results": [
                        {
                            "indicators": [
                                {"type": "IPv4", "indicator": f"8.8.8.{page}"},
                            ]
                        },
                        {
                            "indicators": [
                                {"type": "domain", "indicator": f"bad{page}.example"},
                            ]
                        },
                    ],
                    "next": "has-more",
                }
            )

        self.plugin.get_func = fake_get
        self.plugin.on_load()

        output = io.StringIO()
        with redirect_stdout(output):
            self.plugin.on_startup()

        self.assertEqual(len(calls), 1)
        self.assertEqual(self.plugin.ip_indicators, {"8.8.8.1"})
        self.assertEqual(self.plugin.domain_indicators, {"bad1.example"})
        self.assertIn("refresh progress page=1 pulses_processed=2", output.getvalue())

    def _write_cache(self, indicators, metadata):
        self.plugin.DATA_DIR.mkdir(parents=True, exist_ok=True)
        with self.plugin.INDICATORS_PATH.open("w", encoding="utf-8") as handle:
            for indicator in indicators:
                handle.write(json.dumps(indicator) + "\n")
        self.plugin.METADATA_PATH.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
