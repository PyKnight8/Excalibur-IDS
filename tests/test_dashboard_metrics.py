from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfoNotFoundError

from excalibur.config import Config
from excalibur.dashboard.app import create_app
from excalibur.database import Database


class DashboardMetricsTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "dashboard.sqlite"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        config = Config._default_config()
        config["general"]["timezone"] = "Asia/Amman"
        Config.save(config, self.config_path)
        self.database = Database(self.db_path, config=config)
        self.database.add_host(
            "10.0.0.10",
            None,
            "2026-06-15T09:00:00+00:00",
            "2026-06-15T09:00:00+00:00",
        )
        self.database.log_dns_query(
            "2026-06-16T09:00:00+00:00",
            "10.0.0.10",
            "10.0.0.1",
            "example.org",
            "A",
            "NOERROR",
        )
        self.database.create_alert(
            "2026-06-16T10:00:00+00:00",
            "High",
            "SMB Recon Activity",
            "Source contacted many hosts via SMB.",
            source_ip="10.0.0.10",
        )
        self.database.create_alert(
            "2026-06-15T10:00:00+00:00",
            "Medium",
            "DNS Flood",
            "High DNS volume detected.",
            source_ip="10.0.0.20",
        )
        self.database.record_rule_hit("SMB Recon Activity", "2026-06-16T10:00:00+00:00")
        self.database.record_rule_alert("SMB Recon Activity", "2026-06-16T10:00:00+00:00")
        self.database.record_rule_hit("DNS Flood", "2026-06-15T10:00:00+00:00")
        self.app = create_app(
            self.db_path,
            config_path=self.config_path,
            service_controller=FakeServiceController(),
        )

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_dashboard_metrics_api_returns_summary_cards_and_activity(self):
        response = self.app.test_client().get("/api/dashboard/metrics")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["sensor_status"], "running")
        self.assertEqual(payload["total_alerts"], 2)
        self.assertEqual(payload["rule_hits"], 2)
        self.assertEqual(payload["hosts_seen"], 1)
        self.assertEqual(payload["dns_queries"], 1)
        self.assertEqual(payload["traffic_records"], 0)
        self.assertGreaterEqual(payload["alerts_generated"], 2)

    def test_dashboard_alert_trend_api_zero_fills_missing_days(self):
        response = self.app.test_client().get("/api/dashboard/alert-trend")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(payload["days"]), 7)
        counts = {day["date"]: day["count"] for day in payload["days"]}
        self.assertIn("2026-06-16", counts)
        self.assertIn("2026-06-15", counts)

    def test_dashboard_top_rules_api_sorts_by_alerts_desc(self):
        response = self.app.test_client().get("/api/dashboard/top-rules")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["rules"][0]["rule_name"], "SMB Recon Activity")
        self.assertEqual(payload["rules"][0]["alerts"], 1)

    def test_dashboard_top_sources_api_returns_sources_desc(self):
        response = self.app.test_client().get("/api/dashboard/top-sources")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(payload["sources"]), 2)
        self.assertEqual(payload["sources"][0]["source_ip"], "10.0.0.10")

    def test_dashboard_homepage_shows_operational_sections(self):
        response = self.app.test_client().get("/")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Alerts Today", html)
        self.assertIn("Top Triggered Rules", html)
        self.assertIn("Most Active Sources", html)
        self.assertIn("Latest Investigations", html)
        self.assertIn("SMB Recon Activity", html)
        self.assertIn("Sensor: Running", html)

    @patch(
        "excalibur.dashboard.app.ZoneInfo",
        side_effect=ZoneInfoNotFoundError("No time zone found"),
    )
    def test_dashboard_falls_back_to_utc_when_timezone_data_is_unavailable(
        self,
        _zone_info,
    ):
        with self.assertLogs("excalibur.dashboard.app", level="WARNING") as logs:
            homepage_response = self.app.test_client().get("/")
            metrics_response = self.app.test_client().get("/api/dashboard/metrics")
            trend_response = self.app.test_client().get("/api/dashboard/alert-trend")

        self.assertEqual(homepage_response.status_code, 200)
        self.assertEqual(metrics_response.status_code, 200)
        self.assertEqual(trend_response.status_code, 200)
        self.assertIn("falling back to UTC", "\n".join(logs.output))


class FakeServiceController:
    def status(self):
        return "running"

    def restart(self):
        return True


if __name__ == "__main__":
    unittest.main()
