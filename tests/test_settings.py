from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.config import Config
from excalibur.dashboard.app import create_app
from excalibur.database import Database
from excalibur.detection.rules_config import RulesConfig


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "settings.sqlite"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.rules_path = Path(self.temp_dir.name) / "rules.yaml"
        self.database = Database(self.db_path)

    def tearDown(self):
        self.database.close()
        self.temp_dir.cleanup()

    def test_missing_config_creates_default_timezone(self):
        config = Config.load(self.config_path)

        self.assertTrue(self.config_path.exists())
        self.assertEqual(config["general"]["timezone"], "Asia/Amman")

    def test_settings_page_saves_timezone_to_yaml(self):
        app = create_app(self.db_path, config_path=self.config_path, rules_path=self.rules_path)
        client = app.test_client()

        response = client.post(
            "/settings",
            data={
                "timezone": "America/New_York",
                "excluded_sources": "192.168.1.173\n10.0.0.5\n",
            },
            follow_redirects=True,
        )
        config = Config.load(self.config_path)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(config["general"]["timezone"], "America/New_York")
        self.assertEqual(
            config["portscan"]["excluded_sources"],
            ["192.168.1.173", "10.0.0.5"],
        )
        self.assertIn("Settings saved.", response.get_data(as_text=True))

    def test_settings_page_saves_notification_settings_to_yaml(self):
        app = create_app(self.db_path, config_path=self.config_path, rules_path=self.rules_path)
        client = app.test_client()

        response = client.post(
            "/settings",
            data={
                "timezone": "Asia/Amman",
                "excluded_sources": "",
                "notifications_enabled": "on",
                "ntfy_url": "http://ntfyServer:5002/Excalibur-Relay-Notifications",
                "ntfy_timeout_seconds": "9",
            },
            follow_redirects=True,
        )
        config = Config.load(self.config_path)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(config["notifications"]["enabled"])
        self.assertFalse(config["notifications"]["desktop"]["enabled"])
        self.assertFalse(config["notifications"]["ntfy"]["enabled"])
        self.assertEqual(
            config["notifications"]["ntfy"]["url"],
            "http://ntfyServer:5002/Excalibur-Relay-Notifications",
        )
        self.assertEqual(config["notifications"]["ntfy"]["timeout_seconds"], 9)

    def test_settings_page_saves_desktop_and_ntfy_provider_toggles(self):
        app = create_app(self.db_path, config_path=self.config_path, rules_path=self.rules_path)
        client = app.test_client()

        response = client.post(
            "/settings",
            data={
                "timezone": "Asia/Amman",
                "excluded_sources": "",
                "notifications_enabled": "on",
                "desktop_enabled": "on",
                "ntfy_enabled": "on",
                "ntfy_url": "http://ntfyServer:5002/Excalibur-Relay-Notifications",
                "ntfy_timeout_seconds": "5",
            },
            follow_redirects=True,
        )
        config = Config.load(self.config_path)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(config["notifications"]["enabled"])
        self.assertTrue(config["notifications"]["desktop"]["enabled"])
        self.assertTrue(config["notifications"]["ntfy"]["enabled"])

    def test_settings_page_shows_ntfy_notification_controls(self):
        app = create_app(self.db_path, config_path=self.config_path, rules_path=self.rules_path)

        response = app.test_client().get("/settings")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Enable Alert Notifications", html)
        self.assertIn("Enable Native Desktop Notifications", html)
        self.assertIn("Enable NTFY Relay Notifications", html)
        self.assertIn("NTFY URL", html)
        self.assertIn("Send Test Notification", html)

    def test_dashboard_converts_utc_timestamps_for_display_only(self):
        Config.save(
            {
                "general": {"timezone": "Asia/Amman"},
                "portscan": Config.DEFAULT_CONFIG["portscan"],
                "monitored_networks": Config.DEFAULT_CONFIG["monitored_networks"],
            },
            self.config_path,
        )
        self.database.log_traffic(
            "2026-06-08T10:00:00+00:00",
            "10.0.0.10",
            "10.0.0.1",
            "TCP",
            12345,
            80,
            512,
        )
        self.database.close()

        app = create_app(self.db_path, config_path=self.config_path, rules_path=self.rules_path)
        response = app.test_client().get("/traffic")
        html = response.get_data(as_text=True)

        verification_database = Database(self.db_path)
        stored_value = verification_database.get_latest_traffic(1)[0]["timestamp"]
        verification_database.close()
        self.assertEqual(stored_value, "2026-06-08T10:00:00+00:00")
        self.assertIn("2026-06-08 13:00:00", html)

    def test_rules_editor_saves_valid_rules_yaml(self):
        rules_text = (
            "global:\n"
            "  exclude_own_ips: true\n"
            "  excluded_sources:\n"
            "    - 10.0.0.99\n"
            "\n"
            "rules:\n"
            "  - name: DNS Flood\n"
            "    type: dns_flood\n"
            "    enabled: true\n"
            "    threshold: 2\n"
            "    window_seconds: 60\n"
            "    cooldown_seconds: 300\n"
            "    severity: Medium\n"
        )
        app = create_app(self.db_path, config_path=self.config_path, rules_path=self.rules_path)

        response = app.test_client().post(
            "/settings",
            data={"action": "save_rules", "rules_yaml": rules_text},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), rules_text)
        self.assertEqual(RulesConfig.load(self.rules_path)["rules"][0]["threshold"], 2)

    def test_rules_editor_rejects_invalid_rules_yaml(self):
        RulesConfig.create_default(self.rules_path)
        original_text = self.rules_path.read_text(encoding="utf-8")
        app = create_app(self.db_path, config_path=self.config_path, rules_path=self.rules_path)

        response = app.test_client().post(
            "/settings",
            data={"action": "save_rules", "rules_yaml": "rules:\n  - name: Broken\n"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.rules_path.read_text(encoding="utf-8"), original_text)
        self.assertIn("Invalid rules.yaml", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
