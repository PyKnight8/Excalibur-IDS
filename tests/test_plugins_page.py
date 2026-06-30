from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.config import Config
from excalibur.dashboard.app import create_app


class FakeServiceController:
    def __init__(self, status="running"):
        self._status = status

    def status(self):
        return self._status

    def restart(self):
        return True


class PluginsPageTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.db_path = self.root / "plugins.sqlite"
        self.config_path = self.root / "config.yaml"
        self.rules_path = self.root / "rules.yaml"
        self.plugins_dir = self.root / "plugins"
        self.plugins_dir.mkdir()
        Config.save(Config._default_config(), self.config_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_plugins_page_lists_installed_plugins(self):
        self._write_plugin(
            "hello_world",
            "\n".join(
                [
                    "name: Hello World",
                    "id: hello_world",
                    "version: 1.0.0",
                    "author: Excalibur",
                    "description: Logs received events.",
                    "entrypoint: plugin.py",
                    "enabled: true",
                ]
            )
            + "\n",
        )
        app = self._create_app()

        response = app.test_client().get("/plugins")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Plugin Management", html)
        self.assertIn("Hello World", html)
        self.assertIn("hello_world", html)
        self.assertIn("Logs received events.", html)
        self.assertIn("Enabled", html)

    def test_toggle_plugin_updates_only_enabled_field(self):
        metadata_path = self._write_plugin(
            "abuseipdb",
            "\n".join(
                [
                    "name: AbuseIPDB",
                    "id: abuseipdb",
                    "version: 1.0.0",
                    "author: Excalibur",
                    "description: AbuseIPDB proof of concept.",
                    "entrypoint: plugin.py",
                    "enabled: true",
                ]
            )
            + "\n",
        )
        app = self._create_app()

        response = app.test_client().post(
            "/plugins/toggle/abuseipdb",
            follow_redirects=True,
        )
        html = response.get_data(as_text=True)
        updated_text = metadata_path.read_text(encoding="utf-8")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Plugin updated. Restart sensor for changes to take effect.", html)
        self.assertIn("Restart Sensor", html)
        self.assertIn("enabled: false", updated_text)
        self.assertIn("name: AbuseIPDB", updated_text)
        self.assertIn("description: AbuseIPDB proof of concept.", updated_text)
        self.assertIn("entrypoint: plugin.py", updated_text)

    def test_plugins_page_reuses_sensor_status_and_restart_paths(self):
        self._write_plugin(
            "alert_logger",
            "\n".join(
                [
                    "name: Alert Logger",
                    "id: alert_logger",
                    "version: 1.0.0",
                    "entrypoint: plugin.py",
                    "enabled: false",
                ]
            )
            + "\n",
        )
        app = self._create_app()

        response = app.test_client().get("/plugins?updated=1")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Sensor Status", html)
        self.assertIn("/sensor/status", html)
        self.assertIn("/sensor/restart", html)
        self.assertIn("Restart Sensor", html)

    def _create_app(self):
        return create_app(
            self.db_path,
            config_path=self.config_path,
            rules_path=self.rules_path,
            service_controller=FakeServiceController(),
        )

    def _write_plugin(self, plugin_name, metadata_text):
        plugin_dir = self.plugins_dir / plugin_name
        plugin_dir.mkdir()
        metadata_path = plugin_dir / "plugin.yaml"
        metadata_path.write_text(metadata_text, encoding="utf-8")
        (plugin_dir / "plugin.py").write_text("from excalibur.plugins.base import Plugin\n", encoding="utf-8")
        return metadata_path


if __name__ == "__main__":
    unittest.main()
