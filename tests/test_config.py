from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur.config import Config


class ConfigDatabasePathTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.config_path = Path(self.temp_dir.name) / "config.yaml"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_config_creates_default_database_path(self):
        config = Config.load(self.config_path)

        self.assertEqual(config["database"]["path"], "excalibur.sqlite")
        self.assertEqual(Config.get_database_path(config), "excalibur.sqlite")

    def test_parse_relative_database_path(self):
        self.config_path.write_text(
            "general:\n"
            "  timezone: Asia/Amman\n"
            "database:\n"
            "  path: data/excalibur.sqlite\n",
            encoding="utf-8",
        )

        config = Config.load(self.config_path)

        self.assertEqual(Config.get_database_path(config), "data/excalibur.sqlite")

    def test_parse_absolute_database_path(self):
        absolute_path = str((Path(self.temp_dir.name) / "db" / "excalibur.sqlite").resolve())
        self.config_path.write_text(
            "general:\n"
            "  timezone: Asia/Amman\n"
            "database:\n"
            f"  path: {absolute_path}\n",
            encoding="utf-8",
        )

        config = Config.load(self.config_path)

        self.assertEqual(Config.get_database_path(config), absolute_path)

    def test_save_preserves_database_path(self):
        Config.save(
            {
                "general": {"timezone": "UTC"},
                "database": {"path": "custom.sqlite"},
                "portscan": Config.DEFAULT_CONFIG["portscan"],
                "monitored_networks": Config.DEFAULT_CONFIG["monitored_networks"],
                "notifications": Config.DEFAULT_CONFIG["notifications"],
            },
            self.config_path,
        )

        config = Config.load(self.config_path)

        self.assertEqual(Config.get_database_path(config), "custom.sqlite")


if __name__ == "__main__":
    unittest.main()
