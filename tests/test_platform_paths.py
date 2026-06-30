import os
from pathlib import Path
import unittest
from unittest.mock import patch

from excalibur import paths


class PlatformPathsTest(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=True)
    @patch("excalibur.paths.platform.system", return_value="Linux")
    def test_linux_defaults(self, _system):
        self.assertEqual(paths.app_dir(), Path("/opt/Excalibur"))
        self.assertEqual(paths.data_dir(), Path("/var/lib/excalibur"))
        self.assertEqual(paths.log_dir(), Path("/var/log/excalibur"))
        self.assertEqual(
            paths.database_path(),
            Path("/var/lib/excalibur/excalibur.sqlite"),
        )
        self.assertEqual(paths.rules_dir(), Path("/var/lib/excalibur/rules"))
        self.assertEqual(paths.plugins_dir(), Path("/var/lib/excalibur/plugins"))

    @patch.dict(
        os.environ,
        {
            "ProgramFiles": r"C:\Program Files",
            "ProgramData": r"C:\ProgramData",
        },
        clear=True,
    )
    @patch("excalibur.paths.platform.system", return_value="Windows")
    def test_windows_defaults(self, _system):
        self.assertEqual(paths.app_dir(), Path(r"C:\Program Files") / "Excalibur")
        self.assertEqual(paths.data_dir(), Path(r"C:\ProgramData") / "Excalibur")
        self.assertEqual(paths.log_dir(), paths.data_dir() / "logs")
        self.assertEqual(paths.database_path(), paths.data_dir() / "excalibur.sqlite")
        self.assertEqual(paths.rules_dir(), paths.data_dir() / "rules")
        self.assertEqual(paths.plugins_dir(), paths.data_dir() / "plugins")

    @patch.dict(
        os.environ,
        {
            "EXCALIBUR_APP_DIR": "custom-app",
            "EXCALIBUR_DATA_DIR": "custom-data",
            "EXCALIBUR_LOG_DIR": "custom-logs",
            "EXCALIBUR_DATABASE_PATH": "custom-db.sqlite",
            "EXCALIBUR_RULES_DIR": "custom-rules",
            "EXCALIBUR_PLUGINS_DIR": "custom-plugins",
        },
        clear=True,
    )
    def test_environment_overrides(self):
        self.assertEqual(paths.app_dir(), Path("custom-app"))
        self.assertEqual(paths.data_dir(), Path("custom-data"))
        self.assertEqual(paths.log_dir(), Path("custom-logs"))
        self.assertEqual(paths.database_path(), Path("custom-db.sqlite"))
        self.assertEqual(paths.rules_dir(), Path("custom-rules"))
        self.assertEqual(paths.plugins_dir(), Path("custom-plugins"))


if __name__ == "__main__":
    unittest.main()
