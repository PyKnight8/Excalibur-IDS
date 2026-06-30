import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from excalibur import env


class EnvironmentLoadingTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.env_path = Path(self.temp_dir.name) / ".env"
        self._original_values = {}
        for key in (
            "OTX_API_KEY",
            "OTX_REFRESH_HOURS",
            "EXCALIBUR_ERL_DEBUG_RULES",
        ):
            self._original_values[key] = os.environ.get(key)
            os.environ.pop(key, None)
        env._loaded_paths.clear()

    def tearDown(self):
        env._loaded_paths.clear()
        for key, value in self._original_values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temp_dir.cleanup()

    def test_load_environment_reads_dotenv_file(self):
        self.env_path.write_text(
            "OTX_API_KEY=TEST_KEY\n"
            "OTX_REFRESH_HOURS=24\n",
            encoding="utf-8",
        )

        loaded = env.load_environment(self.env_path)

        self.assertTrue(loaded)
        self.assertEqual(os.environ.get("OTX_API_KEY"), "TEST_KEY")
        self.assertEqual(os.environ.get("OTX_REFRESH_HOURS"), "24")

    def test_load_environment_does_not_override_existing_variables(self):
        os.environ["OTX_API_KEY"] = "EXISTING_KEY"
        self.env_path.write_text("OTX_API_KEY=DOTENV_KEY\n", encoding="utf-8")

        env.load_environment(self.env_path)

        self.assertEqual(os.environ.get("OTX_API_KEY"), "EXISTING_KEY")

    def test_load_environment_only_loads_each_path_once(self):
        self.env_path.write_text("OTX_API_KEY=FIRST\n", encoding="utf-8")

        first_loaded = env.load_environment(self.env_path)
        self.env_path.write_text("OTX_API_KEY=SECOND\n", encoding="utf-8")
        second_loaded = env.load_environment(self.env_path)

        self.assertTrue(first_loaded)
        self.assertFalse(second_loaded)
        self.assertEqual(os.environ.get("OTX_API_KEY"), "FIRST")

    def test_load_environment_returns_false_when_file_missing(self):
        loaded = env.load_environment(self.env_path)

        self.assertFalse(loaded)
        self.assertIsNone(os.environ.get("OTX_API_KEY"))


if __name__ == "__main__":
    unittest.main()
