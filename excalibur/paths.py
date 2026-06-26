import os
import platform
from pathlib import Path


def _is_windows():
    return platform.system().lower() == "windows"


def _environment_path(name):
    value = os.environ.get(name)
    return Path(value).expanduser() if value else None


def app_dir():
    override = _environment_path("EXCALIBUR_APP_DIR")
    if override is not None:
        return override
    if _is_windows():
        return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Excalibur"
    return Path("/opt/Excalibur")


def data_dir():
    override = _environment_path("EXCALIBUR_DATA_DIR")
    if override is not None:
        return override
    if _is_windows():
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Excalibur"
    return Path("/var/lib/excalibur")


def log_dir():
    override = _environment_path("EXCALIBUR_LOG_DIR")
    if override is not None:
        return override
    if _is_windows():
        return data_dir() / "logs"
    return Path("/var/log/excalibur")


def config_path():
    return _environment_path("EXCALIBUR_CONFIG_PATH") or data_dir() / "config.yaml"


def database_path(configured_path=None):
    override = _environment_path("EXCALIBUR_DATABASE_PATH")
    if override is not None:
        return override
    if configured_path:
        path = Path(configured_path).expanduser()
        return path if path.is_absolute() else data_dir() / path
    return data_dir() / "excalibur.sqlite"


def rules_config_path():
    return _environment_path("EXCALIBUR_RULES_CONFIG_PATH") or data_dir() / "rules.yaml"


def rules_dir():
    return _environment_path("EXCALIBUR_RULES_DIR") or data_dir() / "rules"


def plugins_dir():
    return _environment_path("EXCALIBUR_PLUGINS_DIR") or data_dir() / "plugins"


def runtime_path(environment_name, local_default, platform_default):
    """Use service layout paths only when explicitly configured by the installer."""
    return _environment_path(environment_name) or Path(local_default or platform_default)
