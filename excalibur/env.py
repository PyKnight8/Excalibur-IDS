from pathlib import Path

from dotenv import load_dotenv


_loaded_paths = set()


def default_env_path():
    return Path(__file__).resolve().parent.parent / ".env"


def load_environment(env_path=None):
    path = Path(env_path) if env_path is not None else default_env_path()
    resolved_path = path.resolve()
    if resolved_path in _loaded_paths:
        return False
    _loaded_paths.add(resolved_path)
    if not resolved_path.exists():
        return False
    load_dotenv(resolved_path, override=False)
    return True

