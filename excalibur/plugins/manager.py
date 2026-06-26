from dataclasses import dataclass
import importlib.util
from pathlib import Path

from excalibur.plugins.base import Plugin
from excalibur.plugins.context import PluginContext


@dataclass
class PluginMetadata:
    name: str
    plugin_id: str
    version: str
    entrypoint: str
    author: str = ""
    description: str = ""
    enabled: bool = True


@dataclass
class PluginRecord:
    metadata: PluginMetadata
    instance: Plugin
    context: PluginContext
    path: Path


class PluginManager:
    """Discovers and loads trusted local plugins from the plugins directory."""

    REQUIRED_FIELDS = ("name", "id", "version", "entrypoint")

    def __init__(self, event_bus, plugins_dir):
        self.event_bus = event_bus
        self.plugins_dir = Path(plugins_dir)
        self.plugins = []
        self._loaded_plugin_ids = set()

    def load_plugins(self):
        if not self.plugins_dir.exists():
            return

        for plugin_dir in sorted(path for path in self.plugins_dir.iterdir() if path.is_dir()):
            self._load_plugin(plugin_dir)

    def startup_plugins(self):
        for record in self.plugins:
            try:
                record.instance.on_startup()
            except Exception as exc:
                print(
                    f"[PLUGIN] Startup failed for plugin '{record.metadata.name}': {exc}",
                    flush=True,
                )

    def shutdown_plugins(self):
        for record in self.plugins:
            try:
                record.instance.on_shutdown()
            except Exception as exc:
                print(
                    f"[PLUGIN] Shutdown failed for plugin '{record.metadata.name}': {exc}",
                    flush=True,
                )

    def _load_plugin(self, plugin_dir):
        metadata = self._load_metadata(plugin_dir / "plugin.yaml")
        if metadata is None:
            return
        if not metadata.enabled or metadata.plugin_id in self._loaded_plugin_ids:
            return

        entrypoint_path = self._resolve_entrypoint(plugin_dir, metadata.entrypoint)
        if entrypoint_path is None:
            print(
                f"[PLUGIN] Skipping plugin '{metadata.name}': invalid entrypoint",
                flush=True,
            )
            return

        try:
            module = self._load_module(metadata.plugin_id, entrypoint_path)
            plugin_class = getattr(module, "Plugin", None)
            if not isinstance(plugin_class, type) or not issubclass(plugin_class, Plugin):
                raise TypeError("plugin.py must define a Plugin class")

            instance = plugin_class()
            if getattr(instance, "name", "Unnamed") == "Unnamed":
                instance.name = metadata.name
            context = PluginContext(self.event_bus, instance.name)
            instance.on_load()
            self.event_bus.subscribe(
                "*",
                lambda event, plugin=instance, plugin_context=context: plugin.handle_event(
                    event,
                    plugin_context,
                ),
            )
            record = PluginRecord(
                metadata=metadata,
                instance=instance,
                context=context,
                path=plugin_dir,
            )
            self.plugins.append(record)
            self._loaded_plugin_ids.add(metadata.plugin_id)
            print(f"[PLUGIN] Loaded plugin '{metadata.name}'", flush=True)
            print(f"[PLUGIN] Registered plugin '{metadata.name}'", flush=True)
        except Exception as exc:
            print(
                f"[PLUGIN] Failed to load plugin '{metadata.name}': {exc}",
                flush=True,
            )

    def _load_metadata(self, metadata_path):
        if not metadata_path.exists():
            print(f"[PLUGIN] Skipping plugin at '{metadata_path.parent}': missing plugin.yaml", flush=True)
            return None

        data = {}
        for raw_line in metadata_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            data[key.strip()] = self._parse_scalar(value.strip())

        missing = [field for field in self.REQUIRED_FIELDS if not data.get(field)]
        if missing:
            print(
                f"[PLUGIN] Skipping plugin at '{metadata_path.parent}': missing {', '.join(missing)}",
                flush=True,
            )
            return None

        return PluginMetadata(
            name=str(data["name"]),
            plugin_id=str(data["id"]),
            version=str(data["version"]),
            entrypoint=str(data["entrypoint"]),
            author=str(data.get("author", "")),
            description=str(data.get("description", "")),
            enabled=bool(data.get("enabled", True)),
        )

    def _parse_scalar(self, value):
        if value == "":
            return ""
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            return value[1:-1]
        return value

    def _resolve_entrypoint(self, plugin_dir, entrypoint):
        entrypoint_path = (plugin_dir / entrypoint).resolve()
        plugin_root = plugin_dir.resolve()
        if plugin_root not in entrypoint_path.parents and entrypoint_path != plugin_root:
            return None
        if not entrypoint_path.exists() or not entrypoint_path.is_file():
            return None
        return entrypoint_path

    def _load_module(self, plugin_id, entrypoint_path):
        module_name = f"excalibur_plugin_{plugin_id}"
        spec = importlib.util.spec_from_file_location(module_name, entrypoint_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"unable to create import spec for {entrypoint_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

