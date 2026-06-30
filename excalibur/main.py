import os
import sys
from pathlib import Path
from threading import Event


if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from excalibur.env import load_environment

load_environment()

from excalibur.database import Database
from excalibur.config import Config
from excalibur.detection.rules_config import RulesConfig
from excalibur.notifications import NotificationManager
from excalibur.paths import (
    config_path as platform_config_path,
    database_path as platform_database_path,
    plugins_dir as platform_plugins_dir,
    rules_config_path as platform_rules_config_path,
    rules_dir as platform_rules_dir,
    runtime_path,
)
from excalibur.plugins import EventBus, PluginManager
from excalibur.sensor import PacketSniffer


class ExcaliburApp:
    def __init__(
        self,
        db_path=None,
        interface=None,
        config_path=None,
        rules_path=None,
        signature_rules_dir=None,
    ):
        config_path = runtime_path(
            "EXCALIBUR_CONFIG_PATH", config_path or "config.yaml", platform_config_path()
        )
        rules_path = runtime_path(
            "EXCALIBUR_RULES_CONFIG_PATH",
            rules_path or "rules.yaml",
            platform_rules_config_path(),
        )
        signature_rules_dir = runtime_path(
            "EXCALIBUR_RULES_DIR",
            signature_rules_dir or "rules",
            platform_rules_dir(),
        )
        self.config = Config.load(config_path)
        self.rules = RulesConfig.load(rules_path)
        configured_database_path = Config.get_database_path(self.config)
        if db_path is not None:
            database_path = db_path
        elif "EXCALIBUR_DATA_DIR" in os.environ or "EXCALIBUR_DATABASE_PATH" in os.environ:
            database_path = platform_database_path(configured_database_path)
        else:
            database_path = configured_database_path
        self.database = Database(database_path, async_writes=True)
        self.database.reconcile_system_metrics()
        self.notification_manager = NotificationManager(self.config)
        self.database.set_notification_manager(self.notification_manager)
        self.event_bus = EventBus()
        self.database.set_event_bus(self.event_bus)
        self.plugin_manager = PluginManager(
            self.event_bus,
            (
                platform_plugins_dir()
                if "EXCALIBUR_PLUGINS_DIR" in os.environ
                else Path(config_path).resolve().parent / "plugins"
            ),
        )
        print("[+] Database initialized", flush=True)

        self.sniffer = PacketSniffer(
            database=self.database,
            interface=interface,
            config=self.config,
            rules=self.rules,
            signature_rules_dir=signature_rules_dir,
            event_bus=self.event_bus,
        )
        self._shutdown_event = Event()

    def run(self):
        try:
            self.plugin_manager.load_plugins()
            self.plugin_manager.startup_plugins()
            self.sniffer.start()
            print("[+] Packet sniffer started", flush=True)
            print("[+] Excalibur running", flush=True)

            while not self._shutdown_event.is_set():
                self._shutdown_event.wait(timeout=0.5)
        except KeyboardInterrupt:
            pass
        finally:
            print("[+] Shutting down", flush=True)
            self.sniffer.stop()
            self.plugin_manager.shutdown_plugins()
            self.database.close()


if __name__ == "__main__":
    try:
        app = ExcaliburApp()
        app.run()
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
