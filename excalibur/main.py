import os
import sys
import traceback
from pathlib import Path
from threading import Event, enumerate as enumerate_threads

import psutil


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


def _safe_process_value(getter, default=None):
    try:
        return getter()
    except (psutil.Error, OSError):
        return default


def _is_service_tree_process(process):
    name = str(_safe_process_value(process.name, "") or "").lower()
    exe = str(_safe_process_value(process.exe, "") or "").lower().replace("\\", "/")
    cmdline = " ".join(_safe_process_value(process.cmdline, []) or []).lower().replace(
        "\\", "/"
    )
    return (
        "python" in name
        or "python" in exe
        or "excalibur" in name
        or "excalibur" in exe
        or "excalibur" in cmdline
    )


def _service_tree_root(process):
    current = process
    while True:
        parent = _safe_process_value(current.parent)
        if parent is None or not _is_service_tree_process(parent):
            return current
        current = parent


def _walk_tree(process):
    nodes = [process]
    for child in _safe_process_value(lambda: process.children(), []) or []:
        nodes.extend(_walk_tree(child))
    return nodes


def _log_process_snapshot(label):
    process = psutil.Process(os.getpid())
    root = _service_tree_root(process)
    print(f"[ProcTree] {label}", flush=True)
    print(f"[ProcTree]   current_pid={process.pid}", flush=True)
    print(f"[ProcTree]   root_pid={root.pid}", flush=True)
    print(
        "[ProcTree]   threads="
        f"{[(thread.name, thread.ident) for thread in enumerate_threads()]}",
        flush=True,
    )
    for node in _walk_tree(root):
        if not _is_service_tree_process(node):
            continue
        memory_info = _safe_process_value(node.memory_info)
        print(f"[ProcTree]   pid={node.pid}", flush=True)
        print(
            f"[ProcTree]     parent_pid={getattr(_safe_process_value(node.parent), 'pid', None)}",
            flush=True,
        )
        print(f"[ProcTree]     name={_safe_process_value(node.name)}", flush=True)
        print(f"[ProcTree]     exe={_safe_process_value(node.exe)}", flush=True)
        print(
            f"[ProcTree]     cmdline={' '.join(_safe_process_value(node.cmdline, []) or [])}",
            flush=True,
        )
        print(
            f"[ProcTree]     create_time={_safe_process_value(node.create_time)}",
            flush=True,
        )
        print(
            f"[ProcTree]     rss_bytes={getattr(memory_info, 'rss', None)}",
            flush=True,
        )
        print(
            "[ProcTree]     cpu_percent_raw="
            f"{_safe_process_value(lambda node=node: node.cpu_percent(interval=None))}",
            flush=True,
        )
        print(
            f"[ProcTree]     thread_count={_safe_process_value(node.num_threads)}",
            flush=True,
        )
        print(
            f"[ProcTree]     children={[getattr(child, 'pid', None) for child in (_safe_process_value(node.children, []) or [])]}",
            flush=True,
        )


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
        print(
            "[Startup] "
            f"config_path={config_path} "
            f"rules_path={rules_path} "
            f"signature_rules_dir={signature_rules_dir} "
            f"database_path={database_path} "
            f"interface={interface!r}",
            flush=True,
        )
        _log_process_snapshot("after_init")

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
            _log_process_snapshot("before_plugin_startup")
            self.plugin_manager.load_plugins()
            self.plugin_manager.startup_plugins()
            _log_process_snapshot("before_sniffer_start")
            self.sniffer.start()
            _log_process_snapshot("after_sniffer_start")
            print("[+] Packet sniffer started", flush=True)
            print("[+] Excalibur running", flush=True)

            while not self._shutdown_event.is_set():
                self._shutdown_event.wait(timeout=0.5)
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            print(f"[ERROR] Sensor startup/runtime failure: {exc}", flush=True)
            print(traceback.format_exc(), flush=True)
            raise
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
