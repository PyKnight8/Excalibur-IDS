class PluginLogger:
    def __init__(self, plugin_name):
        self.plugin_name = plugin_name

    def info(self, message):
        print(f"[PLUGIN] {self.plugin_name} {message}", flush=True)

    def warning(self, message):
        print(f"[PLUGIN] {self.plugin_name} {message}", flush=True)

    def error(self, message):
        print(f"[PLUGIN] {self.plugin_name} {message}", flush=True)


class PluginContext:
    """Controlled surface exposed to plugins."""

    def __init__(self, event_bus, plugin_name):
        self._event_bus = event_bus
        self.logger = PluginLogger(plugin_name)

    def emit_event(self, event):
        self._event_bus.emit(event)

