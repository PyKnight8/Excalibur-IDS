class Plugin:
    """Minimal base class for Excalibur plugins."""

    name = "Unnamed"

    def on_load(self):
        """Called once after the plugin is imported and instantiated."""

    def on_startup(self):
        """Called after all plugins are loaded and registered."""

    def on_shutdown(self):
        """Called during Excalibur shutdown."""

    def handle_event(self, event, context):
        """Handle a single event delivered by the plugin event bus."""

