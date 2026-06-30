from excalibur.plugins.base import Plugin


class Plugin(Plugin):
    name = "Hello World"

    def handle_event(self, event, context):
        context.logger.info(f"received {event.event_type}")

