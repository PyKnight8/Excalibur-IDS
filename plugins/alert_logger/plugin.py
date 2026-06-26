from excalibur.plugins.base import Plugin


class Plugin(Plugin):
    name = "Alert Logger"

    def handle_event(self, event, context):
        if event.event_type != "alert_event":
            return
        context.logger.info(f"received alert_event for alert #{event.alert_id}")

