from dataclasses import dataclass

from excalibur.events.base import BaseEvent


@dataclass
class AlertEvent(BaseEvent):
    """Placeholder alert event type for future plugin consumers."""

    alert_id: int | None = None
    title: str = ""
    severity: str = ""
    description: str = ""
    source_ip: str | None = None
    destination_ip: str | None = None
    context_json: str | None = None

    def __init__(
        self,
        timestamp,
        alert_id=None,
        title="",
        severity="",
        description="",
        source_ip=None,
        destination_ip=None,
        context_json=None,
    ):
        super().__init__(event_type="alert_event", timestamp=timestamp)
        self.alert_id = alert_id
        self.title = title
        self.severity = severity
        self.description = description
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.context_json = context_json
