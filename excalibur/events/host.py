from dataclasses import dataclass

from excalibur.events.base import BaseEvent


@dataclass
class HostEvent(BaseEvent):
    """Placeholder host event type for the initial plugin framework."""

    ip_address: str = ""
    mac_address: str | None = None

    def __init__(self, timestamp, ip_address, mac_address=None):
        super().__init__(event_type="host_event", timestamp=timestamp)
        self.ip_address = ip_address
        self.mac_address = mac_address

