from dataclasses import dataclass, field
from datetime import datetime, timezone


def _utc_timestamp():
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BaseEvent:
    """Base type for all internal Excalibur events."""

    event_type: str
    timestamp: str = field(default_factory=_utc_timestamp)

