from dataclasses import dataclass

from excalibur.events.base import BaseEvent


@dataclass
class DnsEvent(BaseEvent):
    """DNS metadata emitted alongside existing DNS processing."""

    client_ip: str = ""
    dns_server_ip: str = ""
    query_name: str = ""
    query_type: str = ""
    dns_rcode: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    risk_reasons: str | None = None

    def __init__(
        self,
        timestamp,
        client_ip,
        dns_server_ip,
        query_name,
        query_type,
        dns_rcode=None,
        risk_score=None,
        risk_level=None,
        risk_reasons=None,
    ):
        super().__init__(event_type="dns_event", timestamp=timestamp)
        self.client_ip = client_ip
        self.dns_server_ip = dns_server_ip
        self.query_name = query_name
        self.query_type = query_type
        self.dns_rcode = dns_rcode
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.risk_reasons = risk_reasons

