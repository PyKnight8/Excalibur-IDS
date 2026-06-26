from dataclasses import dataclass

from excalibur.events.base import BaseEvent


@dataclass
class PacketEvent(BaseEvent):
    """Packet metadata emitted alongside existing packet processing."""

    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    packet_size: int = 0
    src_mac: str | None = None
    tcp_flags: str | None = None

    def __init__(
        self,
        timestamp,
        src_ip,
        dst_ip,
        protocol,
        src_port=None,
        dst_port=None,
        packet_size=0,
        src_mac=None,
        tcp_flags=None,
    ):
        super().__init__(event_type="packet_event", timestamp=timestamp)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.packet_size = packet_size
        self.src_mac = src_mac
        self.tcp_flags = tcp_flags

