"""
NetVis data models.
Dataclasses for devices, connections, DNS queries, and alerts.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Device:
    """Represents a network device."""

    ip: str
    mac: str = "unknown"
    hostname: str = ""
    vendor: str = ""
    os: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    service_banners: Dict[int, str] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""
    is_gateway: bool = False
    is_local: bool = False


@dataclass
class Connection:
    """Represents a connection between two devices."""

    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    packet_count: int = 0
    byte_count: int = 0
    last_seen: str = ""
    first_seen: str = ""
    services: List[str] = field(default_factory=list)
    application: str = ""  # Detected application layer protocol


@dataclass
class DNSQuery:
    """Represents a DNS query from a device."""

    src_ip: str
    domain: str
    query_type: str
    resolved_ip: str = ""
    timestamp: str = ""


@dataclass
class Alert:
    """Security alert."""

    alert_type: str
    severity: str  # low, medium, high, critical
    message: str
    src_ip: str = ""
    dst_ip: str = ""
    timestamp: str = ""
    details: Dict = field(default_factory=dict)
