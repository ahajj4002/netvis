"""
NetVis optional dependency flags.
Set after attempting to import scapy and nmap.
"""

try:
    from scapy.all import sniff, ARP, Ether, IP, TCP, UDP, ICMP, get_if_list, conf  # noqa: F401
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap  # noqa: F401
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
