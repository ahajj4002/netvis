#!/usr/bin/env python3
"""NIP technique registry.

This is the Phase 0.1 building block from NIP_Roadmap.md.pdf: every technique is
registered as a self-describing object (inputs/outputs, safety constraints, cost).

The registry is intentionally metadata-only. Execution stays in server.py via
coursework job runners and the multi-chain pipeline.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    scope: str  # l2, l3, l4, l7, passive, ids, pipeline, netvis
    module: str
    action: str
    description: str

    requires_root: bool = False
    requires_scapy: bool = False
    lab_only: bool = False  # spoofing/decoy steps
    status: str = "available"  # available | declined | not_implemented
    rationale: str = ""  # why declined / not implemented (optional)

    consumes: List[str] = field(default_factory=list)  # data dependencies
    provides: List[str] = field(default_factory=list)  # outputs produced
    tags: List[str] = field(default_factory=list)

    # Phase 0.1 roadmap fields
    mode: str = "active"           # "active" | "passive"
    stealth: float = 0.3           # 0.0 (loud) to 1.0 (silent)
    detection_profile: Dict[str, float] = field(default_factory=dict)  # IDS rule -> detection %
    estimated_time: str = "varies"  # human description e.g. "5-30s per host"


def default_registry() -> Dict[str, Technique]:
    reg: Dict[str, Technique] = {}

    def add(t: Technique) -> None:
        reg[t.id] = t

    # --------------------
    # Module 1: Link-layer
    # --------------------
    add(
        Technique(
            id="mod1.active_arp",
            name="Active ARP Enumeration",
            scope="l2",
            module="mod1",
            action="active",
            description="Broadcast ARP requests across a subnet and record ARP replies (IP->MAC).",
            requires_root=True,
            requires_scapy=True,
            consumes=["network.cidr", "interface"],
            provides=["assets.ip_mac", "assets.discovered"],
            tags=["rubric:1a", "active"],
            mode="active",
            stealth=0.2,
            detection_profile={"arp_sweep": 0.9, "ids_arp_scan": 0.6},
            estimated_time="2-10s per /24 subnet",
        )
    )
    add(
        Technique(
            id="mod1.passive_arp",
            name="Passive ARP Observation",
            scope="l2",
            module="mod1",
            action="passive",
            description="Sniff ARP traffic (promisc) to reconstruct IP->MAC without transmitting.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["assets.ip_mac", "assets.discovered"],
            tags=["rubric:1b", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds (no transmit)",
        )
    )
    add(
        Technique(
            id="mod1.mac_randomization",
            name="MAC Address Randomization Session",
            scope="l2",
            module="mod1",
            action="randomized",
            description="Run active ARP using a randomized locally-administered source MAC.",
            requires_root=True,
            requires_scapy=True,
            consumes=["network.cidr", "interface"],
            provides=["assets.ip_mac", "assets.discovered"],
            tags=["rubric:1c", "active", "lab"],
            mode="active",
            stealth=0.4,
            detection_profile={"arp_sweep": 0.7},
            estimated_time="2-10s per /24 subnet",
        )
    )

    # --------------------
    # Module 2: Transport
    # --------------------
    add(
        Technique(
            id="mod2.tcp_syn",
            name="TCP SYN Scan (Half-Open)",
            scope="l4",
            module="mod2",
            action="syn",
            description="Send SYN; SYN-ACK=open; RST=closed; send RST to avoid handshake completion.",
            requires_root=True,
            requires_scapy=True,
            consumes=["targets.hosts", "targets.ports_tcp"],
            provides=["services.tcp_open"],
            tags=["rubric:2a", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={"suricata_port_scan": 1.0, "zeek_scan": 1.0},
            estimated_time="1-30s per host",
        )
    )
    add(
        Technique(
            id="mod2.tcp_connect",
            name="TCP Connect Scan (Baseline)",
            scope="l4",
            module="mod2",
            action="connect",
            description="Full three-way handshake via OS sockets; baseline for logging/detection.",
            consumes=["targets.hosts", "targets.ports_tcp"],
            provides=["services.tcp_open"],
            tags=["rubric:2b", "active"],
            mode="active",
            stealth=0.1,
            detection_profile={"suricata_port_scan": 1.0, "zeek_scan": 1.0, "netflow_scan": 1.0},
            estimated_time="1-30s per host",
        )
    )
    add(
        Technique(
            id="mod2.tcp_fin",
            name="TCP FIN Scan",
            scope="l4",
            module="mod2",
            action="fin",
            description="FIN-only probe; closed ports respond RST per RFC793; open may drop.",
            requires_root=True,
            requires_scapy=True,
            consumes=["targets.hosts", "targets.ports_tcp"],
            provides=["services.tcp_state_inference"],
            tags=["rubric:2c", "active"],
            mode="active",
            stealth=0.5,
            detection_profile={"suricata_port_scan": 0.6, "zeek_scan": 0.8},
            estimated_time="1-30s per host",
        )
    )
    add(
        Technique(
            id="mod2.tcp_xmas",
            name="TCP XMAS Scan",
            scope="l4",
            module="mod2",
            action="xmas",
            description="FIN+PSH+URG flags; RFC793 closed->RST; open->drop.",
            requires_root=True,
            requires_scapy=True,
            consumes=["targets.hosts", "targets.ports_tcp"],
            provides=["services.tcp_state_inference"],
            tags=["rubric:2d", "active"],
            mode="active",
            stealth=0.5,
            detection_profile={"suricata_xmas": 0.9, "zeek_scan": 0.8},
            estimated_time="1-30s per host",
        )
    )
    add(
        Technique(
            id="mod2.tcp_null",
            name="TCP NULL Scan",
            scope="l4",
            module="mod2",
            action="null",
            description="No TCP flags; RFC793 closed->RST; open->drop.",
            requires_root=True,
            requires_scapy=True,
            consumes=["targets.hosts", "targets.ports_tcp"],
            provides=["services.tcp_state_inference"],
            tags=["rubric:2e", "active"],
            mode="active",
            stealth=0.5,
            detection_profile={"suricata_null": 0.9, "zeek_scan": 0.7},
            estimated_time="1-30s per host",
        )
    )
    add(
        Technique(
            id="mod2.udp_scan",
            name="UDP Scan",
            scope="l4",
            module="mod2",
            action="udp",
            description="Empty/app-specific UDP probes; ICMP port unreachable=closed; silence=open|filtered.",
            requires_root=True,
            requires_scapy=True,
            consumes=["targets.hosts", "targets.ports_udp"],
            provides=["services.udp_state_inference"],
            tags=["rubric:2f", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={"suricata_port_scan": 0.7},
            estimated_time="5-60s per host",
        )
    )
    add(
        Technique(
            id="mod2.tcp_ack",
            name="TCP ACK Scan (Firewall Mapping)",
            scope="l4",
            module="mod2",
            action="ack",
            description="ACK-only probe; RST=unfiltered; silence/ICMP=filtered. Maps firewall behavior.",
            requires_root=True,
            requires_scapy=True,
            consumes=["targets.hosts", "targets.ports_tcp"],
            provides=["firewall.inference"],
            tags=["rubric:2g", "active"],
            mode="active",
            stealth=0.4,
            detection_profile={"suricata_port_scan": 0.5},
            estimated_time="1-30s per host",
        )
    )

    # --------------------
    # Module 3: IP-layer
    # --------------------
    add(
        Technique(
            id="mod3.fragmentation",
            name="IP Fragmentation Test",
            scope="l3",
            module="mod3",
            action="frag",
            description="Fragment probe packets so TCP header spans multiple fragments (optional overlap).",
            requires_root=True,
            requires_scapy=True,
            consumes=["target.ip", "target.port"],
            provides=["ip.reassembly_observations"],
            tags=["rubric:3a", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={"suricata_frag": 0.4},
            estimated_time="1-5s per target",
        )
    )
    add(
        Technique(
            id="mod3.ttl_path",
            name="TTL-Based Path Inference",
            scope="l3",
            module="mod3",
            action="ttl",
            description="Traceroute-like TTL increments; collect ICMP time exceeded to infer path topology.",
            requires_root=True,
            requires_scapy=True,
            consumes=["target.ip"],
            provides=["path.hops"],
            tags=["rubric:3b", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={"icmp_ttl_exceeded": 0.3},
            estimated_time="5-30s per target",
        )
    )
    add(
        Technique(
            id="mod3.ipid_profile",
            name="IPID Sequence Profiling",
            scope="l3",
            module="mod3",
            action="ipid",
            description="Probe a host repeatedly and classify IPID increment behavior (global/sequential vs random).",
            requires_root=True,
            requires_scapy=True,
            consumes=["zombie.ip"],
            provides=["ipid.classification"],
            tags=["rubric:3c", "active"],
            mode="active",
            stealth=0.4,
            detection_profile={},
            estimated_time="5-15s per host",
        )
    )
    add(
        Technique(
            id="mod3.ipid_sweep",
            name="IPID Sweep (Find Suitable Zombies)",
            scope="l3",
            module="mod3",
            action="ipid-sweep",
            description="Profile IPID behavior across many hosts to find sequential candidates faster.",
            requires_root=True,
            requires_scapy=True,
            consumes=["network.cidr"],
            provides=["ipid.candidates"],
            tags=["rubric:3c", "active"],
            mode="active",
            stealth=0.4,
            detection_profile={},
            estimated_time="10-60s per /24 subnet",
        )
    )
    add(
        Technique(
            id="mod3.idle_scan",
            name="Idle Scan (Lab Only)",
            scope="l3",
            module="mod3",
            action="idle",
            description="Classic idle scan using a third-party zombie host (spoofed source). Lab-only.",
            requires_root=True,
            requires_scapy=True,
            lab_only=True,
            consumes=["zombie.ip", "target.ip", "target.port"],
            provides=["services.tcp_state_inference"],
            tags=["rubric:3c", "lab", "spoofing"],
            mode="active",
            stealth=0.8,
            detection_profile={},
            estimated_time="10-60s per target",
        )
    )
    add(
        Technique(
            id="mod3.decoy_mixing",
            name="Decoy Source Mixing (Lab Only)",
            scope="l3",
            module="mod3",
            action="decoy",
            description="Interleave real probes with spoofed-source packets to study defender attribution. Lab-only.",
            requires_root=True,
            requires_scapy=True,
            lab_only=True,
            consumes=["target.ip", "target.port", "decoys[]"],
            provides=["defender_log_perspective"],
            tags=["rubric:3d", "lab", "spoofing"],
            mode="active",
            stealth=0.6,
            detection_profile={},
            estimated_time="5-30s per target",
        )
    )

    # --------------------
    # Module 4: Timing
    # --------------------
    add(
        Technique(
            id="mod4.fixed_rates",
            name="Fixed-Rate Scan Profiles",
            scope="l4",
            module="mod4",
            action="fixed",
            description="Run identical scans at multiple fixed rates and record scan timing distributions.",
            requires_root=True,
            requires_scapy=True,
            consumes=["targets.tuples"],
            provides=["timing.profile_results"],
            tags=["rubric:4a"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-30s per host",
        )
    )
    add(
        Technique(
            id="mod4.jitter",
            name="Randomized Jitter Experiment",
            scope="l4",
            module="mod4",
            action="jitter",
            description="Compare fixed delay vs uniform vs exponential jitter with same average rate.",
            requires_root=True,
            requires_scapy=True,
            consumes=["targets.tuples"],
            provides=["timing.jitter_results"],
            tags=["rubric:4b"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-30s per host",
        )
    )
    add(
        Technique(
            id="mod4.ordering",
            name="Target Ordering Randomization",
            scope="l4",
            module="mod4",
            action="order",
            description="Compare sequential vs shuffled (host,port) ordering for detection heuristics.",
            requires_root=True,
            requires_scapy=True,
            consumes=["targets.tuples"],
            provides=["timing.ordering_results"],
            tags=["rubric:4c"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-30s per host",
        )
    )

    # --------------------
    # Module 5: App
    # --------------------
    add(
        Technique(
            id="mod5.banner",
            name="Banner Grabbing",
            scope="l7",
            module="mod5",
            action="banner",
            description="Connect and read initial server banners to infer service/version hints.",
            consumes=["target.ip", "targets.ports_tcp"],
            provides=["services.banner"],
            tags=["rubric:5a"],
            mode="active",
            stealth=0.3,
            detection_profile={"ids_banner": 0.2},
            estimated_time="1-5s per port",
        )
    )
    add(
        Technique(
            id="mod5.tls",
            name="TLS Certificate Inspection",
            scope="l7",
            module="mod5",
            action="tls",
            description="TLS handshake and parse X.509 chain for CN/SAN/issuer/validity/key size.",
            consumes=["target.ip", "target.port"],
            provides=["tls.certificate_intel"],
            tags=["rubric:5b"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-5s per target",
        )
    )
    add(
        Technique(
            id="mod5.http_headers",
            name="HTTP Header Analysis",
            scope="l7",
            module="mod5",
            action="http",
            description="HTTP GET / and analyze response headers, security headers, caching indicators.",
            consumes=["target.ip", "target.port"],
            provides=["http.header_intel"],
            tags=["rubric:5c"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-5s per target",
        )
    )
    add(
        Technique(
            id="mod5.tcp_fingerprint",
            name="TCP Stack Fingerprinting",
            scope="l4",
            module="mod5",
            action="tcpfp",
            description="Crafted TCP/IP probes + heuristic matching for OS fingerprint guess.",
            requires_root=True,
            requires_scapy=True,
            consumes=["target.ip", "target.port"],
            provides=["os.fingerprint"],
            tags=["rubric:5d"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="5-15s per target",
        )
    )
    add(
        Technique(
            id="mod5.dns_enum",
            name="DNS Enumeration",
            scope="l7",
            module="mod5",
            action="dns",
            description="Query A/AAAA/MX/NS/TXT/SRV/CNAME; attempt AXFR; reverse DNS for discovered IPs.",
            consumes=["domain", "dns.server"],
            provides=["dns.records", "dns.reverse"],
            tags=["rubric:5e"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-10s per query",
        )
    )
    add(
        Technique(
            id="mod5.passive_dns",
            name="Passive DNS Monitor",
            scope="passive",
            module="mod5",
            action="passive-dns",
            description="Promisc sniff of UDP/53 queries on local segment; aggregates top domains.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["dns.passive"],
            tags=["rubric:5e", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )

    # --------------------
    # Module 6: Passive
    # --------------------
    add(
        Technique(
            id="mod6.promisc",
            name="Promiscuous-Mode Traffic Capture",
            scope="passive",
            module="mod6",
            action="promisc",
            description="Capture visible frames and extract L2/L3/L4/L7 metadata; optional PCAP output.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["traffic.flows", "assets.discovered"],
            tags=["rubric:6a", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="mod6.pcap_ingest",
            name="SPAN/Mirror (PCAP) Ingestion",
            scope="passive",
            module="mod6",
            action="pcap",
            description="Parse a PCAP file and extract passive L2-L7 metadata (SPAN/mirror simulation).",
            consumes=["pcap.path"],
            provides=["traffic.flows", "assets.discovered"],
            tags=["rubric:6b"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )
    add(
        Technique(
            id="mod6.netflow_collect",
            name="NetFlow v5 Collection",
            scope="passive",
            module="mod6",
            action="netflow",
            description="Receive NetFlow v5 exports and summarize top talkers/long flows/scanning patterns.",
            requires_root=True,
            requires_scapy=True,
            consumes=["netflow.listen_port", "duration_seconds"],
            provides=["netflow.records", "traffic.matrix"],
            tags=["rubric:6c"],
            mode="passive",
            stealth=0.9,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )

    # --------------------
    # Module 7: Detection
    # --------------------
    add(
        Technique(
            id="mod7.arpwatch",
            name="ARPwatch-Style Monitoring",
            scope="ids",
            module="mod7",
            action="arpwatch",
            description="Detect ARP table changes and MAC/IP anomalies over time.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["alerts.arp"],
            tags=["rubric:7c"],
            mode="passive",
            stealth=0.9,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="mod7.suricata_offline",
            name="Suricata Offline (PCAP)",
            scope="ids",
            module="mod7",
            action="suricata-offline",
            description="Run Suricata against a PCAP with bundled rules; write eve.json for correlation.",
            consumes=["pcap.path"],
            provides=["ids.suricata.eve"],
            tags=["rubric:7a"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )
    add(
        Technique(
            id="mod7.zeek_offline",
            name="Zeek Offline (PCAP)",
            scope="ids",
            module="mod7",
            action="zeek-offline",
            description="Run Zeek against a PCAP with bundled script; write notice.log for correlation.",
            consumes=["pcap.path"],
            provides=["ids.zeek.notice"],
            tags=["rubric:7b"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )
    add(
        Technique(
            id="mod7.netflow_detect",
            name="NetFlow v5 Detection (Alerting)",
            scope="ids",
            module="mod7",
            action="netflow-detect",
            description="Classify scanning patterns and emit timestamped alerts from flow exports.",
            requires_root=True,
            requires_scapy=True,
            consumes=["netflow.listen_port", "duration_seconds"],
            provides=["alerts.netflow"],
            tags=["rubric:7c"],
            mode="passive",
            stealth=0.9,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="mod7.detection_matrix",
            name="Detection Matrix Correlation",
            scope="ids",
            module="mod7",
            action="detection-matrix",
            description="Correlate scan log windows with Suricata/Zeek outputs; produce per-technique/per-rule rates.",
            consumes=["logs.mod*", "ids.suricata.eve?", "ids.zeek.notice?"],
            provides=["report.detection_matrix"],
            tags=["rubric:7"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )

    # --------------------
    # NIP extensions (safe coverage from the missing-techniques sheet)
    # --------------------

    # IPv6
    add(
        Technique(
            id="ipv6.neighbor_discovery",
            name="IPv6 Neighbor Discovery",
            scope="l2",
            module="ipv6",
            action="nd-scan",
            description="Discover IPv6-enabled devices on-link via ICMPv6 all-nodes probing.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface"],
            provides=["assets.ipv6_mac", "assets.discovered"],
            tags=["nip:ipv6", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={"suricata_icmp": 0.5},
            estimated_time="2-10s per subnet",
        )
    )
    add(
        Technique(
            id="ipv6.router_advertisement_scan",
            name="IPv6 Router Advertisement Scan",
            scope="l2",
            module="ipv6",
            action="ra-scan",
            description="Send Router Solicitation and capture Router Advertisements (routers/prefixes/DNS hints).",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface"],
            provides=["ipv6.routers", "ipv6.prefixes", "ipv6.dns_servers"],
            tags=["nip:ipv6", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={"suricata_icmp": 0.5},
            estimated_time="2-10s per subnet",
        )
    )
    add(
        Technique(
            id="ipv6.passive_ndp",
            name="Passive IPv6 NDP Monitor",
            scope="passive",
            module="ipv6",
            action="passive-ndp",
            description="Passively sniff ICMPv6 NDP/RA traffic to build IPv6 inventory and detect DAD events.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["assets.ipv6_mac", "ipv6.events"],
            tags=["nip:ipv6", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="ipv6.slaac_fingerprint",
            name="IPv6 SLAAC Address Fingerprinting",
            scope="l3",
            module="ipv6",
            action="slaac-fp",
            description="Classify IPv6 address generation and derive MAC from EUI-64 when present.",
            consumes=["assets.ipv6_addresses"],
            provides=["ipv6.address_policy", "assets.derived_mac"],
            tags=["nip:ipv6", "analysis"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="<1s",
        )
    )

    # DHCP
    add(
        Technique(
            id="dhcp.passive_monitor",
            name="Passive DHCP Monitor",
            scope="passive",
            module="dhcp",
            action="passive-dhcp",
            description="Sniff DHCP exchanges to map leases, hostnames, vendor class, and lease details.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["dhcp.leases", "assets.hostname", "assets.vendor_class"],
            tags=["nip:dhcp", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="dhcp.fingerprint",
            name="DHCP Fingerprinting",
            scope="l7",
            module="dhcp",
            action="fingerprint",
            description="Infer OS family from DHCP parameter request list and vendor-class hints.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["os.dhcp_fingerprint"],
            tags=["nip:dhcp", "analysis"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="dhcp.rogue_detection",
            name="Rogue DHCP Server Detection",
            scope="ids",
            module="dhcp",
            action="rogue-detect",
            description="Send DHCP Discover and alert when unexpected/multiple DHCP Offers are observed.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "dhcp.known_server_ip"],
            provides=["alerts.rogue_dhcp"],
            tags=["nip:dhcp", "ids", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="2-10s",
        )
    )

    # Discovery protocols
    add(
        Technique(
            id="discovery.mdns",
            name="mDNS / Bonjour Discovery",
            scope="l7",
            module="discovery",
            action="mdns",
            description="Actively query mDNS service catalog to enumerate service types/devices.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface"],
            provides=["assets.mdns_services", "assets.hostname"],
            tags=["nip:discovery", "active"],
            mode="active",
            stealth=0.4,
            detection_profile={},
            estimated_time="2-10s",
        )
    )
    add(
        Technique(
            id="discovery.mdns_passive",
            name="Passive mDNS Monitor",
            scope="passive",
            module="discovery",
            action="mdns-passive",
            description="Passively monitor mDNS advertisements and service records.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["assets.mdns_services", "assets.hostname"],
            tags=["nip:discovery", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="discovery.ssdp_upnp",
            name="SSDP/UPnP Discovery",
            scope="l7",
            module="discovery",
            action="ssdp",
            description="Discover UPnP devices via SSDP M-SEARCH and parse description XML when available.",
            consumes=["interface"],
            provides=["assets.upnp_devices", "assets.manufacturer", "assets.model", "assets.firmware"],
            tags=["nip:discovery", "active"],
            mode="active",
            stealth=0.4,
            detection_profile={},
            estimated_time="2-10s",
        )
    )
    add(
        Technique(
            id="discovery.nbns",
            name="NetBIOS Name Service Query",
            scope="l7",
            module="discovery",
            action="nbns",
            description="Query NBNS node status to recover Windows host naming metadata.",
            consumes=["targets.hosts"],
            provides=["assets.netbios_name"],
            tags=["nip:discovery", "active"],
            mode="active",
            stealth=0.4,
            detection_profile={},
            estimated_time="1-5s per host",
        )
    )
    add(
        Technique(
            id="discovery.llmnr",
            name="LLMNR Passive Monitor",
            scope="passive",
            module="discovery",
            action="llmnr-passive",
            description="Passively monitor LLMNR to collect hostnames and failed name lookups.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["assets.hostname", "dns.failed_lookups"],
            tags=["nip:discovery", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="discovery.wsd",
            name="WS-Discovery Scan",
            scope="l7",
            module="discovery",
            action="wsd",
            description="Probe WS-Discovery multicast and parse device type/endpoints.",
            consumes=["interface"],
            provides=["assets.wsd_devices", "assets.device_type"],
            tags=["nip:discovery", "active"],
            mode="active",
            stealth=0.4,
            detection_profile={},
            estimated_time="2-10s",
        )
    )

    # ICMP
    add(
        Technique(
            id="icmp.echo_sweep",
            name="ICMP Echo Sweep",
            scope="l3",
            module="icmp",
            action="echo-sweep",
            description="ICMP ping sweep across a private CIDR with RTT collection.",
            requires_root=True,
            requires_scapy=True,
            consumes=["network.cidr"],
            provides=["assets.alive_hosts", "icmp.rtt"],
            tags=["nip:icmp", "active"],
            mode="active",
            stealth=0.2,
            detection_profile={"suricata_icmp": 0.5},
            estimated_time="5-30s per /24 subnet",
        )
    )
    add(
        Technique(
            id="icmp.timestamp",
            name="ICMP Timestamp Request",
            scope="l3",
            module="icmp",
            action="timestamp",
            description="Send ICMP timestamp request and capture timestamp-reply behavior.",
            requires_root=True,
            requires_scapy=True,
            consumes=["target.ip"],
            provides=["icmp.timestamp", "os.timezone_hint"],
            tags=["nip:icmp", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={"suricata_icmp": 0.5},
            estimated_time="1-5s per target",
        )
    )
    add(
        Technique(
            id="icmp.address_mask",
            name="ICMP Address Mask Request",
            scope="l3",
            module="icmp",
            action="address-mask",
            description="Send ICMP address mask request to detect legacy responders and subnet hints.",
            requires_root=True,
            requires_scapy=True,
            consumes=["target.ip"],
            provides=["network.subnet_mask_hint"],
            tags=["nip:icmp", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={"suricata_icmp": 0.5},
            estimated_time="1-5s per target",
        )
    )
    add(
        Technique(
            id="icmp.os_fingerprint",
            name="ICMP-Based OS Fingerprinting",
            scope="l3",
            module="icmp",
            action="icmp-os-fp",
            description="Infer OS class from ICMP echo reply TTL/DF/IPID behavior.",
            requires_root=True,
            requires_scapy=True,
            consumes=["target.ip"],
            provides=["os.icmp_fingerprint", "os.ttl_class"],
            tags=["nip:icmp", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={"suricata_icmp": 0.5},
            estimated_time="5-15s per target",
        )
    )

    # SMB / Windows
    add(
        Technique(
            id="smb.enum_shares",
            name="SMB Share Enumeration",
            scope="l7",
            module="smb",
            action="enum-shares",
            description="Enumerate SMB shares using available local tooling (guest/null where allowed).",
            consumes=["target.ip"],
            provides=["smb.shares", "smb.permissions"],
            tags=["nip:smb", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-10s per target",
        )
    )
    add(
        Technique(
            id="smb.enum_sessions",
            name="SMB Session Enumeration",
            scope="l7",
            module="smb",
            action="enum-sessions",
            description="Best-effort enumeration of SMB session/user metadata via rpcclient/nmap when available.",
            consumes=["target.ip"],
            provides=["smb.sessions"],
            tags=["nip:smb", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-10s per target",
        )
    )
    add(
        Technique(
            id="smb.os_discovery",
            name="SMB OS Discovery",
            scope="l7",
            module="smb",
            action="os-discovery",
            description="Gather OS/hostname/domain hints from SMB negotiation/script output.",
            consumes=["target.ip"],
            provides=["os.smb_fingerprint", "assets.hostname", "assets.domain"],
            tags=["nip:smb", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-10s per target",
        )
    )

    # IoT
    add(
        Technique(
            id="iot.mqtt_enum",
            name="MQTT Broker Enumeration",
            scope="l7",
            module="iot",
            action="mqtt-enum",
            description="Anonymous MQTT connect + wildcard subscribe to observe advertised topics/messages.",
            consumes=["target.ip", "target.port"],
            provides=["iot.mqtt_topics", "iot.mqtt_payloads"],
            tags=["nip:iot", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-10s per target",
        )
    )
    add(
        Technique(
            id="iot.coap_discovery",
            name="CoAP Resource Discovery",
            scope="l7",
            module="iot",
            action="coap-discover",
            description="CoAP GET /.well-known/core to enumerate exposed resources on IoT devices.",
            consumes=["target.ip", "target.port"],
            provides=["iot.coap_resources"],
            tags=["nip:iot", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-10s per target",
        )
    )

    # TLS encrypted traffic
    add(
        Technique(
            id="tls.ja3_fingerprint",
            name="JA3 TLS Client Fingerprinting",
            scope="passive",
            module="tls",
            action="ja3",
            description="Compute JA3 from observed ClientHello fields without decryption.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["tls.ja3_fingerprints"],
            tags=["nip:tls", "nip:encrypted", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="tls.ja3s_fingerprint",
            name="JA3S TLS Server Fingerprinting",
            scope="passive",
            module="tls",
            action="ja3s",
            description="Compute JA3S from observed ServerHello fields without decryption.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["tls.ja3s_fingerprints"],
            tags=["nip:tls", "nip:encrypted", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="tls.traffic_classification",
            name="Encrypted Traffic Statistical Classification",
            scope="passive",
            module="tls",
            action="traffic-classify",
            description="Label encrypted flow behavior from timing/size statistics (heuristic lab model).",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["traffic.application_labels", "traffic.confidence_scores"],
            tags=["nip:tls", "nip:encrypted", "nip:analysis", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )

    # VLAN / L2 discovery (passive)
    add(
        Technique(
            id="vlan.discovery",
            name="VLAN Discovery (CDP/LLDP/DTP Sniffing)",
            scope="l2",
            module="vlan",
            action="discover",
            description="Passively sniff CDP/LLDP/DTP to infer VLAN and switch metadata.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["vlan.ids", "switch.model", "switch.mgmt_ip", "vlan.native"],
            tags=["nip:vlan", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )

    # SSH deep analysis
    add(
        Technique(
            id="ssh.host_key_fingerprint",
            name="SSH Host Key Fingerprinting",
            scope="l7",
            module="ssh",
            action="host-key-fp",
            description="Collect SSH host key fingerprints and key types as persistent identifiers.",
            consumes=["target.ip", "target.port"],
            provides=["ssh.host_key_fingerprint", "ssh.key_types"],
            tags=["nip:ssh", "active"],
            mode="active",
            stealth=0.4,
            detection_profile={},
            estimated_time="1-5s per target",
        )
    )
    add(
        Technique(
            id="ssh.algorithm_audit",
            name="SSH Algorithm Security Audit",
            scope="l7",
            module="ssh",
            action="algo-audit",
            description="Audit SSH KEX/cipher/MAC offerings (nmap script when available; fallback key-type checks).",
            consumes=["target.ip", "target.port"],
            provides=["ssh.algorithm_audit", "ssh.weak_algorithms"],
            tags=["nip:ssh", "active"],
            mode="active",
            stealth=0.4,
            detection_profile={},
            estimated_time="1-5s per target",
        )
    )

    # DNS advanced
    add(
        Technique(
            id="dns.tunnel_detection",
            name="DNS Tunneling Detection",
            scope="passive",
            module="dns",
            action="tunnel-detect",
            description="Detect high-entropy/long-label DNS patterns and suspicious query rates.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["alerts.dns_tunnel", "dns.tunnel_domains"],
            tags=["nip:dns", "nip:analysis", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="dns.doh_dot_detection",
            name="DNS-over-HTTPS/TLS Detection",
            scope="passive",
            module="dns",
            action="doh-detect",
            description="Detect DoH/DoT usage from TLS SNI/port observations.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["dns.doh_users", "dns.monitoring_gaps"],
            tags=["nip:dns", "nip:analysis", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )
    add(
        Technique(
            id="dns.dga_detection",
            name="Domain Generation Algorithm Detection",
            scope="passive",
            module="dns",
            action="dga-detect",
            description="Score queried domains for DGA-like lexical characteristics.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface", "duration_seconds"],
            provides=["alerts.dga", "dns.dga_confidence"],
            tags=["nip:dns", "nip:analysis", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )

    # SNMP
    add(
        Technique(
            id="snmp.walk",
            name="SNMP Walk",
            scope="l7",
            module="snmp",
            action="walk",
            description="Read-only SNMP walk for system/interface/routing metadata (mode dependent).",
            consumes=["target.ip", "snmp.community"],
            provides=["snmp.system", "snmp.interface_table", "snmp.routing_table"],
            tags=["nip:snmp", "active"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="5-30s per target",
        )
    )

    # WiFi passive
    add(
        Technique(
            id="wifi.passive_scan",
            name="WiFi Passive Scan",
            scope="l2",
            module="wifi",
            action="passive-scan",
            description="Capture beacon/probe management frames to inventory SSIDs/BSSIDs/clients.",
            requires_root=True,
            requires_scapy=True,
            consumes=["interface.wireless", "duration_seconds"],
            provides=["wifi.ssids", "wifi.bssids", "wifi.clients", "wifi.probe_history"],
            tags=["nip:wifi", "passive"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="duration_seconds",
        )
    )

    # Analysis / inference
    add(
        Technique(
            id="analysis.baseline_compute",
            name="Behavioral Baseline Computation",
            scope="passive",
            module="analysis",
            action="compute-baseline",
            description="Compute per-device decayed behavioral baseline from historical metric windows.",
            consumes=["traffic.metrics_historical", "device.id"],
            provides=["baseline.device_profile", "baseline.active_hours"],
            tags=["nip:analysis", "nip:temporal"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )
    add(
        Technique(
            id="analysis.anomaly_score",
            name="Multi-Factor Anomaly Scoring",
            scope="passive",
            module="analysis",
            action="anomaly-score",
            description="Score current behavior vs baseline across volume, destination novelty, ports, and off-hours.",
            consumes=["traffic.current_observation", "baseline.device_profile"],
            provides=["anomaly.score", "anomaly.factors"],
            tags=["nip:analysis", "nip:temporal"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="<1s",
        )
    )
    add(
        Technique(
            id="analysis.identity_resolution",
            name="Device Identity Resolution",
            scope="passive",
            module="analysis",
            action="identity-resolve",
            description="Match a new device to prior candidates using behavioral feature similarity.",
            consumes=["device.new", "graph.inactive_devices"],
            provides=["identity.match", "identity.confidence"],
            tags=["nip:analysis", "nip:identity"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )
    add(
        Technique(
            id="analysis.community_detection",
            name="Traffic Community Detection",
            scope="passive",
            module="analysis",
            action="community-detect",
            description="Detect traffic communities from graph structure via label propagation.",
            consumes=["graph.traffic_edges"],
            provides=["community.clusters"],
            tags=["nip:analysis", "nip:graph"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )
    add(
        Technique(
            id="analysis.risk_score",
            name="Multi-Factor Risk Scoring",
            scope="passive",
            module="analysis",
            action="risk-score",
            description="Compute per-device risk score using exposure, anomalies, topology, and threat matches.",
            consumes=["device.id", "services", "alerts", "threat.matches"],
            provides=["risk.score", "risk.factors", "risk.recommendation"],
            tags=["nip:analysis", "nip:risk"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )
    add(
        Technique(
            id="analysis.attack_chain",
            name="Attack Chain Reconstruction",
            scope="passive",
            module="analysis",
            action="attack-chain",
            description="Build a staged narrative from alerts + observations.",
            consumes=["alerts.recent", "observations.recent"],
            provides=["attack_chain.pattern", "attack_chain.narrative"],
            tags=["nip:analysis", "nip:incident"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )
    add(
        Technique(
            id="analysis.temporal_correlation",
            name="Temporal Event Correlation",
            scope="passive",
            module="analysis",
            action="temporal-correlate",
            description="Correlate observations/metrics around an anchor event timestamp.",
            consumes=["alert.anchor", "timeseries.events"],
            provides=["correlation.timeline", "correlation.related_events"],
            tags=["nip:analysis", "nip:temporal"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )
    add(
        Technique(
            id="analysis.graph_diff",
            name="Knowledge Graph Time Diff",
            scope="passive",
            module="analysis",
            action="graph-diff",
            description="Compare asset/service/flow graph snapshots between two timestamps.",
            consumes=["graph.snapshot_t1", "graph.snapshot_t2"],
            provides=["graph.diff"],
            tags=["nip:analysis", "nip:temporal"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-5s per device",
        )
    )

    # Threat intel
    add(
        Technique(
            id="threat.cve_lookup",
            name="CVE Vulnerability Lookup",
            scope="l7",
            module="threat",
            action="cve-lookup",
            description="Query NVD CVE API for product/version vulnerability metadata.",
            consumes=["services.product", "services.version"],
            provides=["services.cve_list", "services.max_cvss"],
            tags=["nip:threat", "nip:external"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-10s per query (network)",
        )
    )
    add(
        Technique(
            id="threat.ip_reputation",
            name="IP Reputation Check",
            scope="l7",
            module="threat",
            action="ip-reputation",
            description="Check IPs against locally-synchronized indicator feeds.",
            consumes=["ip.list"],
            provides=["threat.ip_matches"],
            tags=["nip:threat", "nip:external"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-10s per query (network)",
        )
    )
    add(
        Technique(
            id="threat.domain_reputation",
            name="Domain Reputation Check",
            scope="l7",
            module="threat",
            action="domain-reputation",
            description="Check domains against indicator feeds and DGA-style lexical heuristics.",
            consumes=["dns.queried_domains"],
            provides=["threat.domain_matches", "threat.dga_scores"],
            tags=["nip:threat", "nip:external"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-10s per query (network)",
        )
    )
    add(
        Technique(
            id="threat.feed_sync",
            name="Threat Feed Synchronization",
            scope="l7",
            module="threat",
            action="feed-sync",
            description="Merge local threat feeds and run retroactive indicator matching.",
            consumes=["threat.feed_paths"],
            provides=["threat.indicators_updated", "threat.retroactive_matches"],
            tags=["nip:threat", "nip:external"],
            mode="passive",
            stealth=1.0,
            detection_profile={},
            estimated_time="1-10s per query (network)",
        )
    )

    # --------------------
    # Declined techniques (explicitly tracked for transparency)
    # --------------------
    add(
        Technique(
            id="evasion.ids_threshold_discovery",
            name="IDS Threshold Discovery (Declined)",
            scope="l4",
            module="evasion",
            action="threshold-discover",
            description="Adaptive probing to discover IDS thresholds.",
            status="declined",
            rationale="Not implemented: covert/evasion behavior is out of scope for safe coursework support.",
            tags=["nip:evasion", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="evasion.response_classifier",
            name="Probe Response Classifier (Declined)",
            scope="l4",
            module="evasion",
            action="classify-response",
            description="Classify defensive responses to optimize evasive scanning.",
            status="declined",
            rationale="Not implemented: covert/evasion behavior is out of scope for safe coursework support.",
            tags=["nip:evasion", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="evasion.traffic_model_builder",
            name="Traffic Model Builder (Declined)",
            scope="passive",
            module="evasion",
            action="build-traffic-model",
            description="Build traffic camouflage templates for stealth scanning.",
            status="declined",
            rationale="Not implemented: covert/evasion behavior is out of scope for safe coursework support.",
            tags=["nip:evasion", "declined"],
            mode="passive",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="evasion.morphed_syn_scan",
            name="Morphed SYN Scan (Declined)",
            scope="l4",
            module="evasion",
            action="morphed-syn",
            description="Traffic-morphed SYN scan intended to evade detection.",
            status="declined",
            rationale="Not implemented: covert/evasion behavior is out of scope for safe coursework support.",
            tags=["nip:evasion", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="evasion.morphed_fin_scan",
            name="Morphed FIN Scan (Declined)",
            scope="l4",
            module="evasion",
            action="morphed-fin",
            description="Traffic-morphed FIN scan intended to evade detection.",
            status="declined",
            rationale="Not implemented: covert/evasion behavior is out of scope for safe coursework support.",
            tags=["nip:evasion", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="evasion.morph_validation",
            name="Traffic Morph Validation (Declined)",
            scope="passive",
            module="evasion",
            action="validate-morph",
            description="Statistical validation of scan camouflage against baseline traffic.",
            status="declined",
            rationale="Not implemented: covert/evasion behavior is out of scope for safe coursework support.",
            tags=["nip:evasion", "declined"],
            mode="passive",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="evasion.http_impersonation",
            name="HTTP Impersonation Scan (Declined)",
            scope="l7",
            module="evasion",
            action="http-impersonate",
            description="Protocol impersonation intended to mask scanning activity.",
            status="declined",
            rationale="Not implemented: covert/evasion behavior is out of scope for safe coursework support.",
            tags=["nip:evasion", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="evasion.ssh_impersonation",
            name="SSH Impersonation Scan (Declined)",
            scope="l7",
            module="evasion",
            action="ssh-impersonate",
            description="Protocol impersonation intended to mask scanning activity.",
            status="declined",
            rationale="Not implemented: covert/evasion behavior is out of scope for safe coursework support.",
            tags=["nip:evasion", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="evasion.smtp_impersonation",
            name="SMTP Impersonation Scan (Declined)",
            scope="l7",
            module="evasion",
            action="smtp-impersonate",
            description="Protocol impersonation intended to mask scanning activity.",
            status="declined",
            rationale="Not implemented: covert/evasion behavior is out of scope for safe coursework support.",
            tags=["nip:evasion", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="dhcp.starvation_test",
            name="DHCP Starvation Test (Declined)",
            scope="l2",
            module="dhcp",
            action="starvation",
            description="Attempt to exhaust DHCP pools by mass lease requests.",
            lab_only=True,
            status="declined",
            rationale="Not implemented: disruptive network-denial behavior is out of scope.",
            tags=["nip:dhcp", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="iot.telnet_default_creds",
            name="Telnet Default Credential Check (Declined)",
            scope="l7",
            module="iot",
            action="telnet-defaults",
            description="Credential-guessing check against Telnet services.",
            lab_only=True,
            status="declined",
            rationale="Not implemented: credential-guessing behavior is out of scope.",
            tags=["nip:iot", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="vlan.double_tag",
            name="VLAN Double Tagging (Declined)",
            scope="l2",
            module="vlan",
            action="double-tag",
            description="VLAN hopping via double-tagged frames.",
            lab_only=True,
            status="declined",
            rationale="Not implemented: active bypass/attack behavior is out of scope.",
            tags=["nip:vlan", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="vlan.dtp_negotiation",
            name="DTP Trunk Negotiation (Declined)",
            scope="l2",
            module="vlan",
            action="dtp-negotiate",
            description="Attempt to force trunking via DTP misconfiguration abuse.",
            lab_only=True,
            status="declined",
            rationale="Not implemented: active bypass/attack behavior is out of scope.",
            tags=["nip:vlan", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="l2.cam_overflow",
            name="CAM Table Overflow (Declined)",
            scope="l2",
            module="vlan",
            action="cam-overflow",
            description="Flood switch CAM table with spoofed MAC addresses.",
            lab_only=True,
            status="declined",
            rationale="Not implemented: disruptive L2 flooding behavior is out of scope.",
            tags=["nip:l2", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="snmp.community_bruteforce",
            name="SNMP Community Bruteforce (Declined)",
            scope="l7",
            module="snmp",
            action="community-brute",
            description="Bruteforce SNMP community strings.",
            lab_only=True,
            status="declined",
            rationale="Not implemented: credential brute-force behavior is out of scope.",
            tags=["nip:snmp", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )
    add(
        Technique(
            id="wifi.deauth_test",
            name="WiFi Deauthentication Test (Declined)",
            scope="l2",
            module="wifi",
            action="deauth-test",
            description="Force WiFi client deauthentication/reassociation.",
            lab_only=True,
            status="declined",
            rationale="Not implemented: disruptive wireless attack behavior is out of scope.",
            tags=["nip:wifi", "declined"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="varies",
        )
    )

    # --------------------
    # Pipeline: multi-chain
    # --------------------
    add(
        Technique(
            id="pipeline.multichain",
            name="Multi-Chain Discovery Pipeline",
            scope="pipeline",
            module="pipeline",
            action="multichain",
            description="Run staged recon chain and synthesize a casefile + narrative story.",
            requires_root=True,
            requires_scapy=True,
            consumes=["network.cidr", "interface"],
            provides=["report.casefile", "report.story", "assets.fused_profiles"],
            tags=["nip:chain"],
            mode="active",
            stealth=0.3,
            detection_profile={},
            estimated_time="1-10min",
        )
    )

    return reg


def registry_as_list(registry: Dict[str, Technique]) -> List[dict]:
    return [asdict(t) for t in sorted(registry.values(), key=lambda x: x.id)]
