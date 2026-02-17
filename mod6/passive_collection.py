#!/usr/bin/env python3
"""Module 6: Passive collection methods (NetVis toolkit).

Implements:
- 6a Promiscuous-mode traffic capture and multi-layer parsing
- 6b SPAN/mirror port ingestion (supports pcap file ingestion as simulated SPAN)
- 6c NetFlow v5 collector + aggregation analytics

Outputs structured JSON logs under logs/mod6/.
"""

from __future__ import annotations

import argparse
import socket
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

from scapy.all import Ether, IP, TCP, UDP, ARP, Raw, conf, sniff, rdpcap

from toolkit.utils import (
    infer_local_ip,
    new_session_id,
    percentile,
    promisc_flag_on_interface,
    tx_packets_on_interface,
    utc_now_iso,
    write_json_log,
)

conf.verb = 0


APP_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}


def _parse_packets(packets) -> Dict[str, object]:
    macs = set()
    ips = set()
    ttl_values = []

    flow_bytes = defaultdict(int)
    flow_pkts = defaultdict(int)

    ip_bytes = defaultdict(int)

    l7_apps = defaultdict(int)

    arp_pairs = set()

    for p in packets:
        if p.haslayer(Ether):
            macs.add(p[Ether].src)
            macs.add(p[Ether].dst)

        if p.haslayer(ARP):
            arp_pairs.add((p[ARP].psrc, p[ARP].hwsrc))

        if not p.haslayer(IP):
            continue

        ip = p[IP]
        ips.add(ip.src)
        ips.add(ip.dst)
        ttl_values.append(int(ip.ttl))

        proto = "IP"
        sport = 0
        dport = 0
        if p.haslayer(TCP):
            proto = "TCP"
            sport = int(p[TCP].sport)
            dport = int(p[TCP].dport)
        elif p.haslayer(UDP):
            proto = "UDP"
            sport = int(p[UDP].sport)
            dport = int(p[UDP].dport)

        app = APP_PORTS.get(dport) or APP_PORTS.get(sport) or "Unknown"
        l7_apps[app] += len(p)

        key = f"{ip.src}:{sport}->{ip.dst}:{dport}/{proto}"
        flow_bytes[key] += len(p)
        flow_pkts[key] += 1
        ip_bytes[ip.src] += len(p)
        ip_bytes[ip.dst] += len(p)

    top_talkers = sorted(ip_bytes.items(), key=lambda x: -x[1])[:15]

    matrix = defaultdict(lambda: defaultdict(int))
    for key, b in flow_bytes.items():
        # parse src/dst
        try:
            left, rest = key.split("->", 1)
            src_ip = left.split(":", 1)[0]
            dst_ip = rest.split(":", 1)[0]
            matrix[src_ip][dst_ip] += b
        except Exception:
            pass

    return {
        "unique_macs": len(macs),
        "unique_ips": len(ips),
        "macs": sorted(list(macs))[:200],
        "ips": sorted(list(ips))[:500],
        "ttl_stats": {
            "count": len(ttl_values),
            "p50": percentile(ttl_values, 50),
            "p95": percentile(ttl_values, 95),
        },
        "flows": [
            {
                "flow_key": k,
                "bytes": flow_bytes[k],
                "packets": flow_pkts[k],
            }
            for k in sorted(flow_bytes.keys())
        ],
        "flow_count": len(flow_bytes),
        "traffic_matrix": {src: dict(dst) for src, dst in matrix.items()},
        "top_talkers": [{"ip": ip, "bytes": b} for ip, b in top_talkers],
        "application_bytes": dict(sorted(l7_apps.items(), key=lambda x: -x[1])[:20]),
        "arp_ip_mac_pairs": [{"ip": ip, "mac": mac} for ip, mac in sorted(list(arp_pairs))[:200]],
    }


def promisc_capture(interface: str, duration: int, bpf: str = "", pcap_out: str = "") -> Dict[str, object]:
    promisc_before = promisc_flag_on_interface(interface)
    tx_before = tx_packets_on_interface(interface)
    start = time.time()

    packets = sniff(
        iface=interface,
        filter=bpf or None,
        timeout=duration,
        store=True,
        promisc=True,
    )

    elapsed = time.time() - start
    promisc_after = promisc_flag_on_interface(interface)
    tx_after = tx_packets_on_interface(interface)
    tx_delta = (tx_after - tx_before) if (tx_before >= 0 and tx_after >= 0) else None

    pcap_written = ""
    if pcap_out:
        try:
            from pathlib import Path
            from scapy.utils import wrpcap

            out_path = Path(str(pcap_out)).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            wrpcap(str(out_path), packets)
            pcap_written = str(out_path)
        except Exception:
            pcap_written = ""

    analysis = _parse_packets(packets)

    return {
        "technique": "promiscuous_mode_capture",
        "interface": interface,
        "duration_seconds": duration,
        "bpf_filter": bpf,
        "pcap_out_requested": bool(pcap_out),
        "pcap_out": pcap_written,
        "pcap_packets_written": len(packets) if pcap_written else 0,
        "promiscuous_mode_requested": True,
        "promiscuous_flag_before": promisc_before,
        "promiscuous_flag_after": promisc_after,
        "packets_captured": len(packets),
        "elapsed_seconds": elapsed,
        "zero_transmit_verification": {
            "tx_before": tx_before,
            "tx_after": tx_after,
            "tx_delta": tx_delta,
            "tool_generated_packets": 0,
            "note": "Tool does not transmit; TX delta may include background host traffic.",
        },
        "analysis": analysis,
    }


def ingest_pcap(path: str) -> Dict[str, object]:
    packets = rdpcap(path)
    analysis = _parse_packets(packets)
    return {
        "technique": "span_pcap_ingestion",
        "pcap_path": path,
        "packets": len(packets),
        "analysis": analysis,
        "span_comparison_prompt": "Compare visibility (unique hosts/flows/apps) vs inline promisc capture.",
    }


# ------------------------------
# NetFlow v5 collector (6c)
# ------------------------------

@dataclass
class NetFlowV5Record:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    first_ms: int
    last_ms: int
    tcp_flags: int


def parse_netflow_v5_packet(data: bytes) -> List[NetFlowV5Record]:
    if len(data) < 24:
        return []
    version, count = struct.unpack(">HH", data[:4])
    if version != 5 or count <= 0:
        return []
    records = []
    offset = 24
    for _ in range(count):
        if offset + 48 > len(data):
            break
        rec = data[offset : offset + 48]
        # NetFlow v5 record is exactly 48 bytes (Cisco format).
        # Fields: srcaddr dstaddr nexthop input output dPkts dOctets first last srcport dstport pad1 tcp_flags prot tos src_as dst_as src_mask dst_mask pad2
        srcaddr, dstaddr, _nexthop, _input, _output, dpkts, doctets, first, last, sport, dport, _pad1, tcp_flags, prot, tos, src_as, dst_as, src_mask, dst_mask, _pad2 = struct.unpack(
            ">IIIHHIIIIHHBBBBHHBBH", rec
        )
        records.append(
            NetFlowV5Record(
                src_ip=socket.inet_ntoa(struct.pack(">I", srcaddr)),
                dst_ip=socket.inet_ntoa(struct.pack(">I", dstaddr)),
                src_port=int(sport),
                dst_port=int(dport),
                protocol=int(prot),
                packets=int(dpkts),
                bytes=int(doctets),
                first_ms=int(first),
                last_ms=int(last),
                tcp_flags=int(tcp_flags),
            )
        )
        offset += 48
    return records


def netflow_collect(listen_host: str, listen_port: int, duration: int) -> Dict[str, object]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_host, listen_port))
    sock.settimeout(1.0)

    start = time.time()
    records: List[NetFlowV5Record] = []

    while time.time() - start < duration:
        try:
            data, addr = sock.recvfrom(65535)
            records.extend(parse_netflow_v5_packet(data))
        except socket.timeout:
            continue
        except Exception:
            continue

    sock.close()

    # Aggregate
    matrix = defaultdict(lambda: defaultdict(int))
    ip_bytes = defaultdict(int)
    flow_key_bytes = defaultdict(int)
    src_unique_ports = defaultdict(set)

    long_flows = []

    for r in records:
        matrix[r.src_ip][r.dst_ip] += r.bytes
        ip_bytes[r.src_ip] += r.bytes
        ip_bytes[r.dst_ip] += r.bytes
        key = f"{r.src_ip}:{r.src_port}->{r.dst_ip}:{r.dst_port}/p{r.protocol}"
        flow_key_bytes[key] += r.bytes
        src_unique_ports[r.src_ip].add(r.dst_port)

        duration_ms = max(0, r.last_ms - r.first_ms)
        if duration_ms > 30_000:  # 30s in exporter uptime units
            long_flows.append({**asdict(r), "flow_duration_ms": duration_ms})

    top_talkers = sorted(ip_bytes.items(), key=lambda x: -x[1])[:15]

    scanning_suspects = []
    for src, ports in src_unique_ports.items():
        if len(ports) >= 20:
            scanning_suspects.append({"src_ip": src, "unique_dst_ports": len(ports), "ports_sample": sorted(list(ports))[:30]})

    return {
        "technique": "netflow_v5_collection",
        "listen": {"host": listen_host, "port": listen_port},
        "duration_seconds": duration,
        "records": len(records),
        "traffic_matrix": {src: dict(dst) for src, dst in matrix.items()},
        "top_talkers": [{"ip": ip, "bytes": b} for ip, b in top_talkers],
        "long_duration_flows": long_flows[:200],
        "scanning_patterns": scanning_suspects,
        "detail_level_notes": "NetFlow provides L3/L4 metadata but not L7 payloads; compare against full pcap visibility.",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Module 6: passive collection")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_prom = sub.add_parser("promisc")
    p_prom.add_argument("--interface", required=True)
    p_prom.add_argument("--duration", type=int, default=60)
    p_prom.add_argument("--bpf", default="")
    p_prom.add_argument("--pcap-out", default="", help="Optional path to write captured packets as a PCAP")

    p_pcap = sub.add_parser("pcap")
    p_pcap.add_argument("--path", required=True)

    p_nf = sub.add_parser("netflow")
    p_nf.add_argument("--listen-host", default="0.0.0.0")
    p_nf.add_argument("--listen-port", type=int, default=2055)
    p_nf.add_argument("--duration", type=int, default=60)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    session = new_session_id(f"mod6-{args.mode}")
    started_at = utc_now_iso()
    scanner_local_ip = infer_local_ip()

    if args.mode == "promisc":
        result = promisc_capture(args.interface, duration=args.duration, bpf=args.bpf, pcap_out=str(args.pcap_out or ""))
    elif args.mode == "pcap":
        result = ingest_pcap(args.path)
    elif args.mode == "netflow":
        result = netflow_collect(args.listen_host, args.listen_port, duration=args.duration)
    else:
        raise ValueError("Unknown mode")

    finished_at = utc_now_iso()
    out = write_json_log("mod6", session, {"started_at": started_at, "finished_at": finished_at, "scanner_local_ip": scanner_local_ip, "result": result})
    print(f"[mod6] {args.mode} complete. log={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
