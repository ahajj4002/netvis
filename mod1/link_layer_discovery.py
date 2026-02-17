#!/usr/bin/env python3
"""Module 1: Link-layer discovery techniques (NetVis toolkit)."""

from __future__ import annotations

import argparse
import ipaddress
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

from scapy.all import ARP, AsyncSniffer, Ether, conf, get_if_addr, get_if_hwaddr, sniff, sendp

from toolkit.utils import (
    elapsed_ms,
    hosts_from_network,
    infer_default_network,
    infer_local_ip,
    new_session_id,
    promisc_flag_on_interface,
    random_mac,
    tx_packets_on_interface,
    utc_now_iso,
    write_json_log,
)

conf.verb = 0


@dataclass
class ARPHost:
    ip: str
    mac: str
    first_seen: str
    last_seen: str
    seen_count: int = 1


def _vlan_boundary_heuristic(network: str, discovered_ips: List[str], local_ip: str) -> Dict[str, object]:
    """
    ARP is broadcast-domain limited. We estimate whether replies are constrained to local /24
    when scanning larger prefixes.
    """
    net = ipaddress.ip_network(network, strict=False)
    local_24 = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    out_of_local_24 = [ip for ip in discovered_ips if ipaddress.ip_address(ip) not in local_24]
    return {
        "network": str(net),
        "local_24": str(local_24),
        "responses_total": len(discovered_ips),
        "responses_outside_local_24": len(out_of_local_24),
        "outside_local_24_examples": out_of_local_24[:10],
        "interpretation": (
            "Likely limited to local broadcast domain"
            if len(out_of_local_24) == 0
            else "ARP replies observed beyond local /24 (possible bridged segments or expanded L2 domain)"
        ),
    }


def active_arp_enumeration(
    network: str,
    interface: Optional[str],
    probe_src_mac: Optional[str] = None,
    *,
    inter: float | None = None,
    batch_size: int | None = None,
    reply_wait: float = 2.0,
    max_hosts: int | None = None,
) -> Dict[str, object]:
    net = ipaddress.ip_network(network, strict=False)
    if net.prefixlen < 16:
        raise ValueError("Refusing to ARP-scan prefixes larger than /16 in coursework mode.")

    all_hosts = hosts_from_network(network, max_hosts=max_hosts)
    iface = interface or conf.iface
    try:
        local_ip = get_if_addr(iface) or infer_local_ip()
    except Exception:
        local_ip = infer_local_ip()
    scan_started_iso = utc_now_iso()
    start = time.time()

    # For small scans, a tight inter-packet delay is fine. For /16-scale sweeps,
    # introduce a small inter delay to reduce drops and keep the scan predictable.
    inter = (0.0 if len(all_hosts) <= 1024 else 0.002) if inter is None else max(0.0, float(inter))
    if batch_size is None:
        batch_size = 512 if len(all_hosts) > 1024 else 128
    batch_size = max(1, int(batch_size))

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_common = ARP(op=1, psrc=local_ip)

    real_src_mac = None
    try:
        real_src_mac = get_if_hwaddr(iface)
    except Exception:
        real_src_mac = None

    chosen_src_mac = probe_src_mac or real_src_mac
    if chosen_src_mac:
        ether.src = chosen_src_mac
        # Match the ARP sender hardware address to the Ethernet source.
        arp_common.hwsrc = chosen_src_mac

    host_map: Dict[str, ARPHost] = {}
    frame_count = 0

    def handler(pkt):
        nonlocal frame_count
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        if int(arp.op) != 2:
            return

        frame_count += 1
        now_iso = utc_now_iso()
        ip = str(arp.psrc)
        mac = str(arp.hwsrc)
        if ip not in host_map:
            host_map[ip] = ARPHost(ip=ip, mac=mac, first_seen=now_iso, last_seen=now_iso)
        else:
            host_map[ip].seen_count += 1
            host_map[ip].last_seen = now_iso

    sniffer = AsyncSniffer(
        iface=iface,
        filter="arp and arp[6:2] = 2",  # ARP reply
        prn=handler,
        store=False,
        promisc=True,
    )

    try:
        sniffer.start()

        # Stream packets in batches to avoid prebuilding huge packet lists for /16.
        for i in range(0, len(all_hosts), batch_size):
            batch = all_hosts[i : i + batch_size]
            pkts = []
            for ip in batch:
                arp = arp_common.copy()
                arp.pdst = ip
                pkts.append(ether / arp)
            sendp(pkts, iface=iface, inter=inter, verbose=0)

        # Give late replies a short window before stopping the sniffer.
        time.sleep(max(0.0, float(reply_wait)))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    duration_sec = max(0.0001, time.time() - start)
    response_rate = len(host_map) / max(1, len(all_hosts))

    return {
        "technique": "active_arp_enumeration",
        "network": network,
        "interface": str(iface),
        "local_ip": local_ip,
        "probe_src_mac": probe_src_mac,
        "scan_started": scan_started_iso,
        "scan_duration_seconds": duration_sec,
        "addresses_probed": len(all_hosts),
        "hosts_responded": len(host_map),
        "response_rate": response_rate,
        "time_per_probe_ms": (duration_sec / max(1, len(all_hosts))) * 1000.0,
        "frames_observed": frame_count,
        "send_profile": {"batch_size": batch_size, "inter_seconds": inter, "reply_wait_seconds": reply_wait},
        "hosts": [asdict(v) for v in sorted(host_map.values(), key=lambda h: h.ip)],
        "vlan_boundary_behavior": _vlan_boundary_heuristic(network, list(host_map.keys()), local_ip),
    }


def passive_arp_observation(interface: str, duration: int) -> Dict[str, object]:
    start_ts = time.time()
    end_ts = start_ts + duration

    promisc_before = promisc_flag_on_interface(interface)
    # Baseline TX counter for zero-transmit verification
    tx_before = tx_packets_on_interface(interface)

    table: Dict[str, ARPHost] = {}
    coverage_markers = {60: set(), 600: set(), 3600: set()}
    frame_count = 0

    def handler(pkt):
        nonlocal frame_count
        frame_count += 1
        now_iso = utc_now_iso()

        arp = pkt[ARP]
        ip = arp.psrc
        mac = arp.hwsrc

        if ip not in table:
            table[ip] = ARPHost(ip=ip, mac=mac, first_seen=now_iso, last_seen=now_iso)
        else:
            table[ip].seen_count += 1
            table[ip].last_seen = now_iso

        elapsed = time.time() - start_ts
        for marker in coverage_markers:
            if elapsed <= marker:
                coverage_markers[marker].add(ip)

    sniff(
        iface=interface,
        filter="arp",
        prn=handler,
        store=False,
        timeout=duration,
        promisc=True,
    )

    promisc_after = promisc_flag_on_interface(interface)
    tx_after = tx_packets_on_interface(interface)
    tx_delta = (tx_after - tx_before) if (tx_before >= 0 and tx_after >= 0) else None

    packets_per_sec = frame_count / max(1.0, duration)

    return {
        "technique": "passive_arp_observation",
        "interface": str(interface),
        "capture_duration_seconds": duration,
        "capture_elapsed_ms": elapsed_ms(start_ts),
        "promiscuous_mode_requested": True,
        "promiscuous_flag_before": promisc_before,
        "promiscuous_flag_after": promisc_after,
        "frames_observed": frame_count,
        "frames_per_second": packets_per_sec,
        "zero_transmit_verification": {
            "interface_tx_packets_before": tx_before,
            "interface_tx_packets_after": tx_after,
            "interface_tx_delta": tx_delta,
            "tool_generated_packets": 0,
            "note": "TX delta may include background host traffic; tool itself sends no packets in passive mode.",
        },
        "coverage": {
            "hosts_seen_total": len(table),
            "hosts_seen_within_1_min": len(coverage_markers[60]),
            "hosts_seen_within_10_min": len(coverage_markers[600]),
            "hosts_seen_within_1_hour": len(coverage_markers[3600]),
        },
        "ip_mac_table": [asdict(v) for v in sorted(table.values(), key=lambda h: h.ip)],
    }


def mac_randomization_session(
    network: str,
    interface: Optional[str],
    *,
    inter: float | None = None,
    batch_size: int | None = None,
    reply_wait: float = 2.0,
    max_hosts: int | None = None,
) -> Dict[str, object]:
    iface = interface or conf.iface
    session_mac = random_mac()
    try:
        real_mac = get_if_hwaddr(iface)
    except Exception:
        real_mac = None
    active = active_arp_enumeration(
        network=network,
        interface=iface,
        probe_src_mac=session_mac,
        inter=inter,
        batch_size=batch_size,
        reply_wait=reply_wait,
        max_hosts=max_hosts,
    )

    return {
        "technique": "mac_address_randomization",
        "network": network,
        "interface": str(iface),
        "real_interface_mac": real_mac,
        "randomized_probe_mac": session_mac,
        "scan_result": active,
        "switch_behavior_observation_template": {
            "cam_table_expected_effect": "Switch may learn randomized source on ingress port during session.",
            "port_security_risk": "Strict MAC binding/802.1X may block or alert on MAC changes.",
            "arpwatch_correlation_effect": "Repeated scans with changing source MAC reduce simple host-based correlation."
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Module 1: Link-layer discovery")
    parser.add_argument("--interface", default=None, help="Interface to use (default: scapy default)")

    sub = parser.add_subparsers(dest="mode", required=True)

    p_active = sub.add_parser("active", help="Run active ARP enumeration")
    p_active.add_argument("--network", default=infer_default_network(), help="Target subnet CIDR (supports /24 and /16)")
    p_active.add_argument("--inter", type=float, default=None, help="Inter-packet delay seconds (default: auto)")
    p_active.add_argument("--batch-size", type=int, default=None, help="Packets per send batch (default: auto)")
    p_active.add_argument("--reply-wait", type=float, default=2.0, help="Seconds to wait for replies after sending probes")
    p_active.add_argument("--max-hosts", type=int, default=None, help="Limit targets (demo/debug). Leave unset for full sweep.")

    p_passive = sub.add_parser("passive", help="Run passive ARP observation")
    p_passive.add_argument("--duration", type=int, default=600, help="Capture duration in seconds")

    p_rand = sub.add_parser("randomized", help="Run active ARP scan with randomized probe MAC")
    p_rand.add_argument("--network", default=infer_default_network(), help="Target subnet CIDR")
    p_rand.add_argument("--inter", type=float, default=None, help="Inter-packet delay seconds (default: auto)")
    p_rand.add_argument("--batch-size", type=int, default=None, help="Packets per send batch (default: auto)")
    p_rand.add_argument("--reply-wait", type=float, default=2.0, help="Seconds to wait for replies after sending probes")
    p_rand.add_argument("--max-hosts", type=int, default=None, help="Limit targets (demo/debug). Leave unset for full sweep.")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.mode == "active":
        session = new_session_id("mod1-active")
        result = active_arp_enumeration(
            args.network,
            args.interface,
            inter=args.inter,
            batch_size=args.batch_size,
            reply_wait=args.reply_wait,
            max_hosts=args.max_hosts,
        )
        out = write_json_log("mod1", session, result)
        print(f"[mod1] active ARP complete: {result['hosts_responded']} hosts, log={out}")
        return 0

    if args.mode == "passive":
        session = new_session_id("mod1-passive")
        result = passive_arp_observation(interface=args.interface or conf.iface, duration=args.duration)
        out = write_json_log("mod1", session, result)
        print(f"[mod1] passive ARP complete: {result['coverage']['hosts_seen_total']} hosts, log={out}")
        return 0

    if args.mode == "randomized":
        session = new_session_id("mod1-randomized")
        # Forward timing knobs to the underlying active sweep via mac_randomization_session.
        result = mac_randomization_session(
            args.network,
            args.interface,
            inter=args.inter,
            batch_size=args.batch_size,
            reply_wait=args.reply_wait,
            max_hosts=args.max_hosts,
        )
        out = write_json_log("mod1", session, result)
        hosts = result["scan_result"]["hosts_responded"]
        print(f"[mod1] randomized-MAC ARP complete: {hosts} hosts, log={out}")
        return 0

    raise ValueError("Unknown mode")


if __name__ == "__main__":
    raise SystemExit(main())
