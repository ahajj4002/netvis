#!/usr/bin/env python3
"""IPv6 discovery techniques (NIP extensions).

Implements:
- ipv6.neighbor_discovery (active)
- ipv6.router_advertisement_scan (active)
- ipv6.passive_ndp (passive)
- ipv6.slaac_fingerprint (analysis)

All active techniques are intended for lab use and enforce private/local scoping
via the server runner's target guardrails.
"""

from __future__ import annotations

import argparse
import ipaddress
import time
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

from scapy.all import (
    AsyncSniffer,
    Ether,
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6NDOptPrefixInfo,
    conf,
    send,
)

from toolkit.utils import elapsed_ms, new_session_id, utc_now_iso, write_json_log

conf.verb = 0


@dataclass
class IPv6Host:
    ip: str
    mac: str
    first_seen: str
    last_seen: str
    seen_count: int = 1


def _mac_from_pkt(pkt) -> str:
    try:
        if pkt.haslayer(Ether):
            return str(pkt[Ether].src)
    except Exception:
        pass
    return ""


def ipv6_neighbor_discovery(interface: str, *, probes: int = 2, inter: float = 0.2, timeout: float = 3.0) -> Dict[str, object]:
    """Discover IPv6 devices on-link by pinging the all-nodes multicast.

    Practical lab approach: ICMPv6 Echo Request to ff02::1 and harvest Echo Replies.
    """
    iface = str(interface or conf.iface)
    start = time.time()
    started_at = utc_now_iso()

    hosts: Dict[str, IPv6Host] = {}
    frames = 0

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(IPv6):
                return
            if not pkt.haslayer(ICMPv6EchoReply):
                return
            frames += 1
            ip = str(pkt[IPv6].src)
            if not ip:
                return
            mac = _mac_from_pkt(pkt)
            now = utc_now_iso()
            if ip not in hosts:
                hosts[ip] = IPv6Host(ip=ip, mac=mac, first_seen=now, last_seen=now)
            else:
                h = hosts[ip]
                h.seen_count += 1
                h.last_seen = now
                if mac and not h.mac:
                    h.mac = mac
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="icmp6", prn=handler, store=False, promisc=True)

    try:
        sniffer.start()
        # Trigger on-link devices to respond.
        send(IPv6(dst="ff02::1") / ICMPv6EchoRequest(), iface=iface, count=max(1, int(probes)), inter=max(0.0, float(inter)), verbose=0)
        time.sleep(max(0.0, float(timeout)))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    duration = max(0.0001, time.time() - start)
    return {
        "technique": "ipv6_neighbor_discovery",
        "interface": iface,
        "started_at": started_at,
        "scan_duration_seconds": duration,
        "probes_sent": int(probes),
        "frames_observed": frames,
        "hosts_discovered": len(hosts),
        "hosts": [asdict(v) for v in sorted(hosts.values(), key=lambda h: h.ip)],
    }


def ipv6_router_advertisement_scan(interface: str, *, probes: int = 2, inter: float = 0.2, timeout: float = 3.0) -> Dict[str, object]:
    """Send Router Solicitation to ff02::2 and collect Router Advertisements."""
    iface = str(interface or conf.iface)
    start = time.time()
    started_at = utc_now_iso()

    routers = {}
    prefixes = []
    dns_servers = set()
    frames = 0

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(IPv6) or not pkt.haslayer(ICMPv6ND_RA):
                return
            frames += 1
            src_ip = str(pkt[IPv6].src)
            mac = _mac_from_pkt(pkt)
            ra = pkt[ICMPv6ND_RA]
            now = utc_now_iso()
            routers[src_ip] = {
                "router_ip": src_ip,
                "router_mac": mac,
                "first_seen": routers.get(src_ip, {}).get("first_seen", now),
                "last_seen": now,
                "router_lifetime": int(getattr(ra, "routerlifetime", 0) or 0),
                "reachable_time_ms": int(getattr(ra, "reachabletime", 0) or 0),
                "retrans_timer_ms": int(getattr(ra, "retranstimer", 0) or 0),
            }

            # Prefix info options
            try:
                for opt in pkt.getlayer(ICMPv6NDOptPrefixInfo, nb=1) or []:
                    # scapy getlayer(nb=) isn't a list, so handle below.
                    pass
            except Exception:
                pass

            # Iterate all layers and collect prefix/dns options.
            lay = pkt
            while lay:
                if isinstance(lay, ICMPv6NDOptPrefixInfo):
                    pfx = str(getattr(lay, "prefix", "") or "")
                    plen = int(getattr(lay, "prefixlen", 0) or 0)
                    if pfx:
                        prefixes.append(
                            {
                                "router_ip": src_ip,
                                "prefix": pfx,
                                "prefixlen": plen,
                                "valid_lifetime": int(getattr(lay, "validlifetime", 0) or 0),
                                "preferred_lifetime": int(getattr(lay, "preferredlifetime", 0) or 0),
                                "autonomous": bool(getattr(lay, "A", 0)),
                                "on_link": bool(getattr(lay, "L", 0)),
                            }
                        )
                # RDNSS option class name varies by scapy version; detect by field presence.
                if hasattr(lay, "dns") and hasattr(lay, "lifetime"):
                    try:
                        for d in list(getattr(lay, "dns") or []):
                            if d:
                                dns_servers.add(str(d))
                    except Exception:
                        pass
                lay = getattr(lay, "payload", None)
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="icmp6", prn=handler, store=False, promisc=True)

    try:
        sniffer.start()
        send(IPv6(dst="ff02::2") / ICMPv6ND_RS(), iface=iface, count=max(1, int(probes)), inter=max(0.0, float(inter)), verbose=0)
        time.sleep(max(0.0, float(timeout)))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    duration = max(0.0001, time.time() - start)
    router_list = list(routers.values())
    router_list.sort(key=lambda r: r.get("router_ip", ""))

    rogue_ra = False
    if len(router_list) > 1:
        rogue_ra = True

    return {
        "technique": "ipv6_router_advertisement_scan",
        "interface": iface,
        "started_at": started_at,
        "scan_duration_seconds": duration,
        "probes_sent": int(probes),
        "frames_observed": frames,
        "routers": router_list,
        "prefixes": prefixes,
        "dns_servers": sorted(list(dns_servers)),
        "rogue_ra_suspected": rogue_ra,
        "notes": "Multiple RA sources observed may indicate multiple routers or a rogue RA in lab.",
    }


def ipv6_passive_ndp(interface: str, duration: int) -> Dict[str, object]:
    """Passively sniff NDP/RA traffic and build IPv6 inventory."""
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    start = time.time()

    hosts: Dict[str, IPv6Host] = {}
    events: List[dict] = []
    frames = 0

    def add_host(ip: str, mac: str) -> None:
        if not ip:
            return
        now = utc_now_iso()
        if ip not in hosts:
            hosts[ip] = IPv6Host(ip=ip, mac=mac, first_seen=now, last_seen=now)
        else:
            h = hosts[ip]
            h.seen_count += 1
            h.last_seen = now
            if mac and not h.mac:
                h.mac = mac

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(IPv6):
                return
            ip6 = pkt[IPv6]
            src_ip = str(ip6.src)
            mac = _mac_from_pkt(pkt)
            frames += 1

            # Track NDP/RA messages (types 133-136).
            if pkt.haslayer(ICMPv6ND_RA):
                add_host(src_ip, mac)
                events.append({"type": "RA", "router_ip": src_ip, "router_mac": mac, "ts": utc_now_iso()})
            elif pkt.haslayer(ICMPv6ND_NA):
                add_host(src_ip, mac)
                tgt = str(getattr(pkt[ICMPv6ND_NA], "tgt", "") or "")
                events.append({"type": "NA", "src_ip": src_ip, "target": tgt, "mac": mac, "ts": utc_now_iso()})
            elif pkt.haslayer(ICMPv6ND_NS):
                # DAD: src is :: (unspecified)
                tgt = str(getattr(pkt[ICMPv6ND_NS], "tgt", "") or "")
                if src_ip == "::" and tgt:
                    events.append({"type": "DAD", "target": tgt, "mac": mac, "ts": utc_now_iso()})
                else:
                    add_host(src_ip, mac)
                    events.append({"type": "NS", "src_ip": src_ip, "target": tgt, "mac": mac, "ts": utc_now_iso()})
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="icmp6", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    return {
        "technique": "ipv6_passive_ndp",
        "interface": iface,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "frames_observed": frames,
        "hosts_discovered": len(hosts),
        "hosts": [asdict(v) for v in sorted(hosts.values(), key=lambda h: h.ip)],
        "events": events[-500:],
    }


def ipv6_slaac_fingerprint(addresses: List[str]) -> Dict[str, object]:
    """Classify IPv6 address generation policy and (when possible) derive MAC from EUI-64."""
    addrs = [str(a).strip() for a in (addresses or []) if str(a).strip()]
    out = []

    def derive_mac_from_eui64(ip6: ipaddress.IPv6Address) -> str:
        iid = int(ip6) & ((1 << 64) - 1)
        b = iid.to_bytes(8, "big")
        # EUI-64 pattern: xx:xx:xx:ff:fe:xx:xx:xx
        if b[3] != 0xFF or b[4] != 0xFE:
            return ""
        mac_bytes = bytes([b[0] ^ 0x02, b[1], b[2], b[5], b[6], b[7]])
        return ":".join(f"{x:02x}" for x in mac_bytes)

    for a in addrs:
        try:
            ip6 = ipaddress.IPv6Address(a)
        except Exception:
            continue
        policy = "random_or_privacy"
        derived_mac = ""
        try:
            derived_mac = derive_mac_from_eui64(ip6)
            if derived_mac:
                policy = "eui64"
        except Exception:
            pass
        out.append({"ipv6": str(ip6), "policy": policy, "derived_mac": derived_mac})

    return {"technique": "ipv6_slaac_fingerprint", "count": len(out), "results": out}


def main() -> int:
    parser = argparse.ArgumentParser(description="IPv6 discovery techniques")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_nd = sub.add_parser("nd-scan", help="Active IPv6 neighbor discovery (ICMPv6 all-nodes ping)")
    p_nd.add_argument("--interface", default=str(conf.iface))
    p_nd.add_argument("--timeout", type=float, default=3.0)

    p_ra = sub.add_parser("ra-scan", help="Router solicitation + advertisement capture")
    p_ra.add_argument("--interface", default=str(conf.iface))
    p_ra.add_argument("--timeout", type=float, default=3.0)

    p_p = sub.add_parser("passive-ndp", help="Passive NDP/RA monitor")
    p_p.add_argument("--interface", default=str(conf.iface))
    p_p.add_argument("--duration", type=int, default=60)

    p_fp = sub.add_parser("slaac-fp", help="SLAAC address fingerprinting (EUI-64 vs privacy)")
    p_fp.add_argument("--addresses", default="", help="Comma-separated IPv6 addresses")

    args = parser.parse_args()
    cmd = args.cmd

    if cmd == "nd-scan":
        result = ipv6_neighbor_discovery(args.interface, timeout=args.timeout)
        sid = new_session_id("ipv6-nd-scan")
        write_json_log("ipv6", sid, {"result": result})
        print(sid)
        return 0
    if cmd == "ra-scan":
        result = ipv6_router_advertisement_scan(args.interface, timeout=args.timeout)
        sid = new_session_id("ipv6-ra-scan")
        write_json_log("ipv6", sid, {"result": result})
        print(sid)
        return 0
    if cmd == "passive-ndp":
        result = ipv6_passive_ndp(args.interface, args.duration)
        sid = new_session_id("ipv6-passive-ndp")
        write_json_log("ipv6", sid, {"result": result})
        print(sid)
        return 0
    if cmd == "slaac-fp":
        addrs = [x.strip() for x in str(args.addresses or "").split(",") if x.strip()]
        result = ipv6_slaac_fingerprint(addrs)
        sid = new_session_id("ipv6-slaac-fp")
        write_json_log("ipv6", sid, {"result": result})
        print(sid)
        return 0

    raise SystemExit(2)


if __name__ == "__main__":
    raise SystemExit(main())

