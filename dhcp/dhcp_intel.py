#!/usr/bin/env python3
"""DHCP intelligence techniques (NIP extensions).

Implements:
- dhcp.passive_monitor (passive)
- dhcp.fingerprint (analysis from captured packets)
- dhcp.rogue_detection (active)

NOTE: Disruptive techniques (e.g., DHCP starvation) are intentionally not implemented.
"""

from __future__ import annotations

import argparse
import random
import time
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from scapy.all import (
    AsyncSniffer,
    BOOTP,
    DHCP,
    Ether,
    IP,
    UDP,
    conf,
    get_if_hwaddr,
    sendp,
)

from toolkit.utils import elapsed_ms, new_session_id, random_mac, utc_now_iso, write_json_log

conf.verb = 0


@dataclass
class DHCPLease:
    client_mac: str
    assigned_ip: str = ""
    server_ip: str = ""
    hostname: str = ""
    vendor_class: str = ""
    client_id: str = ""
    lease_time: int = 0
    first_seen: str = ""
    last_seen: str = ""
    seen_messages: List[str] = None
    param_req_list: List[int] = None
    os_guess: str = ""


def _opt(dhcp_opts: List[Tuple], key: str):
    for o in dhcp_opts or []:
        try:
            if o and isinstance(o, tuple) and o[0] == key:
                return o[1]
        except Exception:
            continue
    return None


def _fmt_mac_from_pkt(pkt) -> str:
    try:
        if pkt.haslayer(Ether):
            return str(pkt[Ether].src)
    except Exception:
        pass
    try:
        if pkt.haslayer(BOOTP):
            ch = bytes(pkt[BOOTP].chaddr or b"")[:6]
            if ch:
                return ":".join(f"{b:02x}" for b in ch)
    except Exception:
        pass
    return ""


def _normalize_msg_type(v) -> str:
    # scapy may give int or string
    if v is None:
        return ""
    if isinstance(v, int):
        return str(v)
    s = str(v).strip().lower()
    return s


def dhcp_fingerprint_from_param_req_list(prl: List[int], vendor_class: str = "") -> str:
    """Very small offline DHCP fingerprint map (lab-friendly, no external DB)."""
    prl = [int(x) for x in (prl or []) if isinstance(x, int) or str(x).isdigit()]
    vc = (vendor_class or "").lower()

    # Heuristic signatures (not exhaustive).
    # Windows often requests NetBIOS options 44/46/47 and WPAD 252.
    if any(x in prl for x in (44, 46, 47)) and 252 in prl:
        return "windows_likely"
    # Apple clients tend to include 119 (domain search) and 95 (LDAP) rarely; vendor class may say dhcpcd/macos/ios.
    if "apple" in vc or "macos" in vc or "ios" in vc:
        return "apple_likely"
    # Android often uses vendor class "android-dhcp-*" (varies).
    if "android" in vc:
        return "android_likely"
    # Linux dhclient tends to request (1,28,2,3,15,6,12,26,119,121,42, ...); no NetBIOS trio.
    if 121 in prl and not any(x in prl for x in (44, 46, 47)):
        return "linux_dhclient_likely"
    if prl and not any(x in prl for x in (44, 46, 47)) and 15 in prl and 6 in prl:
        return "unix_like_likely"
    return ""


def passive_dhcp_monitor(interface: str, duration: int) -> Dict[str, object]:
    """Passively sniff DHCP traffic and reconstruct lease + hostname + vendor hints."""
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    start = time.time()

    leases: Dict[str, DHCPLease] = {}
    frames = 0
    msg_counts: Dict[str, int] = {}
    servers_seen: Dict[str, int] = {}

    def touch(mac: str) -> DHCPLease:
        now = utc_now_iso()
        if mac not in leases:
            leases[mac] = DHCPLease(
                client_mac=mac,
                first_seen=now,
                last_seen=now,
                seen_messages=[],
                param_req_list=[],
            )
        l = leases[mac]
        l.last_seen = now
        return l

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
                return
            frames += 1
            bootp = pkt[BOOTP]
            opts = list(pkt[DHCP].options or [])

            msg = _normalize_msg_type(_opt(opts, "message-type"))
            if msg:
                msg_counts[msg] = msg_counts.get(msg, 0) + 1

            mac = _fmt_mac_from_pkt(pkt)
            if not mac:
                return

            l = touch(mac)
            if msg and msg not in (l.seen_messages or []):
                l.seen_messages.append(msg)

            # Offer/ACK assigned IP is in yiaddr.
            yiaddr = str(getattr(bootp, "yiaddr", "") or "").strip()
            if yiaddr and yiaddr != "0.0.0.0":
                l.assigned_ip = yiaddr

            # Server identification
            srv = _opt(opts, "server_id")
            if srv:
                l.server_ip = str(srv)
                servers_seen[l.server_ip] = servers_seen.get(l.server_ip, 0) + 1
            else:
                # Fallback to IP source
                try:
                    if pkt.haslayer(IP):
                        src_ip = str(pkt[IP].src)
                        if src_ip:
                            l.server_ip = l.server_ip or src_ip
                            servers_seen[src_ip] = servers_seen.get(src_ip, 0) + 1
                except Exception:
                    pass

            hn = _opt(opts, "hostname")
            if hn:
                try:
                    l.hostname = hn.decode("utf-8", errors="ignore") if isinstance(hn, (bytes, bytearray)) else str(hn)
                except Exception:
                    l.hostname = str(hn)

            vc = _opt(opts, "vendor_class_id")
            if vc:
                try:
                    l.vendor_class = vc.decode("utf-8", errors="ignore") if isinstance(vc, (bytes, bytearray)) else str(vc)
                except Exception:
                    l.vendor_class = str(vc)

            cid = _opt(opts, "client_id")
            if cid:
                try:
                    l.client_id = cid.hex() if isinstance(cid, (bytes, bytearray)) else str(cid)
                except Exception:
                    l.client_id = str(cid)

            lt = _opt(opts, "lease_time")
            if isinstance(lt, int):
                l.lease_time = int(lt)

            prl = _opt(opts, "param_req_list")
            if prl:
                try:
                    l.param_req_list = [int(x) for x in list(prl)]
                except Exception:
                    pass

            l.os_guess = dhcp_fingerprint_from_param_req_list(l.param_req_list or [], l.vendor_class or "")
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="udp and (port 67 or port 68)", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    lease_list = [asdict(v) for v in leases.values()]
    lease_list.sort(key=lambda x: x.get("client_mac", ""))

    return {
        "technique": "passive_dhcp_monitor",
        "interface": iface,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "frames_observed": frames,
        "message_counts": msg_counts,
        "servers_seen": servers_seen,
        "leases": lease_list,
    }


def dhcp_fingerprint(interface: str, duration: int) -> Dict[str, object]:
    """Convenience wrapper: run passive capture and return just fingerprints per MAC."""
    r = passive_dhcp_monitor(interface, duration)
    fps = []
    for row in r.get("leases") or []:
        if not isinstance(row, dict):
            continue
        if row.get("os_guess"):
            fps.append(
                {
                    "client_mac": row.get("client_mac"),
                    "hostname": row.get("hostname"),
                    "vendor_class": row.get("vendor_class"),
                    "param_req_list": row.get("param_req_list") or [],
                    "os_guess": row.get("os_guess"),
                }
            )
    return {
        "technique": "dhcp_fingerprint",
        "interface": str(interface or conf.iface),
        "duration_seconds": int(duration),
        "fingerprints": fps,
        "counts": {"fingerprints": len(fps), "leases_total": len(r.get("leases") or [])},
        "source_capture": r,
    }


def rogue_dhcp_server_detection(interface: str, *, known_server_ip: str = "", timeout: float = 3.0) -> Dict[str, object]:
    """Send a DHCP Discover and flag multiple DHCP Offers (potential rogue)."""
    iface = str(interface or conf.iface)
    started_at = utc_now_iso()
    start = time.time()

    xid = random.randint(1, 0xFFFFFFFF)
    chaddr = bytes.fromhex(random_mac().replace(":", "")) + b"\x00" * 10

    # Try to use interface MAC as src; doesn't matter much for lab.
    try:
        src_mac = get_if_hwaddr(iface)
    except Exception:
        src_mac = random_mac()

    discover = (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=chaddr, xid=xid, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), ("param_req_list", [1, 3, 6, 15, 51, 54, 58, 59, 119, 252]), "end"])
    )

    offers = []
    servers = set()

    def handler(pkt):
        try:
            if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
                return
            bootp = pkt[BOOTP]
            if int(getattr(bootp, "xid", 0) or 0) != int(xid):
                return
            opts = list(pkt[DHCP].options or [])
            msg = _normalize_msg_type(_opt(opts, "message-type"))
            if msg not in ("offer", "2", "dhcpoffer"):
                return
            srv = _opt(opts, "server_id")
            srv_ip = str(srv) if srv else (str(pkt[IP].src) if pkt.haslayer(IP) else "")
            yiaddr = str(getattr(bootp, "yiaddr", "") or "").strip()
            servers.add(srv_ip)
            offers.append(
                {
                    "server_ip": srv_ip,
                    "offered_ip": yiaddr,
                    "subnet_mask": str(_opt(opts, "subnet_mask") or ""),
                    "router": str(_opt(opts, "router") or ""),
                    "dns": _opt(opts, "name_server") or [],
                }
            )
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="udp and (port 67 or port 68)", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        sendp(discover, iface=iface, verbose=0)
        time.sleep(max(0.2, float(timeout)))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    duration = max(0.0001, time.time() - start)
    rogue = False
    if len(servers) > 1:
        rogue = True
    if known_server_ip and servers and (known_server_ip not in servers):
        rogue = True

    return {
        "technique": "rogue_dhcp_server_detection",
        "interface": iface,
        "started_at": started_at,
        "scan_duration_seconds": duration,
        "xid": int(xid),
        "offers": offers,
        "servers": sorted(list(servers)),
        "known_server_ip": known_server_ip,
        "rogue_dhcp_suspected": rogue,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="DHCP intelligence techniques")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("passive-dhcp", help="Passive DHCP monitor")
    p1.add_argument("--interface", default=str(conf.iface))
    p1.add_argument("--duration", type=int, default=60)

    p2 = sub.add_parser("fingerprint", help="DHCP fingerprinting (passive capture + analysis)")
    p2.add_argument("--interface", default=str(conf.iface))
    p2.add_argument("--duration", type=int, default=60)

    p3 = sub.add_parser("rogue-detect", help="Rogue DHCP server detection (active discover + offer collection)")
    p3.add_argument("--interface", default=str(conf.iface))
    p3.add_argument("--known-server-ip", default="")
    p3.add_argument("--timeout", type=float, default=3.0)

    args = parser.parse_args()

    if args.cmd == "passive-dhcp":
        result = passive_dhcp_monitor(args.interface, args.duration)
    elif args.cmd == "fingerprint":
        result = dhcp_fingerprint(args.interface, args.duration)
    elif args.cmd == "rogue-detect":
        result = rogue_dhcp_server_detection(args.interface, known_server_ip=str(args.known_server_ip or ""), timeout=float(args.timeout))
    else:
        raise SystemExit(2)

    sid = new_session_id(f"dhcp-{args.cmd}")
    write_json_log("dhcp", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

