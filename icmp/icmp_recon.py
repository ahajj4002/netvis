#!/usr/bin/env python3
"""ICMP reconnaissance techniques (NIP extensions).

Implements:
- icmp.echo_sweep
- icmp.timestamp
- icmp.address_mask
- icmp.os_fingerprint
"""

from __future__ import annotations

import argparse
import time
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

from scapy.all import IP, ICMP, conf, sr, sr1

from toolkit.utils import ensure_private_target, hosts_from_network, new_session_id, utc_now_iso, write_json_log

conf.verb = 0


@dataclass
class AliveHost:
    ip: str
    rtt_ms: float
    ttl: int
    ipid: int
    df: bool


def icmp_echo_sweep(network: str, *, timeout: float = 1.0, inter: float = 0.0, max_hosts: int = 512, shuffle: bool = True) -> Dict[str, object]:
    ensure_private_target(network)
    started_at = utc_now_iso()
    start = time.time()

    hosts = hosts_from_network(network, max_hosts=max(1, int(max_hosts)))
    if shuffle:
        import random

        random.shuffle(hosts)

    pkts = [IP(dst=h) / ICMP(type=8, code=0) for h in hosts]
    ans, unans = sr(pkts, timeout=float(timeout), inter=max(0.0, float(inter)), verbose=0)

    alive: List[AliveHost] = []
    for sent, recv in ans:
        try:
            ip = str(recv[IP].src)
            rtt_ms = max(0.0, (float(recv.time) - float(sent.time)) * 1000.0)
            ttl = int(getattr(recv[IP], "ttl", 0) or 0)
            ipid = int(getattr(recv[IP], "id", 0) or 0)
            df = bool("DF" in str(getattr(recv[IP], "flags", "")))
            alive.append(AliveHost(ip=ip, rtt_ms=rtt_ms, ttl=ttl, ipid=ipid, df=df))
        except Exception:
            continue

    duration = max(0.0001, time.time() - start)
    alive.sort(key=lambda x: x.ip)

    return {
        "technique": "icmp_echo_sweep",
        "network": network,
        "started_at": started_at,
        "scan_duration_seconds": duration,
        "timeout_seconds": float(timeout),
        "inter_seconds": float(inter),
        "addresses_probed": len(hosts),
        "hosts_alive": len(alive),
        "alive_hosts": [asdict(x) for x in alive],
    }


def icmp_timestamp_request(target: str, *, timeout: float = 1.5) -> Dict[str, object]:
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    req = IP(dst=str(target)) / ICMP(type=13, code=0)
    resp = sr1(req, timeout=float(timeout), verbose=0)

    out = {
        "technique": "icmp_timestamp_request",
        "target": str(target),
        "started_at": started_at,
        "scan_duration_seconds": max(0.0001, time.time() - start),
        "responded": bool(resp is not None),
        "reply": {},
    }
    if resp is not None and resp.haslayer(ICMP):
        ic = resp[ICMP]
        out["reply"] = {
            "type": int(getattr(ic, "type", 0) or 0),
            "code": int(getattr(ic, "code", 0) or 0),
            "ts_ori": str(getattr(ic, "ts_ori", "")),
            "ts_rx": str(getattr(ic, "ts_rx", "")),
            "ts_tx": str(getattr(ic, "ts_tx", "")),
            "ttl": int(getattr(resp[IP], "ttl", 0) or 0),
        }
    return out


def icmp_address_mask_request(target: str, *, timeout: float = 1.5) -> Dict[str, object]:
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    req = IP(dst=str(target)) / ICMP(type=17, code=0)
    resp = sr1(req, timeout=float(timeout), verbose=0)

    out = {
        "technique": "icmp_address_mask_request",
        "target": str(target),
        "started_at": started_at,
        "scan_duration_seconds": max(0.0001, time.time() - start),
        "responded": bool(resp is not None),
        "reply": {},
    }
    if resp is not None and resp.haslayer(ICMP):
        ic = resp[ICMP]
        out["reply"] = {
            "type": int(getattr(ic, "type", 0) or 0),
            "code": int(getattr(ic, "code", 0) or 0),
            "addr_mask": str(getattr(ic, "addr_mask", "")),
            "ttl": int(getattr(resp[IP], "ttl", 0) or 0),
        }
    return out


def icmp_os_fingerprint(target: str, *, timeout: float = 1.0) -> Dict[str, object]:
    """Lightweight ICMP-based OS hints (TTL class, DF bit, IPID behavior)."""
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    req = IP(dst=str(target), flags="DF") / ICMP(type=8, code=0) / (b"NetVis-ICMP-FP" * 2)
    resp = sr1(req, timeout=float(timeout), verbose=0)

    ttl = 0
    ipid = 0
    df = False
    if resp is not None and resp.haslayer(IP):
        ttl = int(getattr(resp[IP], "ttl", 0) or 0)
        ipid = int(getattr(resp[IP], "id", 0) or 0)
        df = bool("DF" in str(getattr(resp[IP], "flags", "")))

    ttl_class = ""
    if ttl >= 240:
        ttl_class = "network_device_like"
    elif ttl >= 120:
        ttl_class = "windows_like"
    elif ttl > 0:
        ttl_class = "unix_like"

    os_hint = ttl_class
    if ttl_class == "unix_like":
        os_hint = "linux_unix_likely"
    elif ttl_class == "windows_like":
        os_hint = "windows_likely"
    elif ttl_class == "network_device_like":
        os_hint = "router_switch_likely"

    return {
        "technique": "icmp_os_fingerprint",
        "target": str(target),
        "started_at": started_at,
        "scan_duration_seconds": max(0.0001, time.time() - start),
        "responded": bool(resp is not None),
        "ttl": ttl,
        "ttl_class": ttl_class,
        "ipid": ipid,
        "df": df,
        "os_hint": os_hint,
        "notes": "TTL-based OS hints are approximate and depend on hop count; use TCP fingerprinting for stronger inference.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="ICMP reconnaissance techniques")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("echo-sweep", help="ICMP echo sweep")
    p1.add_argument("--network", required=True)
    p1.add_argument("--timeout", type=float, default=1.0)
    p1.add_argument("--inter", type=float, default=0.0)
    p1.add_argument("--max-hosts", type=int, default=512)

    p2 = sub.add_parser("timestamp", help="ICMP timestamp request")
    p2.add_argument("--target", required=True)
    p2.add_argument("--timeout", type=float, default=1.5)

    p3 = sub.add_parser("address-mask", help="ICMP address mask request")
    p3.add_argument("--target", required=True)
    p3.add_argument("--timeout", type=float, default=1.5)

    p4 = sub.add_parser("icmp-os-fp", help="ICMP OS fingerprint")
    p4.add_argument("--target", required=True)
    p4.add_argument("--timeout", type=float, default=1.0)

    args = parser.parse_args()

    if args.cmd == "echo-sweep":
        result = icmp_echo_sweep(args.network, timeout=args.timeout, inter=args.inter, max_hosts=args.max_hosts)
    elif args.cmd == "timestamp":
        result = icmp_timestamp_request(args.target, timeout=args.timeout)
    elif args.cmd == "address-mask":
        result = icmp_address_mask_request(args.target, timeout=args.timeout)
    elif args.cmd == "icmp-os-fp":
        result = icmp_os_fingerprint(args.target, timeout=args.timeout)
    else:
        raise SystemExit(2)

    sid = new_session_id(f"icmp-{args.cmd}")
    write_json_log("icmp", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

