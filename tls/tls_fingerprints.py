#!/usr/bin/env python3
"""TLS passive fingerprints (NIP extensions).

Implements:
- tls.ja3_fingerprint (ClientHello)
- tls.ja3s_fingerprint (ServerHello)

This is passive: it sniffs traffic on the specified interface for a duration and
extracts TLS handshake metadata when available.
"""

from __future__ import annotations

import argparse
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

from scapy.all import AsyncSniffer, IP, TCP, conf

from toolkit.tls_ja3 import ja3_from_client_hello, ja3s_from_server_hello
from toolkit.utils import elapsed_ms, new_session_id, utc_now_iso, write_json_log

conf.verb = 0


def _payload_bytes(pkt) -> bytes:
    try:
        raw = bytes(pkt[TCP].payload)
        return raw or b""
    except Exception:
        return b""


def ja3_passive_capture(interface: str, duration: int, *, ports: Optional[List[int]] = None) -> Dict[str, object]:
    """Capture TLS ClientHello and compute JA3 hashes."""
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    started_at = utc_now_iso()
    start = time.time()

    ports = [int(p) for p in (ports or [443, 8443, 853]) if isinstance(p, int) or str(p).isdigit()]
    ports = [p for p in ports if 1 <= int(p) <= 65535]
    if not ports:
        ports = [443]

    out = []
    counts = defaultdict(int)
    seen = set()

    def handler(pkt):
        try:
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                return
            tcp = pkt[TCP]
            if int(tcp.dport) not in ports and int(tcp.sport) not in ports:
                return
            payload = _payload_bytes(pkt)
            if not payload:
                return
            info = ja3_from_client_hello(payload)
            if not info:
                return
            src = str(pkt[IP].src)
            dst = str(pkt[IP].dst)
            dport = int(tcp.dport)
            key = (src, dst, dport, info.get("ja3", ""))
            if key in seen:
                counts[info.get("ja3", "")] += 1
                return
            seen.add(key)
            counts[info.get("ja3", "")] += 1
            out.append(
                {
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": dport,
                    **info,
                }
            )
        except Exception:
            return

    # BPF filter keeps it light.
    port_clause = " or ".join([f"tcp port {int(p)}" for p in ports])
    bpf = f"tcp and ({port_clause})"
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    elapsed = elapsed_ms(start)
    out.sort(key=lambda r: (r.get("src_ip", ""), r.get("dst_ip", ""), int(r.get("dst_port") or 0)))
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:20]
    return {
        "technique": "ja3_passive_capture",
        "interface": iface,
        "started_at": started_at,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed,
        "ports": ports,
        "fingerprints": out,
        "top_ja3": [{"ja3": k, "count": v} for k, v in top],
        "count": len(out),
    }


def ja3s_passive_capture(interface: str, duration: int, *, ports: Optional[List[int]] = None) -> Dict[str, object]:
    """Capture TLS ServerHello and compute JA3S hashes."""
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    started_at = utc_now_iso()
    start = time.time()

    ports = [int(p) for p in (ports or [443, 8443, 853]) if isinstance(p, int) or str(p).isdigit()]
    ports = [p for p in ports if 1 <= int(p) <= 65535]
    if not ports:
        ports = [443]

    out = []
    counts = defaultdict(int)
    seen = set()

    def handler(pkt):
        try:
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                return
            tcp = pkt[TCP]
            if int(tcp.dport) not in ports and int(tcp.sport) not in ports:
                return
            payload = _payload_bytes(pkt)
            if not payload:
                return
            info = ja3s_from_server_hello(payload)
            if not info:
                return
            src = str(pkt[IP].src)
            dst = str(pkt[IP].dst)
            sport = int(tcp.sport)
            key = (src, dst, sport, info.get("ja3s", ""))
            if key in seen:
                counts[info.get("ja3s", "")] += 1
                return
            seen.add(key)
            counts[info.get("ja3s", "")] += 1
            out.append(
                {
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": sport,
                    **info,
                }
            )
        except Exception:
            return

    port_clause = " or ".join([f"tcp port {int(p)}" for p in ports])
    bpf = f"tcp and ({port_clause})"
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    elapsed = elapsed_ms(start)
    out.sort(key=lambda r: (r.get("src_ip", ""), r.get("dst_ip", ""), int(r.get("src_port") or 0)))
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:20]
    return {
        "technique": "ja3s_passive_capture",
        "interface": iface,
        "started_at": started_at,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed,
        "ports": ports,
        "fingerprints": out,
        "top_ja3s": [{"ja3s": k, "count": v} for k, v in top],
        "count": len(out),
    }


def encrypted_traffic_classification(interface: str, duration: int) -> Dict[str, object]:
    """Passive encrypted-flow classification (heuristic, no decryption).

    Features:
    - packet size sequence summary
    - inter-arrival timing
    - flow duration
    - bytes/packets totals

    Labels are heuristic and intended for lab demonstration.
    """
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    started_at = utc_now_iso()
    start = time.time()

    # flow key -> stats
    flows = {}

    def get_flow(src: str, sport: int, dst: str, dport: int, proto: str) -> dict:
        k = f"{src}:{sport}->{dst}:{dport}/{proto}"
        if k not in flows:
            flows[k] = {
                "flow_key": k,
                "src_ip": src,
                "src_port": int(sport),
                "dst_ip": dst,
                "dst_port": int(dport),
                "protocol": proto,
                "first_ts": None,
                "last_ts": None,
                "packets": 0,
                "bytes": 0,
                "sizes": [],
                "deltas": [],
            }
        return flows[k]

    def handler(pkt):
        try:
            if not pkt.haslayer(IP):
                return
            ts = float(getattr(pkt, "time", time.time()))
            if pkt.haslayer(TCP):
                p = pkt[TCP]
                if int(p.dport) not in (443, 8443, 853) and int(p.sport) not in (443, 8443, 853):
                    return
                src, dst = str(pkt[IP].src), str(pkt[IP].dst)
                fl = get_flow(src, int(p.sport), dst, int(p.dport), "TCP")
                plen = len(bytes(p.payload)) if p.payload else 0
            elif pkt.haslayer(UDP):
                p = pkt[UDP]
                if int(p.dport) not in (443, 853, 784) and int(p.sport) not in (443, 853, 784):
                    return
                src, dst = str(pkt[IP].src), str(pkt[IP].dst)
                fl = get_flow(src, int(p.sport), dst, int(p.dport), "UDP")
                plen = len(bytes(p.payload)) if p.payload else 0
            else:
                return

            if fl["first_ts"] is None:
                fl["first_ts"] = ts
            if fl["last_ts"] is not None:
                fl["deltas"].append(max(0.0, ts - float(fl["last_ts"])))
            fl["last_ts"] = ts
            fl["packets"] += 1
            fl["bytes"] += int(max(0, plen))
            if len(fl["sizes"]) < 64:
                fl["sizes"].append(int(plen))
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="(tcp port 443 or tcp port 8443 or tcp port 853 or udp port 443 or udp port 853)", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    labeled = []
    for f in flows.values():
        pkts = int(f["packets"])
        b = int(f["bytes"])
        if pkts <= 0:
            continue
        dur_s = max(0.001, float(f["last_ts"] or 0) - float(f["first_ts"] or 0))
        avg_size = float(sum(f["sizes"]) / max(1, len(f["sizes"])))
        avg_delta = float(sum(f["deltas"]) / max(1, len(f["deltas"]))) if f["deltas"] else 0.0
        rate_bps = float(b) / dur_s

        # Heuristic labeling.
        label = "browsing"
        conf_score = 0.55
        if pkts >= 40 and rate_bps > 80_000 and avg_size > 700:
            label = "streaming_or_large_transfer"
            conf_score = 0.75
        elif avg_delta > 5.0 and pkts <= 12 and b < 20_000:
            label = "periodic_beacon"
            conf_score = 0.7
        elif pkts >= 20 and avg_size < 300 and avg_delta < 0.25:
            label = "interactive_or_voip_like"
            conf_score = 0.6

        labeled.append(
            {
                "flow_key": f["flow_key"],
                "src_ip": f["src_ip"],
                "dst_ip": f["dst_ip"],
                "dst_port": f["dst_port"],
                "protocol": f["protocol"],
                "packets": pkts,
                "bytes": b,
                "duration_seconds": dur_s,
                "avg_packet_size": avg_size,
                "avg_interarrival_seconds": avg_delta,
                "label": label,
                "confidence": conf_score,
            }
        )

    labeled.sort(key=lambda r: (-float(r.get("bytes") or 0), r.get("flow_key") or ""))
    return {
        "technique": "encrypted_traffic_classification",
        "interface": iface,
        "started_at": started_at,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "flows": labeled[:500],
        "counts": {"flows_total": len(labeled)},
        "notes": "Classification is heuristic and intended for lab analysis, not production attribution.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="TLS passive fingerprints (JA3/JA3S)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("ja3", help="JA3 ClientHello fingerprints (passive)")
    p1.add_argument("--interface", default=str(conf.iface))
    p1.add_argument("--duration", type=int, default=60)
    p1.add_argument("--ports", default="443,8443,853")

    p2 = sub.add_parser("ja3s", help="JA3S ServerHello fingerprints (passive)")
    p2.add_argument("--interface", default=str(conf.iface))
    p2.add_argument("--duration", type=int, default=60)
    p2.add_argument("--ports", default="443,8443,853")

    p3 = sub.add_parser("traffic-classify", help="Encrypted traffic statistical classification (passive)")
    p3.add_argument("--interface", default=str(conf.iface))
    p3.add_argument("--duration", type=int, default=60)

    args = parser.parse_args()
    ports = []
    for part in str(getattr(args, "ports", "") or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ports.append(int(part))
        except Exception:
            continue

    if args.cmd == "ja3":
        result = ja3_passive_capture(args.interface, int(args.duration), ports=ports)
        sid = new_session_id("tls-ja3")
    elif args.cmd == "ja3s":
        result = ja3s_passive_capture(args.interface, int(args.duration), ports=ports)
        sid = new_session_id("tls-ja3s")
    elif args.cmd == "traffic-classify":
        result = encrypted_traffic_classification(args.interface, int(args.duration))
        sid = new_session_id("tls-classify")
    else:
        raise SystemExit(2)

    write_json_log("tls", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
