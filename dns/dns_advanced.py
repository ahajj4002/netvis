#!/usr/bin/env python3
"""Advanced DNS analysis techniques (NIP extensions).

Implements:
- dns.tunnel_detection (passive sniff + entropy/rate heuristics)
- dns.doh_dot_detection (passive sniff TLS SNI/ports to known resolvers)
- dns.dga_detection (heuristic scoring)
"""

from __future__ import annotations

import argparse
import math
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from scapy.all import AsyncSniffer, DNS, IP, TCP, UDP, conf

from toolkit.tls_ja3 import ja3_from_client_hello
from toolkit.utils import elapsed_ms, new_session_id, utc_now_iso, write_json_log

conf.verb = 0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = float(len(s))
    ent = 0.0
    for c in counts.values():
        p = float(c) / n
        ent -= p * math.log(p, 2)
    return float(ent)


def _domain_labels(domain: str) -> List[str]:
    d = (domain or "").strip().strip(".")
    if not d:
        return []
    return [p for p in d.split(".") if p]


def _dga_score(domain: str) -> float:
    """Heuristic DGA score in [0,1]."""
    labels = _domain_labels(domain)
    if len(labels) < 2:
        return 0.0
    # Focus on the left-most label (subdomain) for tunneling/DGA-like behavior.
    left = labels[0]
    if not left:
        return 0.0

    length = len(left)
    if length < 10:
        return 0.0

    ent = _shannon_entropy(left)
    digits = sum(ch.isdigit() for ch in left)
    digit_ratio = digits / max(1.0, float(length))
    vowels = sum(ch in "aeiou" for ch in left.lower())
    vowel_ratio = vowels / max(1.0, float(length))

    score = 0.0
    # Entropy contribution
    if ent >= 3.5:
        score += 0.5
    elif ent >= 3.0:
        score += 0.35
    elif ent >= 2.6:
        score += 0.2

    # Long random-looking labels
    if length >= 25:
        score += 0.2
    elif length >= 18:
        score += 0.1

    # Digit-heavy labels
    if digit_ratio >= 0.35:
        score += 0.2
    elif digit_ratio >= 0.2:
        score += 0.1

    # Very low vowel ratio tends to correlate with random strings
    if vowel_ratio <= 0.15:
        score += 0.1

    return max(0.0, min(score, 1.0))


def dns_tunnel_detection(interface: str, duration: int, *, entropy_threshold: float = 3.5, label_len_threshold: int = 30) -> Dict[str, object]:
    """Passive sniff of DNS queries and flag tunneling-like domains."""
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    started_at = utc_now_iso()
    start = time.time()

    q_by_domain = defaultdict(int)
    q_by_src = defaultdict(int)
    labels_meta = {}
    frames = 0

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(DNS) or not pkt.haslayer(UDP) or not pkt.haslayer(IP):
                return
            dns = pkt[DNS]
            # queries only
            if int(getattr(dns, "qr", 0) or 0) != 0:
                return
            qd = getattr(dns, "qd", None)
            if not qd:
                return
            qname = getattr(qd, "qname", b"")
            domain = qname.decode("utf-8", errors="ignore") if isinstance(qname, (bytes, bytearray)) else str(qname)
            domain = (domain or "").strip()
            if not domain:
                return
            frames += 1
            src = str(pkt[IP].src)
            q_by_domain[domain] += 1
            q_by_src[src] += 1

            labels = _domain_labels(domain)
            if not labels:
                return
            left = labels[0]
            ent = _shannon_entropy(left)
            labels_meta[domain] = {
                "left_label": left,
                "left_len": len(left),
                "left_entropy": ent,
                "labels": labels[:6],
            }
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="udp port 53", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    suspicious = []
    for dom, cnt in sorted(q_by_domain.items(), key=lambda kv: -kv[1]):
        meta = labels_meta.get(dom) or {}
        left_len = int(meta.get("left_len") or 0)
        left_ent = float(meta.get("left_entropy") or 0.0)
        if left_len >= int(label_len_threshold) and left_ent >= float(entropy_threshold):
            suspicious.append(
                {
                    "domain": dom,
                    "count": int(cnt),
                    "left_label_len": left_len,
                    "left_label_entropy": left_ent,
                    "reason": "long_high_entropy_label",
                }
            )
        elif left_ent >= float(entropy_threshold) and cnt >= max(20, int(dur / 2)):
            suspicious.append(
                {
                    "domain": dom,
                    "count": int(cnt),
                    "left_label_len": left_len,
                    "left_label_entropy": left_ent,
                    "reason": "high_entropy_high_rate",
                }
            )

    return {
        "technique": "dns_tunnel_detection",
        "interface": iface,
        "started_at": started_at,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "frames_observed": frames,
        "counts": {"unique_domains": len(q_by_domain), "unique_src_ips": len(q_by_src)},
        "top_domains": sorted([{"domain": d, "count": c} for d, c in q_by_domain.items()], key=lambda x: -x["count"])[:25],
        "suspicious_domains": suspicious[:100],
        "thresholds": {"entropy": float(entropy_threshold), "label_len": int(label_len_threshold)},
    }


_KNOWN_DOH_SNIS = {
    "dns.google",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "doh.opendns.com",
    "dns.quad9.net",
    "doh.cleanbrowsing.org",
}


def dns_doh_dot_detection(interface: str, duration: int, *, extra_snis: Optional[List[str]] = None) -> Dict[str, object]:
    """Detect DoH/DoT by sniffing TLS ClientHello SNI and port usage."""
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    started_at = utc_now_iso()
    start = time.time()

    known = set(_KNOWN_DOH_SNIS)
    for s in (extra_snis or []):
        s = str(s or "").strip().lower()
        if s:
            known.add(s)

    frames = 0
    doh_hits = []  # {src_ip,dst_ip,sni,ja3}
    dot_hits = []  # {src_ip,dst_ip,dst_port,ja3}
    users = set()

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                return
            tcp = pkt[TCP]
            dst_port = int(getattr(tcp, "dport", 0) or 0)
            if dst_port not in (443, 853):
                return
            payload = bytes(tcp.payload) if tcp.payload else b""
            if not payload:
                return
            frames += 1
            info = ja3_from_client_hello(payload)
            if not info:
                return
            src = str(pkt[IP].src)
            dst = str(pkt[IP].dst)
            sni = str(info.get("sni") or "").strip().lower()
            if dst_port == 853:
                users.add(src)
                dot_hits.append({"src_ip": src, "dst_ip": dst, "dst_port": dst_port, "ja3": info.get("ja3")})
            if sni and sni in known:
                users.add(src)
                doh_hits.append({"src_ip": src, "dst_ip": dst, "sni": sni, "ja3": info.get("ja3")})
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="tcp and (port 443 or port 853)", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    return {
        "technique": "dns_doh_dot_detection",
        "interface": iface,
        "started_at": started_at,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "frames_observed": frames,
        "known_snis": sorted(list(known)),
        "doh_users": sorted(list(users)),
        "doh_hits": doh_hits[:200],
        "dot_hits": dot_hits[:200],
        "monitoring_gaps": {
            "devices_using_doh_dot": len(users),
            "note": "Devices using DoH/DoT can bypass on-path DNS query monitoring.",
        },
    }


def dns_dga_detection(interface: str, duration: int, *, score_threshold: float = 0.7) -> Dict[str, object]:
    """Heuristic DGA detection from passive DNS queries."""
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    started_at = utc_now_iso()
    start = time.time()

    q_by_domain = defaultdict(int)
    q_by_src = defaultdict(int)
    frames = 0

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(DNS) or not pkt.haslayer(UDP) or not pkt.haslayer(IP):
                return
            dns = pkt[DNS]
            if int(getattr(dns, "qr", 0) or 0) != 0:
                return
            qd = getattr(dns, "qd", None)
            if not qd:
                return
            qname = getattr(qd, "qname", b"")
            domain = qname.decode("utf-8", errors="ignore") if isinstance(qname, (bytes, bytearray)) else str(qname)
            domain = (domain or "").strip()
            if not domain:
                return
            frames += 1
            src = str(pkt[IP].src)
            q_by_domain[domain] += 1
            q_by_src[src] += 1
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="udp port 53", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    scored = []
    for dom, cnt in q_by_domain.items():
        s = _dga_score(dom)
        if s >= float(score_threshold):
            scored.append({"domain": dom, "count": int(cnt), "score": float(s)})
    scored.sort(key=lambda r: (-r["score"], -r["count"], r["domain"]))

    return {
        "technique": "dns_dga_detection",
        "interface": iface,
        "started_at": started_at,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "frames_observed": frames,
        "score_threshold": float(score_threshold),
        "suspicious": scored[:100],
        "counts": {"unique_domains": len(q_by_domain), "unique_src_ips": len(q_by_src), "suspicious_domains": len(scored)},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Advanced DNS techniques")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("tunnel-detect")
    p1.add_argument("--interface", default=str(conf.iface))
    p1.add_argument("--duration", type=int, default=60)

    p2 = sub.add_parser("doh-detect")
    p2.add_argument("--interface", default=str(conf.iface))
    p2.add_argument("--duration", type=int, default=60)

    p3 = sub.add_parser("dga-detect")
    p3.add_argument("--interface", default=str(conf.iface))
    p3.add_argument("--duration", type=int, default=60)

    args = parser.parse_args()

    if args.cmd == "tunnel-detect":
        result = dns_tunnel_detection(args.interface, int(args.duration))
        sid = new_session_id("dns-tunnel")
    elif args.cmd == "doh-detect":
        result = dns_doh_dot_detection(args.interface, int(args.duration))
        sid = new_session_id("dns-doh")
    elif args.cmd == "dga-detect":
        result = dns_dga_detection(args.interface, int(args.duration))
        sid = new_session_id("dns-dga")
    else:
        raise SystemExit(2)

    write_json_log("dns", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

