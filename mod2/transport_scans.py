#!/usr/bin/env python3
"""Module 2: Transport-layer port scanning methods (NetVis toolkit).

Implements:
- 2a TCP SYN scan (half-open)
- 2b TCP connect scan
- 2c FIN scan
- 2d XMAS scan
- 2e NULL scan
- 2f UDP scan (with payloads for DNS/NTP/SNMP)
- 2g ACK scan

Also provides timing controls used by Module 4 (fixed rates, jitter, ordering randomization).
"""

from __future__ import annotations

import argparse
import math
import random
import socket
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

from scapy.all import IP, TCP, UDP, ICMP, Raw, conf, sr1, send

from toolkit.utils import (
    ensure_private_target,
    infer_default_network,
    infer_local_ip,
    hosts_from_network,
    new_session_id,
    percentile,
    shuffled_tuples,
    sleep_with_jitter,
    utc_now_iso,
    write_json_log,
)

conf.verb = 0


@dataclass
class PortResult:
    host: str
    port: int
    proto: str
    state: str  # open|closed|filtered|unfiltered|open_or_filtered
    reason: str
    rtt_ms: float = 0.0


def _tcp_scan_single(host: str, port: int, flags: str, timeout: float, src_port: Optional[int] = None,
                     ip_frag: bool = False, frag_size: int = 24) -> PortResult:
    """Send a crafted TCP segment and classify based on response."""
    sport = src_port or random.randint(1024, 65535)
    pkt = IP(dst=host) / TCP(sport=sport, dport=port, flags=flags, seq=random.randint(0, 2**32 - 1))

    start = time.time()
    if ip_frag:
        # scapy's fragment() returns list of IP fragments
        from scapy.all import fragment

        frags = fragment(pkt, fragsize=frag_size)
        for f in frags:
            send(f, verbose=False)
        # We need to sniff for response; simplest: sr1 a non-fragmented re-probe for response timing.
        # For Module 3a, use dedicated fragmentation testing module.
        resp = sr1(pkt, timeout=timeout, verbose=False)
    else:
        resp = sr1(pkt, timeout=timeout, verbose=False)

    rtt = (time.time() - start) * 1000.0

    if resp is None:
        # FIN/XMAS/NULL: open ports often silently drop, so "no response" is ambiguous.
        if flags in ("F", "", "FPU"):
            return PortResult(host, port, "tcp", "open_or_filtered", "no_response", rtt_ms=rtt)
        return PortResult(host, port, "tcp", "filtered", "no_response", rtt_ms=rtt)

    if resp.haslayer(ICMP):
        ic = resp.getlayer(ICMP)
        if ic.type == 3:
            return PortResult(host, port, "tcp", "filtered", f"icmp_unreachable_code_{ic.code}", rtt_ms=rtt)

    if resp.haslayer(TCP):
        tcp = resp.getlayer(TCP)
        # SYN scan classification
        if flags == "S":
            if tcp.flags & 0x12:  # SYN-ACK
                # send RST to avoid completing handshake
                rst = IP(dst=host) / TCP(sport=sport, dport=port, flags="R", seq=tcp.ack)
                send(rst, verbose=False)
                return PortResult(host, port, "tcp", "open", "syn_ack", rtt_ms=rtt)
            if tcp.flags & 0x14 or tcp.flags & 0x04:  # RST-ACK or RST
                return PortResult(host, port, "tcp", "closed", "rst", rtt_ms=rtt)
            return PortResult(host, port, "tcp", "filtered", f"tcp_flags_{int(tcp.flags)}", rtt_ms=rtt)

        # FIN/XMAS/NULL logic (RFC793): closed -> RST; open -> no response
        if flags in ("F", "", "FPU"):
            if tcp.flags & 0x04:
                return PortResult(host, port, "tcp", "closed", "rst", rtt_ms=rtt)
            return PortResult(host, port, "tcp", "open_or_filtered", f"tcp_flags_{int(tcp.flags)}", rtt_ms=rtt)

        # ACK scan: RST -> unfiltered; no resp/ICMP -> filtered
        if flags == "A":
            if tcp.flags & 0x04:
                return PortResult(host, port, "tcp", "unfiltered", "rst", rtt_ms=rtt)
            return PortResult(host, port, "tcp", "filtered", f"tcp_flags_{int(tcp.flags)}", rtt_ms=rtt)

    return PortResult(host, port, "tcp", "filtered", "unexpected_response", rtt_ms=rtt)


def tcp_syn_scan(hosts: List[str], ports: List[int], timeout: float, rate_delay: float,
                 jitter_mode: str, jitter_arg: float, shuffle: bool) -> Dict[str, object]:
    targets = shuffled_tuples(hosts, ports) if shuffle else [(h, p) for h in hosts for p in ports]

    results: List[PortResult] = []
    delays: List[float] = []

    start = time.time()
    for host, port in targets:
        r = _tcp_scan_single(host, port, flags="S", timeout=timeout)
        results.append(r)
        delays.append(sleep_with_jitter(rate_delay, mode=jitter_mode, jitter_arg=jitter_arg))
    duration = time.time() - start

    return {
        "technique": "tcp_syn_scan",
        "hosts": hosts,
        "ports": ports,
        "timeout_seconds": timeout,
        "rate_delay_seconds": rate_delay,
        "jitter_mode": jitter_mode,
        "jitter_arg": jitter_arg,
        "target_order_randomized": shuffle,
        "scan_duration_seconds": duration,
        "delay_stats": {
            "count": len(delays),
            "avg": sum(delays) / max(1, len(delays)),
            "p50": percentile(delays, 50),
            "p95": percentile(delays, 95),
        },
        "results": [asdict(r) for r in results],
        "counts": {
            "open": sum(1 for r in results if r.state == "open"),
            "closed": sum(1 for r in results if r.state == "closed"),
            "filtered": sum(1 for r in results if r.state == "filtered"),
        },
    }


def tcp_connect_scan(hosts: List[str], ports: List[int], timeout: float, rate_delay: float,
                     jitter_mode: str, jitter_arg: float, shuffle: bool) -> Dict[str, object]:
    """Complete TCP handshake using OS sockets for baseline logging visibility."""
    targets = shuffled_tuples(hosts, ports) if shuffle else [(h, p) for h in hosts for p in ports]
    results: List[PortResult] = []
    delays: List[float] = []

    start = time.time()
    for host, port in targets:
        t0 = time.time()
        state = "filtered"
        reason = "no_response"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            rc = sock.connect_ex((host, port))
            if rc == 0:
                state = "open"
                reason = "connect_ok"
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
            else:
                state = "closed"
                reason = f"connect_ex_{rc}"
            sock.close()
        except Exception as exc:
            state = "filtered"
            reason = f"exception_{type(exc).__name__}"

        rtt = (time.time() - t0) * 1000.0
        results.append(PortResult(host, port, "tcp", state, reason, rtt_ms=rtt))
        delays.append(sleep_with_jitter(rate_delay, mode=jitter_mode, jitter_arg=jitter_arg))

    duration = time.time() - start

    return {
        "technique": "tcp_connect_scan",
        "hosts": hosts,
        "ports": ports,
        "timeout_seconds": timeout,
        "rate_delay_seconds": rate_delay,
        "jitter_mode": jitter_mode,
        "jitter_arg": jitter_arg,
        "target_order_randomized": shuffle,
        "scan_duration_seconds": duration,
        "delay_stats": {
            "count": len(delays),
            "avg": sum(delays) / max(1, len(delays)),
            "p50": percentile(delays, 50),
            "p95": percentile(delays, 95),
        },
        "results": [asdict(r) for r in results],
        "counts": {
            "open": sum(1 for r in results if r.state == "open"),
            "closed": sum(1 for r in results if r.state == "closed"),
            "filtered": sum(1 for r in results if r.state == "filtered"),
        },
    }


def tcp_flag_scan(name: str, flags: str, hosts: List[str], ports: List[int], timeout: float,
                  rate_delay: float, jitter_mode: str, jitter_arg: float, shuffle: bool) -> Dict[str, object]:
    targets = shuffled_tuples(hosts, ports) if shuffle else [(h, p) for h in hosts for p in ports]
    results: List[PortResult] = []
    delays: List[float] = []

    start = time.time()
    for host, port in targets:
        r = _tcp_scan_single(host, port, flags=flags, timeout=timeout)
        results.append(r)
        delays.append(sleep_with_jitter(rate_delay, mode=jitter_mode, jitter_arg=jitter_arg))

    duration = time.time() - start
    return {
        "technique": name,
        "flags": flags,
        "hosts": hosts,
        "ports": ports,
        "timeout_seconds": timeout,
        "rate_delay_seconds": rate_delay,
        "jitter_mode": jitter_mode,
        "jitter_arg": jitter_arg,
        "target_order_randomized": shuffle,
        "scan_duration_seconds": duration,
        "delay_stats": {
            "count": len(delays),
            "avg": sum(delays) / max(1, len(delays)),
            "p50": percentile(delays, 50),
            "p95": percentile(delays, 95),
        },
        "results": [asdict(r) for r in results],
        "counts": {
            "closed_rst": sum(1 for r in results if r.reason == "rst"),
            "no_response": sum(1 for r in results if r.reason == "no_response"),
        },
    }


def udp_scan(hosts: List[str], ports: List[int], timeout: float, rate_delay: float,
             jitter_mode: str, jitter_arg: float, shuffle: bool) -> Dict[str, object]:
    payloads = {
        53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS minimal
        123: b"\x1b" + 47 * b"\x00",  # NTP
        161: b"\x30\x26\x02\x01\x01\x04\x06public",  # SNMP-ish
    }

    targets = shuffled_tuples(hosts, ports) if shuffle else [(h, p) for h in hosts for p in ports]
    results: List[PortResult] = []
    delays: List[float] = []
    probe_events: List[Dict[str, object]] = []
    icmp_times: List[float] = []
    icmp_rtts: List[float] = []

    icmp_unreach = 0
    silent = 0

    start = time.time()
    for host, port in targets:
        sent_ts = time.time()
        pkt = IP(dst=host) / UDP(sport=random.randint(1024, 65535), dport=port)
        if port in payloads:
            pkt = pkt / Raw(load=payloads[port])
        t0 = time.time()
        resp = sr1(pkt, timeout=timeout, verbose=False)
        rtt = (time.time() - t0) * 1000.0
        recv_ts = time.time() if resp is not None else None

        if resp is None:
            results.append(PortResult(host, port, "udp", "open_or_filtered", "no_response", rtt_ms=rtt))
            silent += 1
        elif resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 3 and resp.getlayer(ICMP).code == 3:
            results.append(PortResult(host, port, "udp", "closed", "icmp_port_unreachable", rtt_ms=rtt))
            icmp_unreach += 1
            icmp_rtts.append(rtt)
            if recv_ts is not None:
                icmp_times.append(recv_ts - start)
        else:
            results.append(PortResult(host, port, "udp", "open", "udp_response_or_other_icmp", rtt_ms=rtt))

        probe_events.append({
            "host": host,
            "port": port,
            "sent_offset_s": sent_ts - start,
            "recv_offset_s": (recv_ts - start) if recv_ts is not None else None,
            "rtt_ms": round(rtt, 3),
            "outcome": results[-1].state,
            "reason": results[-1].reason,
            "icmp_type": int(resp[ICMP].type) if (resp is not None and resp.haslayer(ICMP)) else None,
            "icmp_code": int(resp[ICMP].code) if (resp is not None and resp.haslayer(ICMP)) else None,
        })

        delays.append(sleep_with_jitter(rate_delay, mode=jitter_mode, jitter_arg=jitter_arg))

    duration = time.time() - start

    # Build a per-second ICMP unreachable receive histogram to help visualize rate limiting.
    bin_size = 1.0
    bins = max(1, int(math.ceil(duration / bin_size)))
    icmp_per_sec = [0 for _ in range(bins)]
    for t in icmp_times:
        idx = int(t // bin_size)
        if 0 <= idx < bins:
            icmp_per_sec[idx] += 1

    def _rate_over_fraction(frac_start: float, frac_end: float) -> float:
        if duration <= 0:
            return 0.0
        t0 = max(0.0, min(duration, duration * frac_start))
        t1 = max(0.0, min(duration, duration * frac_end))
        if t1 <= t0:
            return 0.0
        count = sum(1 for t in icmp_times if t0 <= t < t1)
        return count / (t1 - t0)

    early_rate = _rate_over_fraction(0.0, 0.25)
    late_rate = _rate_over_fraction(0.75, 1.0)

    avg_icmp_rtt = (sum(icmp_rtts) / len(icmp_rtts)) if icmp_rtts else 0.0
    timeout_ms = max(0.0, float(timeout) * 1000.0)
    observed_wait_ms = sum(r.rtt_ms for r in results)
    observed_timeout_wait_ms = sum(r.rtt_ms for r in results if r.reason == "no_response")
    estimated_extra_wait_vs_icmp_ms = max(0.0, observed_timeout_wait_ms - (silent * avg_icmp_rtt))
    icmp_first = min(icmp_times) if icmp_times else None
    icmp_last = max(icmp_times) if icmp_times else None
    peak_pps = max(icmp_per_sec) if icmp_per_sec else 0
    tail_silence_seconds = round(max(0.0, duration - float(icmp_last)), 3) if icmp_last is not None else None

    suspected_rate_limiting = bool(
        icmp_unreach >= 5
        and early_rate >= 0.2
        and (
            late_rate == 0.0
            or early_rate >= (late_rate * 2.0)
        )
    )

    return {
        "technique": "udp_scan",
        "hosts": hosts,
        "ports": ports,
        "timeout_seconds": timeout,
        "rate_delay_seconds": rate_delay,
        "jitter_mode": jitter_mode,
        "jitter_arg": jitter_arg,
        "target_order_randomized": shuffle,
        "scan_duration_seconds": duration,
        "delay_stats": {
            "count": len(delays),
            "avg": sum(delays) / max(1, len(delays)),
            "p50": percentile(delays, 50),
            "p95": percentile(delays, 95),
        },
        "icmp_rate_limiting_measurements": {
            "icmp_port_unreachable_count": icmp_unreach,
            "silent_count": silent,
            "icmp_unreachable_per_second": icmp_per_sec,
            "icmp_unreachable_first_offset_s": icmp_first,
            "icmp_unreachable_last_offset_s": icmp_last,
            "icmp_unreachable_tail_silence_s": tail_silence_seconds,
            "icmp_unreachable_peak_pps": peak_pps,
            "icmp_unreachable_rate_pps_early": round(early_rate, 3),
            "icmp_unreachable_rate_pps_late": round(late_rate, 3),
            "icmp_unreachable_rate_drop_ratio": round((early_rate / late_rate), 3) if late_rate > 0 else None,
            "suspected_rate_limiting": suspected_rate_limiting,
            "timing_effect_estimate": {
                "avg_icmp_rtt_ms": round(avg_icmp_rtt, 3),
                "timeout_ms": round(timeout_ms, 3),
                "observed_wait_ms_total": round(observed_wait_ms, 3),
                "observed_wait_ms_timeouts": round(observed_timeout_wait_ms, 3),
                "estimated_extra_wait_vs_icmp_ms": round(estimated_extra_wait_vs_icmp_ms, 3),
                "note": "Timeout wait dominates scan duration when ports produce silence (open|filtered or ICMP rate limited).",
            },
            "how_to_isolate": "To isolate ICMP rate limiting, scan a large set of likely-closed UDP ports on a lab host with no UDP services and compare icmp_per_second at different delays/timeouts.",
        },
        "results": [asdict(r) for r in results],
        "probe_timeline_sample": probe_events[: min(200, len(probe_events))],
    }


def ack_scan(hosts: List[str], ports: List[int], timeout: float, rate_delay: float,
             jitter_mode: str, jitter_arg: float, shuffle: bool) -> Dict[str, object]:
    targets = shuffled_tuples(hosts, ports) if shuffle else [(h, p) for h in hosts for p in ports]
    results: List[PortResult] = []
    delays: List[float] = []

    start = time.time()
    for host, port in targets:
        r = _tcp_scan_single(host, port, flags="A", timeout=timeout)
        results.append(r)
        delays.append(sleep_with_jitter(rate_delay, mode=jitter_mode, jitter_arg=jitter_arg))

    duration = time.time() - start

    # Infer simple firewall topology map: per-host unfiltered ratio
    per_host = {}
    for r in results:
        per_host.setdefault(r.host, {"unfiltered": 0, "filtered": 0})
        if r.state == "unfiltered":
            per_host[r.host]["unfiltered"] += 1
        else:
            per_host[r.host]["filtered"] += 1

    host_inference = []
    for host, c in per_host.items():
        total = max(1, c["unfiltered"] + c["filtered"])
        host_inference.append({
            "host": host,
            "unfiltered_ports": c["unfiltered"],
            "filtered_ports": c["filtered"],
            "unfiltered_ratio": c["unfiltered"] / total,
            "inference": (
                "Likely stateful filtering present" if c["filtered"] > 0 else "No filtering observed (RST on all)"
            ),
        })

    return {
        "technique": "tcp_ack_scan",
        "hosts": hosts,
        "ports": ports,
        "timeout_seconds": timeout,
        "rate_delay_seconds": rate_delay,
        "jitter_mode": jitter_mode,
        "jitter_arg": jitter_arg,
        "target_order_randomized": shuffle,
        "scan_duration_seconds": duration,
        "results": [asdict(r) for r in results],
        "firewall_topology_map": host_inference,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Module 2: transport-layer scans")
    parser.add_argument("--host", action="append", default=[], help="Target host IP (repeatable)")
    parser.add_argument("--network", default=None, help="Target subnet CIDR (optional for multi-host)")
    parser.add_argument("--ports", default="22,80,443,445,3389", help="Comma-separated ports")
    parser.add_argument("--timeout", type=float, default=1.0, help="Probe timeout seconds")

    # Timing controls (Module 4)
    parser.add_argument("--delay", type=float, default=0.0, help="Base delay between probes (seconds)")
    parser.add_argument("--jitter", choices=["none", "uniform", "exponential"], default="none")
    parser.add_argument("--jitter-arg", type=float, default=0.0, help="Jitter parameter")
    parser.add_argument("--shuffle", action="store_true", help="Randomize (host,port) ordering")

    sub = parser.add_subparsers(dest="tech", required=True)
    sub.add_parser("syn")
    sub.add_parser("connect")
    sub.add_parser("fin")
    sub.add_parser("xmas")
    sub.add_parser("null")
    sub.add_parser("udp")
    sub.add_parser("ack")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    started_at = utc_now_iso()
    scanner_local_ip = infer_local_ip()

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    hosts: List[str]
    if args.host:
        hosts = args.host
        for h in hosts:
            ensure_private_target(h)
    else:
        network = args.network or infer_default_network()
        ensure_private_target(network)
        hosts = hosts_from_network(network)

    base_delay = max(0.0, args.delay)
    jitter_mode = args.jitter
    jitter_arg = args.jitter_arg
    shuffle = bool(args.shuffle)

    session = new_session_id(f"mod2-{args.tech}")

    if args.tech == "syn":
        result = tcp_syn_scan(hosts, ports, args.timeout, base_delay, jitter_mode, jitter_arg, shuffle)
    elif args.tech == "connect":
        result = tcp_connect_scan(hosts, ports, args.timeout, base_delay, jitter_mode, jitter_arg, shuffle)
    elif args.tech == "fin":
        result = tcp_flag_scan("tcp_fin_scan", "F", hosts, ports, args.timeout, base_delay, jitter_mode, jitter_arg, shuffle)
    elif args.tech == "xmas":
        result = tcp_flag_scan("tcp_xmas_scan", "FPU", hosts, ports, args.timeout, base_delay, jitter_mode, jitter_arg, shuffle)
    elif args.tech == "null":
        result = tcp_flag_scan("tcp_null_scan", "", hosts, ports, args.timeout, base_delay, jitter_mode, jitter_arg, shuffle)
    elif args.tech == "udp":
        result = udp_scan(hosts, ports, args.timeout, base_delay, jitter_mode, jitter_arg, shuffle)
    elif args.tech == "ack":
        result = ack_scan(hosts, ports, args.timeout, base_delay, jitter_mode, jitter_arg, shuffle)
    else:
        raise ValueError("Unknown technique")

    finished_at = utc_now_iso()
    log = write_json_log("mod2", session, {
        "started_at": started_at,
        "finished_at": finished_at,
        "scanner_local_ip": scanner_local_ip,
        "result": result,
        "detection_notes": {
            "instructions": "Run IDS/Zeek/host logs in parallel; correlate detection rate per scan technique and timing profile.",
        },
    })

    print(f"[mod2] {args.tech} scan complete. log={log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
