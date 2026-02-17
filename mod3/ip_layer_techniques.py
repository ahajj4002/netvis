#!/usr/bin/env python3
"""Module 3: IP-layer reconnaissance techniques (NetVis toolkit).

Implements:
- 3a IP fragmentation testing (including optional overlapping fragments)
- 3b TTL-based path inference (traceroute-like mapping)
- 3c IPID sequence profiling and (optional) idle scan
- 3d Decoy source mixing (spoofed-source probes interleaved)

Safety:
- Spoofing features require explicit --lab-ok acknowledgement.
"""

from __future__ import annotations

import argparse
import random
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

from scapy.all import (
    IP,
    ICMP,
    TCP,
    Raw,
    conf,
    fragment,
    send,
    sniff,
    sr1,
)

from toolkit.utils import (
    ensure_private_target,
    hosts_from_network,
    infer_default_network,
    infer_local_ip,
    new_session_id,
    percentile,
    utc_now_iso,
    write_json_log,
)

conf.verb = 0


@dataclass
class Hop:
    ttl: int
    responder_ip: str
    rtt_ms: float
    icmp_type: int
    icmp_code: int


def ttl_path_inference(target: str, max_hops: int = 20, timeout: float = 1.0, method: str = "icmp",
                       dport: int = 80) -> Dict[str, object]:
    ensure_private_target(target)
    hops: List[Hop] = []
    reached = False
    start = time.time()

    for ttl in range(1, max_hops + 1):
        if method == "tcp":
            sport = random.randint(1024, 65535)
            probe = IP(dst=target, ttl=ttl) / TCP(sport=sport, dport=dport, flags="S", seq=random.randint(0, 2**32 - 1))
        else:
            probe = IP(dst=target, ttl=ttl) / ICMP()

        t0 = time.time()
        resp = sr1(probe, timeout=timeout, verbose=False)
        rtt_ms = (time.time() - t0) * 1000.0

        if resp is None:
            hops.append(Hop(ttl=ttl, responder_ip="*", rtt_ms=rtt_ms, icmp_type=-1, icmp_code=-1))
            continue

        if resp.haslayer(ICMP):
            ic = resp.getlayer(ICMP)
            responder = resp.getlayer(IP).src
            hops.append(Hop(ttl=ttl, responder_ip=responder, rtt_ms=rtt_ms, icmp_type=int(ic.type), icmp_code=int(ic.code)))
            # type 0 echo-reply, type 3 dest-unreach, type 11 time-exceeded
            if responder == target or ic.type in (0, 3):
                reached = True
                break
        elif resp.haslayer(TCP):
            responder = resp.getlayer(IP).src
            # For TCP method, reaching target likely yields SYN-ACK or RST
            hops.append(Hop(ttl=ttl, responder_ip=responder, rtt_ms=rtt_ms, icmp_type=-2, icmp_code=-2))
            if responder == target:
                reached = True
                break
        else:
            responder = resp.getlayer(IP).src
            hops.append(Hop(ttl=ttl, responder_ip=responder, rtt_ms=rtt_ms, icmp_type=-3, icmp_code=-3))
            if responder == target:
                reached = True
                break

    duration = time.time() - start

    # Build simple topology edges between consecutive non-* hops
    edges = []
    prev = None
    for h in hops:
        if h.responder_ip == "*":
            continue
        if prev and prev != h.responder_ip:
            edges.append({"src": prev, "dst": h.responder_ip})
        prev = h.responder_ip

    return {
        "technique": "ttl_path_inference",
        "target": target,
        "method": method,
        "tcp_dport": dport if method == "tcp" else None,
        "max_hops": max_hops,
        "timeout_seconds": timeout,
        "reached_target": reached,
        "scan_duration_seconds": duration,
        "hops": [asdict(h) for h in hops],
        "topology_edges": edges,
        "monitoring_position_notes": {
            "prompt": "If you run an IDS/monitor, note at which TTL the probe expires relative to monitor visibility.",
        },
    }


def fragmentation_test(target: str, dport: int, timeout: float = 2.0, fragsize: int = 8,
                       overlap: bool = False) -> Dict[str, object]:
    ensure_private_target(target)
    local_ip = infer_local_ip()
    sport = random.randint(1024, 65535)
    seq = random.randint(0, 2**32 - 1)

    # Include some payload so fragmentation has enough bytes.
    base = IP(dst=target) / TCP(sport=sport, dport=dport, flags="S", seq=seq) / Raw(load=b"A" * 64)

    frags = fragment(base, fragsize=fragsize)

    tx_plan = {
        "fragsize": fragsize,
        "fragment_count": len(frags),
        "fragments": [
            {
                "id": int(f.id),
                "frag_offset": int(f.frag),
                "mf": int(f.flags.MF),
                "len": int(len(f)),
            }
            for f in frags
        ],
    }

    scenarios = []

    def send_and_observe(name: str, frag_list: List[IP]) -> Dict[str, object]:
        # Send fragments
        for f in frag_list:
            send(f, verbose=False)

        # Observe response (SYN-ACK, RST, or ICMP)
        bpf = f"(tcp or icmp) and src host {target} and dst host {local_ip}"
        observed = sniff(filter=bpf, timeout=timeout, count=5)

        resp_summary = []
        for p in observed:
            if p.haslayer(TCP):
                resp_summary.append({
                    "src": p[IP].src,
                    "dst": p[IP].dst,
                    "tcp_flags": int(p[TCP].flags),
                    "sport": int(p[TCP].sport),
                    "dport": int(p[TCP].dport),
                })
            elif p.haslayer(ICMP):
                resp_summary.append({
                    "src": p[IP].src,
                    "dst": p[IP].dst,
                    "icmp_type": int(p[ICMP].type),
                    "icmp_code": int(p[ICMP].code),
                })

        return {
            "scenario": name,
            "response_packets": resp_summary,
            "response_received": len(resp_summary) > 0,
        }

    # Normal fragmentation send
    scenarios.append(send_and_observe("baseline_fragmented", frags))

    if overlap and len(frags) >= 3:
        # Create an overlapping fragment by duplicating a middle fragment with same offset
        # but different payload. This is a best-effort overlapping fragment test.
        overlap_frags = [f.copy() for f in frags]
        victim = overlap_frags[1]
        o = victim.copy()
        o.load = bytes(b"B" * len(bytes(victim.payload)))
        # Force same frag offset as victim (already), send overlapped after baseline
        overlap_frags.insert(2, o)
        scenarios.append(send_and_observe("overlap_same_offset", overlap_frags))

        # Different ordering: overlap first then baseline
        reordered = [o] + [f.copy() for f in frags]
        scenarios.append(send_and_observe("overlap_first", reordered))

    return {
        "technique": "ip_fragmentation_testing",
        "target": target,
        "dport": dport,
        "sport": sport,
        "timeout_seconds": timeout,
        "tx_plan": tx_plan,
        "overlap_test_enabled": overlap,
        "scenarios": scenarios,
        "monitor_target_reassembly_comparison": {
            "prompt": "Run a monitor (e.g., Suricata) and compare its reassembled stream vs target response behavior.",
            "note": "Overlapping fragments may be handled differently across stacks and monitors.",
        },
    }


def ipid_sequence_profile(zombie: str, probes: int = 20, interval: float = 0.2, timeout: float = 1.0) -> Dict[str, object]:
    ensure_private_target(zombie)
    ipids: List[int] = []
    rtts: List[float] = []
    ttls: List[int] = []

    for _ in range(probes):
        pkt = IP(dst=zombie) / ICMP()
        t0 = time.time()
        resp = sr1(pkt, timeout=timeout, verbose=False)
        rtt = (time.time() - t0) * 1000.0
        if resp and resp.haslayer(IP):
            ipids.append(int(resp[IP].id))
            rtts.append(rtt)
            ttls.append(int(resp[IP].ttl))
        time.sleep(max(0.0, interval))

    deltas = [(ipids[i + 1] - ipids[i]) % 65536 for i in range(len(ipids) - 1)]

    sequential_ratio = 0.0
    if deltas:
        sequential_ratio = sum(1 for d in deltas if d in (1, 2)) / len(deltas)

    classification = "unknown"
    if len(deltas) >= 8:
        if sequential_ratio >= 0.8:
            classification = "sequential_global_or_near_sequential"
        elif len(set(deltas)) > len(deltas) * 0.6:
            classification = "likely_randomized"
        else:
            classification = "mixed_or_per_destination"

    zombie_suitable = bool(classification == "sequential_global_or_near_sequential" and sequential_ratio >= 0.8 and len(deltas) >= 8)

    return {
        "technique": "ipid_sequence_profile",
        "zombie": zombie,
        "probes": probes,
        "interval_seconds": interval,
        "timeout_seconds": timeout,
        "ipids": ipids,
        "ttls": ttls,
        "deltas": deltas,
        "classification": classification,
        "sequential_ratio": sequential_ratio,
        "zombie_suitable": zombie_suitable,
        "rtt_stats_ms": {
            "count": len(rtts),
            "p50": percentile(rtts, 50),
            "p95": percentile(rtts, 95),
        },
        "ttl_stats": {
            "count": len(ttls),
            "p50": percentile(ttls, 50),
            "p95": percentile(ttls, 95),
            "hint": "TTL ~128 often indicates Windows-like stacks; TTL ~64 often indicates Unix-like stacks (heuristic).",
        },
    }


def idle_scan(zombie: str, target: str, dport: int, timeout: float = 1.0) -> Dict[str, object]:
    ensure_private_target(zombie)
    ensure_private_target(target)

    precheck = ipid_sequence_profile(zombie, probes=10, interval=0.1, timeout=timeout)
    if not precheck.get("zombie_suitable"):
        return {
            "technique": "idle_scan",
            "zombie": zombie,
            "target": target,
            "dport": dport,
            "precheck": precheck,
            "error": "zombie_not_suitable_for_idle_scan",
            "note": "Choose a different zombie host with sequential/global IPID increments.",
        }

    # Step 1: probe zombie IPID
    p1 = sr1(IP(dst=zombie) / ICMP(), timeout=timeout, verbose=False)
    if not p1:
        return {"error": "Zombie did not respond to probes"}
    ipid1 = int(p1[IP].id)

    # Step 2: spoof SYN to target as if from zombie
    spoof_sport = random.randint(1024, 65535)
    syn = IP(src=zombie, dst=target) / TCP(sport=spoof_sport, dport=dport, flags="S", seq=random.randint(0, 2**32 - 1))
    send(syn, verbose=False)

    # Step 3: probe zombie IPID again
    p2 = sr1(IP(dst=zombie) / ICMP(), timeout=timeout, verbose=False)
    if not p2:
        return {"error": "Zombie probe after spoof did not respond"}
    ipid2 = int(p2[IP].id)

    delta = (ipid2 - ipid1) % 65536

    inference = "inconclusive"
    # Heuristic: if zombie increments for its own ICMP replies (+1) and for RST to SYN-ACK (+1)
    if delta == 1:
        inference = "target_port_closed_or_filtered"
    elif delta == 2:
        inference = "target_port_open"
    else:
        inference = "zombie_not_suitable_or_background_traffic"

    return {
        "technique": "idle_scan",
        "zombie": zombie,
        "target": target,
        "dport": dport,
        "precheck": precheck,
        "ipid1": ipid1,
        "ipid2": ipid2,
        "delta": delta,
        "inference": inference,
        "notes": "For full credit, document which OSes in lab are predictable vs randomized and validate with ground truth.",
    }


def ipid_sweep(hosts: List[str], probes: int = 12, interval: float = 0.15, timeout: float = 1.0) -> Dict[str, object]:
    """Profile IPID behavior across multiple hosts to find suitable idle-scan zombies."""
    start = time.time()

    results = []
    for h in hosts:
        prof = ipid_sequence_profile(h, probes=probes, interval=interval, timeout=timeout)
        results.append({
            "host": h,
            "classification": prof.get("classification"),
            "sequential_ratio": prof.get("sequential_ratio"),
            "zombie_suitable": prof.get("zombie_suitable"),
            "ttl_p50": (prof.get("ttl_stats") or {}).get("p50"),
            "ttl_p95": (prof.get("ttl_stats") or {}).get("p95"),
            "deltas_sample": (prof.get("deltas") or [])[:12],
        })

    duration = time.time() - start

    counts = {"sequential": 0, "randomized": 0, "mixed": 0, "unknown": 0}
    for r in results:
        c = r.get("classification") or "unknown"
        if c == "sequential_global_or_near_sequential":
            counts["sequential"] += 1
        elif c == "likely_randomized":
            counts["randomized"] += 1
        elif c == "mixed_or_per_destination":
            counts["mixed"] += 1
        else:
            counts["unknown"] += 1

    suitable = [r for r in results if r.get("zombie_suitable")]

    return {
        "technique": "ipid_sweep",
        "host_count": len(hosts),
        "probes_per_host": probes,
        "interval_seconds": interval,
        "timeout_seconds": timeout,
        "scan_duration_seconds": duration,
        "counts": counts,
        "suitable_candidates": suitable[:25],
        "results": results,
        "report_prompt": "Cross-reference these hosts with known lab OSes (or Module 5 TCP fingerprinting) and document which OSes are predictable vs randomized.",
    }


def decoy_source_mixing(target: str, dport: int, decoys: List[str], real_probes: int = 5,
                        timeout: float = 1.0) -> Dict[str, object]:
    ensure_private_target(target)
    for d in decoys:
        ensure_private_target(d)
    local_ip = infer_local_ip()

    # Interleave real probe packets and spoofed-source packets
    plan = []
    for i in range(real_probes):
        plan.append({"type": "real", "src": local_ip})
        if decoys:
            plan.append({"type": "decoy", "src": random.choice(decoys)})

    random.shuffle(plan)

    observed_real = []

    for step in plan:
        sport = random.randint(1024, 65535)
        pkt = IP(src=step["src"], dst=target) / TCP(sport=sport, dport=dport, flags="S", seq=random.randint(0, 2**32 - 1))
        send(pkt, verbose=False)

        if step["type"] == "real":
            # Listen for response to our real probe
            bpf = f"tcp and src host {target} and dst host {local_ip}"
            pkts = sniff(filter=bpf, timeout=timeout, count=1)
            if pkts and pkts[0].haslayer(TCP):
                observed_real.append({
                    "tcp_flags": int(pkts[0][TCP].flags),
                    "sport": int(pkts[0][TCP].sport),
                    "dport": int(pkts[0][TCP].dport),
                })

    return {
        "technique": "decoy_source_mixing",
        "target": target,
        "dport": dport,
        "local_ip": local_ip,
        "decoys": decoys,
        "send_plan": plan,
        "real_probe_responses": observed_real,
        "analysis_template": {
            "target_log_expectation": "Target logs should show SYN attempts from multiple source IPs.",
            "defender_needs": [
                "NetFlow/pcap from ingress to correlate true source MAC/interface",
                "Multiple vantage points or L2 telemetry",
                "Ingress switch port mapping",
            ],
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Module 3: IP-layer techniques")

    sub = parser.add_subparsers(dest="tech", required=True)

    p_frag = sub.add_parser("frag", help="3a IP fragmentation testing")
    p_frag.add_argument("--target", required=True)
    p_frag.add_argument("--dport", type=int, default=80)
    p_frag.add_argument("--fragsize", type=int, default=8)
    p_frag.add_argument("--timeout", type=float, default=2.0)
    p_frag.add_argument("--overlap", action="store_true")

    p_ttl = sub.add_parser("ttl", help="3b TTL-based path inference")
    p_ttl.add_argument("--target", required=True)
    p_ttl.add_argument("--max-hops", type=int, default=20)
    p_ttl.add_argument("--timeout", type=float, default=1.0)
    p_ttl.add_argument("--method", choices=["icmp", "tcp"], default="icmp")
    p_ttl.add_argument("--dport", type=int, default=80)

    p_ipid = sub.add_parser("ipid", help="3c IPID sequence profiling")
    p_ipid.add_argument("--zombie", required=True)
    p_ipid.add_argument("--probes", type=int, default=20)
    p_ipid.add_argument("--interval", type=float, default=0.2)
    p_ipid.add_argument("--timeout", type=float, default=1.0)

    p_sweep = sub.add_parser("ipid-sweep", help="3c IPID profiling across many hosts (find suitable zombies)")
    p_sweep.add_argument("--host", action="append", default=[], help="Target host IP (repeatable)")
    p_sweep.add_argument("--network", default=None, help="Target subnet CIDR (optional)")
    p_sweep.add_argument("--max-hosts", type=int, default=64, help="Limit hosts to profile when using --network")
    p_sweep.add_argument("--probes", type=int, default=12)
    p_sweep.add_argument("--interval", type=float, default=0.15)
    p_sweep.add_argument("--timeout", type=float, default=1.0)

    p_idle = sub.add_parser("idle", help="3c Idle scan (spoofed SYN)")
    p_idle.add_argument("--zombie", required=True)
    p_idle.add_argument("--target", required=True)
    p_idle.add_argument("--dport", type=int, required=True)
    p_idle.add_argument("--timeout", type=float, default=1.0)
    p_idle.add_argument("--lab-ok", action="store_true", help="Acknowledge lab-only spoofing")

    p_decoy = sub.add_parser("decoy", help="3d Decoy source mixing (spoofed sources)")
    p_decoy.add_argument("--target", required=True)
    p_decoy.add_argument("--dport", type=int, required=True)
    p_decoy.add_argument("--decoy", action="append", default=[], help="Decoy source IP (repeatable)")
    p_decoy.add_argument("--real-probes", type=int, default=5)
    p_decoy.add_argument("--timeout", type=float, default=1.0)
    p_decoy.add_argument("--lab-ok", action="store_true", help="Acknowledge lab-only spoofing")

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    session = new_session_id(f"mod3-{args.tech}")
    started_at = utc_now_iso()
    scanner_local_ip = infer_local_ip()

    if args.tech == "frag":
        result = fragmentation_test(args.target, args.dport, timeout=args.timeout, fragsize=args.fragsize, overlap=args.overlap)
    elif args.tech == "ttl":
        result = ttl_path_inference(args.target, max_hops=args.max_hops, timeout=args.timeout, method=args.method, dport=args.dport)
    elif args.tech == "ipid":
        result = ipid_sequence_profile(args.zombie, probes=args.probes, interval=args.interval, timeout=args.timeout)
    elif args.tech == "ipid-sweep":
        if args.host:
            hosts = args.host
        else:
            network = args.network or infer_default_network()
            ensure_private_target(network)
            hosts = hosts_from_network(network, max_hosts=max(1, int(args.max_hosts)))
        result = ipid_sweep(hosts, probes=args.probes, interval=args.interval, timeout=args.timeout)
    elif args.tech == "idle":
        if not args.lab_ok:
            raise SystemExit("Refusing to run spoofing technique without --lab-ok")
        result = idle_scan(args.zombie, args.target, args.dport, timeout=args.timeout)
    elif args.tech == "decoy":
        if not args.lab_ok:
            raise SystemExit("Refusing to run spoofing technique without --lab-ok")
        result = decoy_source_mixing(args.target, args.dport, decoys=args.decoy, real_probes=args.real_probes, timeout=args.timeout)
    else:
        raise ValueError("Unknown tech")

    finished_at = utc_now_iso()
    out = write_json_log("mod3", session, {"started_at": started_at, "finished_at": finished_at, "scanner_local_ip": scanner_local_ip, "result": result})
    print(f"[mod3] {args.tech} complete. log={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
