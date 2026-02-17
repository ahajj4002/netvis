#!/usr/bin/env python3
"""Module 4: Timing and rate control experiments (NetVis toolkit).

Implements rubric items:
- 4a Fixed-rate scan profiles (five rates)
- 4b Randomized jitter experiments + inter-packet arrival histograms
- 4c Target ordering randomization (sequential vs shuffled tuples)

This module orchestrates scans using Module 2 logic.
"""

from __future__ import annotations

import argparse
import random
import time
from typing import Dict, List, Tuple

from toolkit.utils import (
    hosts_from_network,
    infer_default_network,
    new_session_id,
    percentile,
    shuffled_tuples,
    sleep_with_jitter,
    utc_now_iso,
    write_json_log,
)

from mod2.transport_scans import _tcp_scan_single


def build_histogram(values: List[float], bins: int = 25) -> List[Dict[str, float]]:
    if not values:
        return []
    vmin = min(values)
    vmax = max(values)
    if vmax == vmin:
        return [{"start": vmin, "end": vmax, "count": float(len(values))}]

    width = (vmax - vmin) / bins
    counts = [0 for _ in range(bins)]
    for v in values:
        idx = int((v - vmin) / width)
        if idx >= bins:
            idx = bins - 1
        counts[idx] += 1

    out = []
    for i, c in enumerate(counts):
        out.append({
            "start": vmin + i * width,
            "end": vmin + (i + 1) * width,
            "count": float(c),
        })
    return out


def run_scan_tuples(tuples: List[Tuple[str, int]], timeout: float, delay: float,
                    jitter_mode: str = "none", jitter_arg: float = 0.0) -> Dict[str, object]:
    results = []
    delays = []
    sent_ts = []

    started_at = utc_now_iso()
    start = time.time()
    for host, port in tuples:
        sent_ts.append(time.time())
        r = _tcp_scan_single(host, port, flags="S", timeout=timeout)
        results.append(r)
        delays.append(sleep_with_jitter(delay, mode=jitter_mode, jitter_arg=jitter_arg))

    duration = time.time() - start
    finished_at = utc_now_iso()

    inter_arrivals = []
    for i in range(1, len(sent_ts)):
        inter_arrivals.append(sent_ts[i] - sent_ts[i - 1])

    return {
        "started_at": started_at,
        "finished_at": finished_at,
        "scan_duration_seconds": duration,
        "probe_count": len(tuples),
        "delay_seconds_config": delay,
        "jitter_mode": jitter_mode,
        "jitter_arg": jitter_arg,
        "delay_seconds_used": delays,
        "inter_arrival_seconds": inter_arrivals,
        "inter_arrival_histogram": build_histogram(inter_arrivals, bins=25),
        "delay_stats": {
            "avg": sum(delays) / max(1, len(delays)),
            "p50": percentile(delays, 50),
            "p95": percentile(delays, 95),
        },
        "counts": {
            "open": sum(1 for r in results if r.state == "open"),
            "closed": sum(1 for r in results if r.state == "closed"),
            "filtered": sum(1 for r in results if r.state == "filtered"),
        },
        "scan_completeness": {
            "total": len(tuples),
            "definitive": sum(1 for r in results if r.state in ("open", "closed")),
            "definitive_ratio": (sum(1 for r in results if r.state in ("open", "closed")) / max(1, len(tuples))),
            "filtered": sum(1 for r in results if r.state == "filtered"),
            "filtered_ratio": (sum(1 for r in results if r.state == "filtered") / max(1, len(tuples))),
            "definition": "Definitive = open|closed. Filtered/no-response reduces completeness at this timeout/rate.",
        },
        "results": [r.__dict__ for r in results],
    }


def fixed_rate_profiles(targets: List[Tuple[str, int]], timeout: float) -> Dict[str, object]:
    profiles = {
        "rate_1_per_5_min": 300.0,
        "rate_1_per_15_sec": 15.0,
        "rate_1_per_0_4_sec": 0.4,
        "rate_1_per_10_ms": 0.01,
        "rate_unrestricted": 0.0,
    }

    out = {}
    for name, delay in profiles.items():
        out[name] = run_scan_tuples(targets, timeout=timeout, delay=delay)
    return {
        "technique": "fixed_rate_scan_profiles",
        "profiles": out,
        "ids_detection_template": {
            "instructions": "Run Suricata/Snort threshold rules for each profile; record alerts and detection rate.",
            "fields_to_fill_in_report": [
                "ids_alerts_count",
                "ids_first_alert_time",
                "scan_completeness",
            ],
        },
    }


def jitter_experiment(targets: List[Tuple[str, int]], timeout: float, base_delay: float) -> Dict[str, object]:
    fixed = run_scan_tuples(targets, timeout=timeout, delay=base_delay, jitter_mode="none")
    uniform = run_scan_tuples(targets, timeout=timeout, delay=base_delay, jitter_mode="uniform", jitter_arg=base_delay)
    expo = run_scan_tuples(targets, timeout=timeout, delay=base_delay, jitter_mode="exponential", jitter_arg=max(1e-6, 1.0 / max(1e-6, base_delay)))

    return {
        "technique": "randomized_jitter",
        "base_delay_seconds": base_delay,
        "fixed": fixed,
        "uniform": uniform,
        "exponential": expo,
        "analysis_prompts": [
            "Compare inter-arrival histograms (fixed vs jitter).",
            "Compare IDS/anomaly detection rates at equivalent average probe rate.",
        ],
    }


def ordering_randomization(targets: List[Tuple[str, int]], timeout: float, delay: float) -> Dict[str, object]:
    sequential = run_scan_tuples(targets, timeout=timeout, delay=delay, jitter_mode="none")
    shuffled_targets = list(targets)
    random.shuffle(shuffled_targets)
    shuffled = run_scan_tuples(shuffled_targets, timeout=timeout, delay=delay, jitter_mode="none")

    return {
        "technique": "target_order_randomization",
        "delay_seconds": delay,
        "sequential": sequential,
        "shuffled": shuffled,
        "analysis_prompts": [
            "Compare sequential-scan heuristic triggers vs shuffled ordering.",
            "Compare scan completeness and IDS alerts under same rate.",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Module 4: timing and rate control")
    parser.add_argument("--host", action="append", default=[], help="Target host (repeatable)")
    parser.add_argument("--network", default=None, help="Target subnet CIDR")
    parser.add_argument("--ports", default="22,80,443", help="Comma-separated ports")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--max-tuples", type=int, default=30, help="Limit host:port tuples to keep long profiles feasible")

    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("fixed")
    p_j = sub.add_parser("jitter")
    p_j.add_argument("--base-delay", type=float, default=0.4)
    p_o = sub.add_parser("order")
    p_o.add_argument("--delay", type=float, default=0.4)

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    started_at = utc_now_iso()

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    hosts: List[str]
    if args.host:
        hosts = args.host
    else:
        network = args.network or infer_default_network()
        hosts = hosts_from_network(network)

    tuples = [(h, p) for h in hosts for p in ports]
    tuples = tuples[: max(1, args.max_tuples)]

    session = new_session_id(f"mod4-{args.mode}")

    if args.mode == "fixed":
        result = fixed_rate_profiles(tuples, timeout=args.timeout)
    elif args.mode == "jitter":
        result = jitter_experiment(tuples, timeout=args.timeout, base_delay=args.base_delay)
    elif args.mode == "order":
        result = ordering_randomization(tuples, timeout=args.timeout, delay=args.delay)
    else:
        raise ValueError("Unknown mode")

    finished_at = utc_now_iso()
    out = write_json_log("mod4", session, {"started_at": started_at, "finished_at": finished_at, "targets": tuples, "result": result})
    print(f"[mod4] {args.mode} complete. log={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
