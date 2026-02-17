#!/usr/bin/env python3
"""NIP Phase 7.3 — Intelligence Quality Metrics.

Compute metrics that measure how well NIP is doing its job:
  - Discovery completeness
  - Identity resolution accuracy (when ground truth is available)
  - Anomaly detection precision/recall (from confirmed alerts)
  - Risk score calibration
  - Time to detection
  - Brain efficiency
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional


def discovery_completeness(
    *,
    discovered_ips: List[str],
    ground_truth_ips: Optional[List[str]] = None,
    subnet_cidrs: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Measure what fraction of the ground truth (or expected subnet hosts) we found."""
    discovered = set(str(ip).strip() for ip in (discovered_ips or []) if ip)

    if ground_truth_ips:
        truth = set(str(ip).strip() for ip in ground_truth_ips if ip)
        found = discovered & truth
        missed = truth - discovered
        extra = discovered - truth
        pct = (len(found) / max(1, len(truth))) * 100.0
        return {
            "metric": "discovery_completeness",
            "completeness_pct": round(pct, 1),
            "discovered": len(discovered),
            "ground_truth": len(truth),
            "found": sorted(list(found)),
            "missed": sorted(list(missed)),
            "extra": sorted(list(extra)),
        }
    else:
        return {
            "metric": "discovery_completeness",
            "discovered": len(discovered),
            "ground_truth": None,
            "completeness_pct": None,
            "note": "No ground truth provided; only reporting count.",
        }


def identity_resolution_accuracy(
    *,
    resolved_pairs: List[Dict[str, Any]],
    ground_truth_pairs: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Measure identity resolution accuracy (TP/FP/FN) against ground truth.

    Each pair: {"new_ip": "...", "old_ip": "...", "matched": True/False}
    Ground truth: {"new_ip": "...", "old_ip": "...", "same": True/False}
    """
    if not ground_truth_pairs:
        total = len(resolved_pairs or [])
        matched = sum(1 for p in (resolved_pairs or []) if p.get("matched"))
        return {
            "metric": "identity_resolution_accuracy",
            "total_comparisons": total,
            "matched": matched,
            "accuracy": None,
            "note": "No ground truth; reporting counts only.",
        }

    truth_map = {}
    for gt in ground_truth_pairs:
        key = (str(gt.get("new_ip", "")), str(gt.get("old_ip", "")))
        truth_map[key] = bool(gt.get("same", False))

    tp = fp = fn = tn = 0
    for p in (resolved_pairs or []):
        key = (str(p.get("new_ip", "")), str(p.get("old_ip", "")))
        predicted = bool(p.get("matched", False))
        actual = truth_map.get(key)
        if actual is None:
            continue
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and actual:
            fn += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    return {
        "metric": "identity_resolution_accuracy",
        "total": total,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def anomaly_detection_quality(
    *,
    alerts: List[dict],
    confirmed_true: Optional[List[str]] = None,
    confirmed_false: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Measure anomaly precision/recall from analyst-confirmed alert IDs."""
    total = len(alerts or [])
    if not confirmed_true and not confirmed_false:
        return {
            "metric": "anomaly_detection_quality",
            "total_alerts": total,
            "precision": None,
            "recall": None,
            "note": "No confirmed true/false labels; reporting count only.",
        }

    ct = set(confirmed_true or [])
    cf = set(confirmed_false or [])

    alert_ids = set()
    for a in (alerts or []):
        aid = str(a.get("id") or a.get("alert_id") or "")
        if aid:
            alert_ids.add(aid)

    tp = len(alert_ids & ct)
    fp = len(alert_ids & cf)
    fn = len(ct - alert_ids)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)

    return {
        "metric": "anomaly_detection_quality",
        "total_alerts": total,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
    }


def risk_score_distribution(
    *,
    device_scores: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Summarize risk score distribution across devices."""
    scores = []
    for d in (device_scores or []):
        try:
            scores.append(float(d.get("score", 0.0)))
        except Exception:
            continue

    if not scores:
        return {"metric": "risk_score_distribution", "count": 0}

    buckets = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for s in scores:
        if s >= 0.8:
            buckets["critical"] += 1
        elif s >= 0.6:
            buckets["high"] += 1
        elif s >= 0.35:
            buckets["medium"] += 1
        else:
            buckets["low"] += 1

    return {
        "metric": "risk_score_distribution",
        "count": len(scores),
        "min": round(min(scores), 4),
        "max": round(max(scores), 4),
        "mean": round(sum(scores) / len(scores), 4),
        "buckets": buckets,
    }


def time_to_detection(
    *,
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Measure how quickly new devices/threats were detected after first_seen.

    Each event: {"entity": "...", "first_seen": "...", "detected_at": "..."}
    """
    deltas = []
    for e in (events or []):
        try:
            fs = datetime.fromisoformat(str(e.get("first_seen", "")))
            da = datetime.fromisoformat(str(e.get("detected_at", "")))
            delta = (da - fs).total_seconds()
            if delta >= 0:
                deltas.append(delta)
        except Exception:
            continue

    if not deltas:
        return {"metric": "time_to_detection", "count": 0}

    return {
        "metric": "time_to_detection",
        "count": len(deltas),
        "min_seconds": round(min(deltas), 1),
        "max_seconds": round(max(deltas), 1),
        "avg_seconds": round(sum(deltas) / len(deltas), 1),
        "median_seconds": round(sorted(deltas)[len(deltas) // 2], 1),
    }


def brain_efficiency(
    *,
    probes_sent: int,
    coverage_achieved_pct: float,
    findings_count: int,
) -> Dict[str, Any]:
    """Measure Brain efficiency: coverage per probe, findings per probe."""
    return {
        "metric": "brain_efficiency",
        "probes_sent": probes_sent,
        "coverage_achieved_pct": round(coverage_achieved_pct, 1),
        "findings_count": findings_count,
        "coverage_per_probe": round(coverage_achieved_pct / max(1, probes_sent), 4),
        "findings_per_probe": round(findings_count / max(1, probes_sent), 4),
    }


def compute_all_metrics(
    *,
    assets: List[dict],
    services: List[dict],
    alerts: List[dict],
    device_scores: List[Dict[str, Any]],
    ground_truth_ips: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Compute all available quality metrics from current data."""
    discovered_ips = [str(a.get("ip", "")) for a in (assets or []) if a.get("ip")]
    metrics = {
        "generated_at": datetime.now().isoformat(),
        "discovery": discovery_completeness(
            discovered_ips=discovered_ips,
            ground_truth_ips=ground_truth_ips,
        ),
        "anomaly": anomaly_detection_quality(alerts=alerts),
        "risk_distribution": risk_score_distribution(device_scores=device_scores),
    }
    return metrics
