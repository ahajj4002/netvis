#!/usr/bin/env python3
"""Analytical / inference techniques (NIP extensions).

This module is intentionally pure (no direct DB access). The server runner
passes in assets/services/flows/metrics/alerts/observations as Python objects.
"""

from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set, Tuple


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(ts))
    except Exception:
        return None


def _hour_of(ts: str) -> Optional[int]:
    dt = _parse_iso(ts)
    if not dt:
        return None
    return int(dt.hour)


def compute_baseline_from_metrics(metrics: List[dict], *, decay: float = 0.97, min_windows: int = 6) -> Dict[str, object]:
    """Compute an exponentially-decayed baseline + active-hour profile."""
    rows = [m for m in (metrics or []) if isinstance(m, dict)]
    if len(rows) < min_windows:
        return {"ok": False, "reason": f"not_enough_windows(min={min_windows})", "baseline": {}, "active_hours": []}

    # Expect metrics newest-first; if not, this still works.
    w_sum = 0.0
    acc = defaultdict(float)
    hour_bytes = defaultdict(float)
    hour_w = defaultdict(float)

    for i, m in enumerate(rows):
        w = float(decay) ** float(i)
        w_sum += w
        for k in ("bytes_out", "bytes_in", "unique_dst_ips", "unique_dst_ports", "dns_queries"):
            try:
                acc[k] += w * float(m.get(k) or 0.0)
            except Exception:
                continue
        hr = _hour_of(str(m.get("timestamp") or ""))
        if hr is not None:
            try:
                hour_bytes[int(hr)] += w * float(m.get("bytes_out") or 0.0)
                hour_w[int(hr)] += w
            except Exception:
                pass

    if w_sum <= 0.0:
        return {"ok": False, "reason": "invalid_weights", "baseline": {}, "active_hours": []}

    baseline = {
        "avg_bytes_out": acc["bytes_out"] / w_sum,
        "avg_bytes_in": acc["bytes_in"] / w_sum,
        "avg_unique_dst_ips": acc["unique_dst_ips"] / w_sum,
        "avg_unique_dst_ports": acc["unique_dst_ports"] / w_sum,
        "avg_dns_queries": acc["dns_queries"] / w_sum,
    }

    # Active hours: hours where average bytes_out exceeds a fraction of the max hour.
    hour_avg = {}
    for hr in range(24):
        if hour_w.get(hr, 0.0) > 0:
            hour_avg[hr] = hour_bytes.get(hr, 0.0) / hour_w[hr]
    max_hr = max(hour_avg.values()) if hour_avg else 0.0
    active_hours = []
    if max_hr > 0:
        for hr, v in sorted(hour_avg.items()):
            if v >= max_hr * 0.25:
                active_hours.append(int(hr))

    return {"ok": True, "baseline": baseline, "active_hours": active_hours, "windows": len(rows), "decay": float(decay)}


def score_anomaly(
    *,
    metric: dict,
    baseline: dict,
    active_hours: Optional[List[int]] = None,
    weights: Optional[dict] = None,
) -> Dict[str, object]:
    """Multi-factor anomaly score in [0,1] with per-factor breakdown."""
    metric = metric or {}
    baseline = baseline or {}
    active_hours = list(active_hours or [])
    w = weights or {"new_destinations": 0.3, "unusual_ports": 0.2, "off_hours": 0.2, "volume_spike": 0.3}

    def f_cur(name: str) -> float:
        try:
            return float(metric.get(name) or 0.0)
        except Exception:
            return 0.0

    def f_avg(name: str) -> float:
        try:
            return float(baseline.get(name) or 0.0)
        except Exception:
            return 0.0

    cur_bytes = f_cur("bytes_out")
    cur_dst_ips = f_cur("unique_dst_ips")
    cur_dst_ports = f_cur("unique_dst_ports")
    cur_dns = f_cur("dns_queries")

    avg_bytes = max(1.0, f_avg("avg_bytes_out"))
    avg_dst_ips = max(1.0, f_avg("avg_unique_dst_ips"))
    avg_dst_ports = max(1.0, f_avg("avg_unique_dst_ports"))

    factors = {}
    # New destinations: ratio above baseline.
    factors["new_destinations"] = min(1.0, max(0.0, (cur_dst_ips - avg_dst_ips) / max(1.0, avg_dst_ips * 4.0)))
    # Unusual ports: ratio above baseline.
    factors["unusual_ports"] = min(1.0, max(0.0, (cur_dst_ports - avg_dst_ports) / max(1.0, avg_dst_ports * 4.0)))
    # Volume spike.
    factors["volume_spike"] = min(1.0, max(0.0, (cur_bytes - avg_bytes) / max(1.0, avg_bytes * 6.0)))
    # Off-hours.
    off_hours = 0.0
    hr = None
    try:
        hr = _hour_of(str(metric.get("timestamp") or ""))
    except Exception:
        hr = None
    if hr is not None and active_hours:
        if int(hr) not in set(int(x) for x in active_hours):
            # Require some activity to count as off-hours.
            if cur_bytes >= max(20_000.0, avg_bytes * 2.0) or cur_dns >= 20:
                off_hours = 1.0
    factors["off_hours"] = off_hours

    score = 0.0
    for k, wk in w.items():
        score += float(wk) * float(factors.get(k, 0.0))
    score = max(0.0, min(score, 1.0))

    return {"score": float(score), "factors": factors, "weights": w, "active_hours": active_hours}


def _top_n(counter: Counter, n: int) -> List[str]:
    return [k for k, _v in counter.most_common(max(0, int(n)))]


def compute_device_features(*, ip: str, flows: List[dict], dns_queries: List[dict], top_n: int = 20) -> Dict[str, object]:
    """Compute a small behavioral fingerprint for identity resolution."""
    ip_s = str(ip or "").strip()
    dst_ips = Counter()
    dst_ports = Counter()
    domains = Counter()

    for f in flows or []:
        if not isinstance(f, dict):
            continue
        if str(f.get("src_ip") or "") != ip_s:
            continue
        dip = str(f.get("dst_ip") or "").strip()
        if dip:
            dst_ips[dip] += int(f.get("byte_count") or 0) + 1
        try:
            dp = int(f.get("dst_port") or 0)
            if dp > 0:
                dst_ports[str(dp)] += int(f.get("byte_count") or 0) + 1
        except Exception:
            pass

    for q in dns_queries or []:
        if not isinstance(q, dict):
            continue
        if str(q.get("src_ip") or "") != ip_s:
            continue
        d = str(q.get("domain") or "").strip().lower()
        if d:
            domains[d] += 1

    return {
        "ip": ip_s,
        "top_dst_ips": _top_n(dst_ips, top_n),
        "top_dst_ports": [int(p) for p in _top_n(dst_ports, top_n) if str(p).isdigit()],
        "top_domains": _top_n(domains, top_n),
    }


def _jaccard(a: Iterable, b: Iterable) -> float:
    sa = set(a or [])
    sb = set(b or [])
    if not sa and not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    if union <= 0:
        return 0.0
    return float(inter) / float(union)


def identity_resolve(
    *,
    new_features: Dict[str, object],
    candidates: List[Dict[str, object]],
    threshold: float = 0.85,
) -> Dict[str, object]:
    """Match a new device against candidates using behavioral similarity."""
    best = None
    best_score = 0.0

    for c in candidates or []:
        if not isinstance(c, dict):
            continue
        score = 0.0
        score += 0.4 * _jaccard(new_features.get("top_dst_ips"), c.get("top_dst_ips"))
        score += 0.3 * _jaccard(new_features.get("top_dst_ports"), c.get("top_dst_ports"))
        score += 0.3 * _jaccard(new_features.get("top_domains"), c.get("top_domains"))
        if score > best_score:
            best_score = score
            best = c

    return {
        "matched": bool(best is not None and best_score >= float(threshold)),
        "threshold": float(threshold),
        "best_score": float(best_score),
        "best_match": best or {},
        "new": new_features,
    }


def community_detect_label_propagation(flows: List[dict], *, max_iter: int = 20) -> Dict[str, object]:
    """Simple community detection via label propagation on the traffic graph."""
    # Build undirected weighted adjacency between internal IPs.
    adj: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
    nodes = set()
    for f in flows or []:
        if not isinstance(f, dict):
            continue
        a = str(f.get("src_ip") or "").strip()
        b = str(f.get("dst_ip") or "").strip()
        if not a or not b or a == b:
            continue
        try:
            w = float(f.get("byte_count") or 1.0)
        except Exception:
            w = 1.0
        adj[a][b] += w
        adj[b][a] += w
        nodes.add(a)
        nodes.add(b)

    labels = {n: n for n in nodes}
    node_list = list(nodes)
    random.shuffle(node_list)

    for _ in range(max(1, int(max_iter))):
        changed = 0
        for n in node_list:
            neigh = adj.get(n) or {}
            if not neigh:
                continue
            # Choose the neighbor label with highest summed weight.
            weight_by_label = defaultdict(float)
            for nb, w in neigh.items():
                weight_by_label[labels.get(nb, nb)] += float(w)
            if not weight_by_label:
                continue
            best_label = max(weight_by_label.items(), key=lambda kv: kv[1])[0]
            if labels.get(n) != best_label:
                labels[n] = best_label
                changed += 1
        if changed == 0:
            break

    clusters: Dict[str, List[str]] = defaultdict(list)
    for n, lab in labels.items():
        clusters[str(lab)].append(n)
    # Normalize: stable IDs by sorting member list and hashing first member label.
    out_clusters = []
    for lab, members in clusters.items():
        members = sorted(members)
        out_clusters.append({"cluster_id": lab, "members": members, "size": len(members)})
    out_clusters.sort(key=lambda c: (-c["size"], c["cluster_id"]))
    return {"ok": True, "clusters": out_clusters, "nodes": len(nodes), "edges": sum(len(v) for v in adj.values()) // 2}


def degree_centrality(flows: List[dict]) -> Dict[str, float]:
    adj = defaultdict(set)
    nodes = set()
    for f in flows or []:
        if not isinstance(f, dict):
            continue
        a = str(f.get("src_ip") or "").strip()
        b = str(f.get("dst_ip") or "").strip()
        if not a or not b or a == b:
            continue
        adj[a].add(b)
        adj[b].add(a)
        nodes.add(a)
        nodes.add(b)
    n = max(1, len(nodes))
    out = {}
    for node in nodes:
        out[node] = float(len(adj.get(node) or set())) / float(max(1, n - 1))
    return out


def risk_score_devices(
    *,
    assets: List[dict],
    services: List[dict],
    flows: List[dict],
    alerts: List[dict],
    threat_matches: List[dict],
) -> Dict[str, object]:
    """Compute per-device risk score 0-1 with factor breakdown."""
    # Exposure: count open services and risk ports.
    risk_ports = {21, 23, 445, 3389, 5900, 6379, 9200, 27017}
    svc_by_ip = defaultdict(list)
    for s in services or []:
        if not isinstance(s, dict):
            continue
        ip = str(s.get("ip") or "").strip()
        if ip:
            svc_by_ip[ip].append(s)

    # Anomaly: presence of recent behavior_anomaly alerts in persisted alert set.
    anom_by_ip = defaultdict(float)
    for a in alerts or []:
        if not isinstance(a, dict):
            continue
        if str(a.get("alert_type") or "") != "behavior_anomaly":
            continue
        ip = str(a.get("src_ip") or "").strip()
        sev = str(a.get("severity") or "").lower()
        if not ip:
            continue
        anom_by_ip[ip] = max(anom_by_ip[ip], 1.0 if sev == "high" else 0.7)

    # Threat: any threat matches.
    threat_by_ip = defaultdict(float)
    for m in threat_matches or []:
        if not isinstance(m, dict):
            continue
        ip = str(m.get("src_ip") or "").strip()
        if ip:
            threat_by_ip[ip] = max(threat_by_ip[ip], 1.0)

    cent = degree_centrality(flows or [])

    out = []
    for a in assets or []:
        if not isinstance(a, dict):
            continue
        ip = str(a.get("ip") or "").strip()
        if not ip:
            continue
        svcs = svc_by_ip.get(ip, [])
        ports = [int(s.get("port") or 0) for s in svcs if isinstance(s.get("port"), int) or str(s.get("port") or "").isdigit()]
        ports = [p for p in ports if p > 0]
        risk_open = [p for p in ports if p in risk_ports]

        exposure = min(1.0, float(len(risk_open)) / 3.0) if risk_open else 0.0
        anomaly = float(anom_by_ip.get(ip, 0.0))
        position = float(cent.get(ip, 0.0))
        threat = float(threat_by_ip.get(ip, 0.0))

        # Vulnerability factor is unavailable without CVE mapping; keep at 0.0 for now.
        vulnerability = 0.0

        score = (
            0.30 * vulnerability
            + 0.15 * exposure
            + 0.25 * anomaly
            + 0.10 * position
            + 0.20 * threat
        )
        score = max(0.0, min(score, 1.0))
        rec = "low"
        if score >= 0.8:
            rec = "critical"
        elif score >= 0.6:
            rec = "high"
        elif score >= 0.35:
            rec = "medium"

        out.append(
            {
                "ip": ip,
                "score": score,
                "recommendation": rec,
                "factors": {
                    "vulnerability": vulnerability,
                    "exposure": exposure,
                    "behavior_anomaly": anomaly,
                    "network_position": position,
                    "threat_match": threat,
                },
                "evidence": {"open_ports": sorted(list(set(ports))), "risk_ports": sorted(list(set(risk_open)))},
            }
        )

    out.sort(key=lambda r: -float(r.get("score") or 0.0))
    return {"ok": True, "device_risk": out, "count": len(out)}


def reconstruct_attack_chain(alerts: List[dict], observations: List[dict]) -> Dict[str, object]:
    """Heuristic reconstruction of a likely activity chain from alerts + technique runs."""
    # This is intentionally conservative: it is a narrative helper, not forensic proof.
    events = []
    for o in observations or []:
        if not isinstance(o, dict):
            continue
        cat = str(o.get("category") or "")
        if cat.startswith("mod") or cat.startswith("pipeline") or cat.startswith("threat") or "anomaly" in cat:
            events.append({"ts": o.get("timestamp"), "type": cat, "entity": o.get("entity"), "summary": o.get("summary")})
    for a in alerts or []:
        if not isinstance(a, dict):
            continue
        events.append({"ts": a.get("timestamp"), "type": f"alert:{a.get('alert_type')}", "entity": a.get("src_ip") or a.get("dst_ip"), "summary": a.get("message")})

    events = [e for e in events if e.get("ts")]
    events.sort(key=lambda e: str(e.get("ts")))

    # Pattern match phases.
    phases = []
    if any("mod2" in (e.get("type") or "") for e in events):
        phases.append({"stage": "reconnaissance", "confidence": 0.7, "evidence": "transport scanning present"})
    if any("mod5.banner" in (e.get("type") or "") or "mod5.http" in (e.get("type") or "") for e in events):
        phases.append({"stage": "enumeration", "confidence": 0.6, "evidence": "service fingerprinting present"})
    if any("alert:behavior_anomaly" == (e.get("type") or "") for e in events):
        phases.append({"stage": "anomalous_behavior", "confidence": 0.6, "evidence": "behavior anomaly alert"})
    if any("threat.match" in (e.get("type") or "") or "alert:threat_match" == (e.get("type") or "") for e in events):
        phases.append({"stage": "threat_contact", "confidence": 0.7, "evidence": "threat indicator match"})

    narrative = []
    for p in phases:
        narrative.append(f"{p['stage']}: {p['evidence']} (confidence={p['confidence']})")
    if not narrative:
        narrative.append("No strong multi-stage pattern detected from current alerts/observations.")

    return {"ok": True, "phases": phases, "timeline": events[-200:], "narrative": narrative}

