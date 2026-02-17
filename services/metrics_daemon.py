"""
NetVis NIP metrics daemon.
Continuous time-window metrics, baselining, and anomaly detection.
"""

import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, Optional, Tuple

from models import Connection


class NipMetricsDaemon:
    """Continuous time-window metrics + baselining + anomaly detection."""

    def __init__(self, analyzer, datastore, nip_bus, *, interval_seconds: int = 10, alpha: float = 0.2):
        self.analyzer = analyzer
        self.datastore = datastore
        self.nip_bus = nip_bus
        self.interval_seconds = max(2, int(interval_seconds))
        self.alpha = max(0.01, min(float(alpha), 0.9))
        self.running = False
        self.thread: Optional[object] = None
        import threading
        self._lock = threading.Lock()
        self._last_flow: Dict[str, Tuple[int, int]] = {}
        self._last_dns_len: int = 0
        self._baseline: Dict[str, Dict[str, float]] = {}
        self._last_alert_ts: Dict[Tuple[str, str], float] = {}
        self._last_tick_at: str = ""

    def configure(
        self,
        *,
        interval_seconds: Optional[int] = None,
        alpha: Optional[float] = None,
    ) -> None:
        with self._lock:
            if interval_seconds is not None:
                self.interval_seconds = max(2, int(interval_seconds))
            if alpha is not None:
                self.alpha = max(0.01, min(float(alpha), 0.9))

    def start(self) -> None:
        import threading
        with self._lock:
            if self.running:
                return
            self.running = True
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()

    def stop(self) -> None:
        with self._lock:
            self.running = False
        try:
            if self.thread:
                self.thread.join(timeout=2)
        except Exception:
            pass

    def status(self) -> dict:
        with self._lock:
            return {
                "running": bool(self.running),
                "interval_seconds": int(self.interval_seconds),
                "alpha": float(self.alpha),
                "baseline_hosts": len(self._baseline),
                "last_tick_at": self._last_tick_at,
            }

    def _loop(self) -> None:
        while True:
            with self._lock:
                if not self.running:
                    return
                interval = int(self.interval_seconds)
            try:
                self._tick(window_seconds=interval)
            except Exception:
                pass
            time.sleep(max(0.5, interval))

    def _conn_key(self, c: Connection) -> str:
        return f"{c.src_ip}:{int(c.src_port)}-{c.dst_ip}:{int(c.dst_port)}-{c.protocol}"

    def _tick(self, *, window_seconds: int) -> None:
        now_iso = datetime.now().isoformat()
        now_epoch = time.time()
        capturing = bool(getattr(self.analyzer, "is_capturing", False))
        with self.analyzer.lock:
            conns = list(self.analyzer.connections.values())
            dns_all = list(self.analyzer.dns_queries)
        new_dns = dns_all[self._last_dns_len :] if self._last_dns_len <= len(dns_all) else []
        self._last_dns_len = len(dns_all)
        dns_by_ip = defaultdict(int)
        for q in new_dns:
            try:
                dns_by_ip[str(q.src_ip)] += 1
            except Exception:
                pass
        per_ip: Dict[str, dict] = {}
        per_ip_dst_ips: Dict[str, set] = defaultdict(set)
        per_ip_dst_ports: Dict[str, set] = defaultdict(set)
        for c in conns:
            key = self._conn_key(c)
            prev_bytes, prev_pkts = self._last_flow.get(key, (0, 0))
            cur_bytes = int(getattr(c, "byte_count", 0) or 0)
            cur_pkts = int(getattr(c, "packet_count", 0) or 0)
            delta_b = max(0, cur_bytes - prev_bytes)
            delta_p = max(0, cur_pkts - prev_pkts)
            self._last_flow[key] = (cur_bytes, cur_pkts)
            if delta_b == 0 and delta_p == 0:
                continue
            src = str(getattr(c, "src_ip", "") or "")
            dst = str(getattr(c, "dst_ip", "") or "")
            dport = int(getattr(c, "dst_port", 0) or 0)
            if src:
                m = per_ip.setdefault(
                    src,
                    {"bytes_out": 0, "bytes_in": 0, "packets_out": 0, "packets_in": 0},
                )
                m["bytes_out"] += int(delta_b)
                m["packets_out"] += int(delta_p)
                if dst:
                    per_ip_dst_ips[src].add(dst)
                if dport > 0:
                    per_ip_dst_ports[src].add(dport)
            if dst:
                m = per_ip.setdefault(
                    dst,
                    {"bytes_out": 0, "bytes_in": 0, "packets_out": 0, "packets_in": 0},
                )
                m["bytes_in"] += int(delta_b)
                m["packets_in"] += int(delta_p)
        for ip, m in per_ip.items():
            metric = {
                "timestamp": now_iso,
                "window_seconds": int(window_seconds),
                "ip": ip,
                "bytes_out": int(m.get("bytes_out") or 0),
                "bytes_in": int(m.get("bytes_in") or 0),
                "packets_out": int(m.get("packets_out") or 0),
                "packets_in": int(m.get("packets_in") or 0),
                "unique_dst_ips": len(per_ip_dst_ips.get(ip, set())),
                "unique_dst_ports": len(per_ip_dst_ports.get(ip, set())),
                "dns_queries": int(dns_by_ip.get(ip, 0)),
            }
            try:
                self.datastore.add_nip_metric(metric)
            except Exception:
                pass
            b = self._baseline.get(ip)
            if not b:
                b = {
                    "avg_bytes_out": float(metric["bytes_out"]),
                    "avg_bytes_in": float(metric["bytes_in"]),
                    "avg_unique_dst_ips": float(metric["unique_dst_ips"]),
                    "avg_unique_dst_ports": float(metric["unique_dst_ports"]),
                    "avg_dns_queries": float(metric["dns_queries"]),
                }
            else:
                a = float(self.alpha)
                b["avg_bytes_out"] = a * float(metric["bytes_out"]) + (1 - a) * float(b.get("avg_bytes_out", 0.0))
                b["avg_bytes_in"] = a * float(metric["bytes_in"]) + (1 - a) * float(b.get("avg_bytes_in", 0.0))
                b["avg_unique_dst_ips"] = a * float(metric["unique_dst_ips"]) + (1 - a) * float(b.get("avg_unique_dst_ips", 0.0))
                b["avg_unique_dst_ports"] = a * float(metric["unique_dst_ports"]) + (1 - a) * float(b.get("avg_unique_dst_ports", 0.0))
                b["avg_dns_queries"] = a * float(metric["dns_queries"]) + (1 - a) * float(b.get("avg_dns_queries", 0.0))
            self._baseline[ip] = b
            try:
                self.datastore.upsert_nip_baseline(
                    ip=ip,
                    baseline=b,
                    window_seconds=int(window_seconds),
                    method=f"ewma(alpha={self.alpha})",
                )
            except Exception:
                pass
            if capturing:
                self._detect_anomaly(ip, metric, b, now_epoch)
        self._last_tick_at = now_iso

    def _detect_anomaly(self, ip: str, metric: dict, baseline: dict, now_epoch: float) -> None:
        cooldown_s = 60.0
        cooldown_key = (ip, "behavior_anomaly")
        last = float(self._last_alert_ts.get(cooldown_key, 0.0))
        if (now_epoch - last) < cooldown_s:
            return
        cur_bytes_out = float(metric.get("bytes_out") or 0.0)
        cur_unique_ports = float(metric.get("unique_dst_ports") or 0.0)
        cur_unique_dsts = float(metric.get("unique_dst_ips") or 0.0)
        cur_dns = float(metric.get("dns_queries") or 0.0)
        avg_bytes_out = max(0.0, float(baseline.get("avg_bytes_out") or 0.0))
        avg_unique_ports = max(0.0, float(baseline.get("avg_unique_dst_ports") or 0.0))
        avg_unique_dsts = max(0.0, float(baseline.get("avg_unique_dst_ips") or 0.0))
        avg_dns = max(0.0, float(baseline.get("avg_dns_queries") or 0.0))
        score = 0.0
        reasons = []
        if avg_bytes_out > 0 and cur_bytes_out > max(200_000.0, avg_bytes_out * 6.0):
            score += 0.45
            reasons.append(f"bytes_out_spike cur={int(cur_bytes_out)} avg≈{int(avg_bytes_out)}")
        if cur_unique_ports >= 20 and (avg_unique_ports <= 1.0 or cur_unique_ports > avg_unique_ports * 6.0):
            score += 0.45
            reasons.append(f"unique_dst_ports_spike cur={int(cur_unique_ports)} avg≈{avg_unique_ports:.1f}")
        if cur_unique_dsts >= 10 and (avg_unique_dsts <= 1.0 or cur_unique_dsts > avg_unique_dsts * 6.0):
            score += 0.20
            reasons.append(f"unique_dst_ips_spike cur={int(cur_unique_dsts)} avg≈{avg_unique_dsts:.1f}")
        if cur_dns >= 30 and (avg_dns <= 1.0 or cur_dns > avg_dns * 8.0):
            score += 0.25
            reasons.append(f"dns_spike cur={int(cur_dns)} avg≈{avg_dns:.1f}")
        if score < 0.6:
            return
        severity = "medium" if score < 0.85 else "high"
        msg = f"Behavior anomaly on {ip}: score={score:.2f} ({', '.join(reasons)})"
        try:
            self.analyzer._add_alert(
                "behavior_anomaly",
                severity,
                msg,
                src_ip=ip,
                dst_ip="",
                details={"metric": metric, "baseline": baseline, "reasons": reasons, "score": score},
            )
        except Exception:
            pass
        try:
            self.nip_bus.publish(
                event_type="anomaly.detected",
                source="nip:change_detector",
                entity=ip,
                summary=msg,
                data={"metric": metric, "baseline": baseline, "reasons": reasons, "score": score, "severity": severity},
            )
        except Exception:
            pass
        self._last_alert_ts[cooldown_key] = now_epoch
