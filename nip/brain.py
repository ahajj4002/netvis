#!/usr/bin/env python3
"""NIP Phase 4 — The Brain (Orchestrator).

Implements:
  4.1  SituationAssessor   — "what do we know and not know?"
  4.2  TechniqueSelector   — "given the situation, what should we run?"
  4.5  StrategyPlanner     — "what high-level objectives should we pursue?"

All three are pure-logic classes that accept data dictionaries and return plans.
Execution is delegated to the server-side job runners.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
import uuid


# ---------------------------------------------------------------------------
# 4.1 — Situation Assessor
# ---------------------------------------------------------------------------

@dataclass
class DeviceKnowledge:
    ip: str
    has_mac: bool = False
    has_os: bool = False
    has_services: bool = False
    has_baseline: bool = False
    last_seen: str = ""
    risk_assessed: bool = False
    gaps: List[str] = field(default_factory=list)


@dataclass
class NetworkSituation:
    """Snapshot of what the Brain currently knows (and doesn't know)."""
    generated_at: str = ""
    total_devices: int = 0
    devices: List[DeviceKnowledge] = field(default_factory=list)
    subnet_coverage: Dict[str, bool] = field(default_factory=dict)
    stale_devices: List[str] = field(default_factory=list)
    unresolved_alerts: int = 0
    overall_coverage_pct: float = 0.0
    knowledge_gaps: Dict[str, int] = field(default_factory=dict)


class SituationAssessor:
    """Maintains a knowledge-gap model of the network (Phase 4.1)."""

    def assess(
        self,
        *,
        assets: List[dict],
        services: List[dict],
        baselines: List[dict],
        alerts: List[dict],
        stale_threshold_hours: float = 6.0,
    ) -> NetworkSituation:
        now = datetime.now()
        svc_ips: Set[str] = set()
        for s in (services or []):
            ip = str(s.get("ip") or "").strip()
            if ip:
                svc_ips.add(ip)

        baseline_ips: Set[str] = set()
        for b in (baselines or []):
            ip = str(b.get("ip") or "").strip()
            if ip:
                baseline_ips.add(ip)

        unresolved = 0
        for a in (alerts or []):
            if not isinstance(a, dict):
                continue
            resolved = a.get("resolved")
            if not resolved:
                unresolved += 1

        devices: List[DeviceKnowledge] = []
        gap_counter: Dict[str, int] = {
            "has_mac": 0, "has_os": 0, "has_services": 0,
            "has_baseline": 0, "risk_assessed": 0,
        }
        stale_list: List[str] = []

        for asset in (assets or []):
            ip = str(asset.get("ip") or "").strip()
            if not ip:
                continue
            mac = str(asset.get("mac") or "").strip()
            os_fp = str(asset.get("os") or "").strip()
            meta = asset.get("metadata") or asset.get("metadata_json") or {}
            if isinstance(meta, str):
                try:
                    import json
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            risk_score = meta.get("risk_score") if isinstance(meta, dict) else None

            dk = DeviceKnowledge(
                ip=ip,
                has_mac=bool(mac and mac != "unknown"),
                has_os=bool(os_fp),
                has_services=(ip in svc_ips),
                has_baseline=(ip in baseline_ips),
                last_seen=str(asset.get("last_seen") or ""),
                risk_assessed=(risk_score is not None),
            )
            gaps = []
            for fld in ("has_mac", "has_os", "has_services", "has_baseline", "risk_assessed"):
                if not getattr(dk, fld, False):
                    gaps.append(fld)
                    gap_counter[fld] = gap_counter.get(fld, 0) + 1
            dk.gaps = gaps

            # Stale check.
            try:
                ls = datetime.fromisoformat(dk.last_seen)
                if (now - ls) > timedelta(hours=stale_threshold_hours):
                    stale_list.append(ip)
            except Exception:
                pass

            devices.append(dk)

        total = max(1, len(devices))
        fields_possible = 5 * total
        fields_known = fields_possible - sum(gap_counter.values())
        coverage = fields_known / fields_possible if fields_possible > 0 else 0.0

        return NetworkSituation(
            generated_at=now.isoformat(),
            total_devices=len(devices),
            devices=devices,
            stale_devices=stale_list,
            unresolved_alerts=unresolved,
            overall_coverage_pct=round(coverage * 100, 1),
            knowledge_gaps=gap_counter,
        )


# ---------------------------------------------------------------------------
# 4.2 — Technique Selector
# ---------------------------------------------------------------------------

@dataclass
class PlannedTechnique:
    technique_id: str
    objective: str
    priority: float = 0.5
    target: str = ""
    reason: str = ""


class TechniqueSelector:
    """Picks the best technique(s) for a given objective and situation (Phase 4.2)."""

    def __init__(self, registry: Dict[str, Any]):
        self._registry = registry or {}

    def _available(self, tid: str) -> bool:
        t = self._registry.get(tid)
        if not t:
            return False
        status = getattr(t, "status", None) or (t.get("status") if isinstance(t, dict) else "available")
        return status == "available"

    def _add(self, plan, tid, obj, pri, target, reason):
        if self._available(tid):
            plan.append(PlannedTechnique(tid, obj, pri, target, reason))

    def select(
        self,
        *,
        objective: str,
        device: Optional[DeviceKnowledge] = None,
        stealth: float = 0.5,
    ) -> List[PlannedTechnique]:
        plan: List[PlannedTechnique] = []
        target = device.ip if device else ""
        a = lambda tid, pri, reason: self._add(plan, tid, objective, pri, target, reason)

        # ---- DISCOVER: find who's on the network ----
        if objective == "discover":
            if stealth < 0.8:
                a("mod1.active_arp", 0.95, "ARP sweep — map all IPs + MACs")
            else:
                a("mod1.passive_arp", 0.7, "passive ARP (slow)")
            a("discovery.nbns", 0.8, "NetBIOS names (who is who)")
            a("discovery.ssdp", 0.7, "UPnP/SSDP device discovery")
            a("discovery.mdns_passive", 0.65, "mDNS/Bonjour names")
            a("discovery.mdns", 0.6, "active mDNS query")
            a("discovery.llmnr", 0.55, "LLMNR hostnames")
            a("discovery.wsd", 0.5, "WS-Discovery (printers/etc)")
            a("icmp.echo_sweep", 0.45, "ICMP ping sweep")
            a("ipv6.neighbor_discovery", 0.4, "IPv6 neighbor discovery")

        # ---- ENUMERATE: deep-dive per device ----
        elif objective == "enumerate" and device:
            gaps = device.gaps if device else []
            # Services & OS
            if "has_services" in gaps or "has_os" in gaps:
                a("mod5.banner", 0.9, "banner grab (service IDs + versions)")
                a("mod5.http_headers", 0.75, "HTTP server headers")
                a("mod5.tls", 0.7, "TLS cert inspection (CN/org/issuer)")
                a("ssh.host_key_fp", 0.65, "SSH host key fingerprint")
            if "has_services" in gaps:
                if stealth < 0.5:
                    a("mod2.tcp_syn", 0.6, "SYN scan for open ports")
                elif stealth < 0.8:
                    a("mod2.tcp_fin", 0.55, "FIN scan (stealthier)")
                a("snmp.walk", 0.5, "SNMP walk (device info)")
                a("smb.enum_shares", 0.45, "SMB share enumeration")
            if "has_os" in gaps:
                a("mod5.tcp_fingerprint", 0.65, "TCP stack OS fingerprint")
                a("icmp.os_fingerprint", 0.5, "ICMP TTL/DF OS hints")
            if "has_baseline" in gaps:
                a("analysis.baseline_compute", 0.4, "compute behavioral baseline")
            if "risk_assessed" in gaps:
                a("analysis.risk_score", 0.4, "compute risk score")

        # ---- MONITOR: passive traffic capture & observation ----
        elif objective == "monitor":
            a("mod6.promisc", 0.9, "capture live traffic (30s)")
            a("tls.ja3", 0.88, "TLS SNI domain capture — reveals real domains (instagram, netflix, etc.)")
            a("mod5.passive_dns", 0.85, "sniff DNS queries (what's being resolved)")
            a("dns.doh_detect", 0.82, "detect encrypted DNS (DoH/DoT) usage")
            a("dhcp.passive_monitor", 0.8, "DHCP snooping (hostnames + OS hints)")
            a("mod7.arpwatch", 0.7, "ARP change monitoring")
            a("ipv6.passive_ndp", 0.5, "IPv6 NDP passive monitoring")

        # ---- ANALYZE: correlate & infer from collected data ----
        elif objective == "analyze":
            a("analysis.community_detect", 0.9, "traffic community clustering")
            a("analysis.identity_resolve", 0.8, "device identity resolution")
            a("analysis.graph_diff", 0.7, "graph diff (what changed?)")
            a("analysis.anomaly_score", 0.6, "anomaly scoring")
            a("dns.tunnel_detect", 0.55, "DNS tunneling detection")
            a("threat.feed_sync", 0.5, "sync threat feeds + retroactive match")

        # ---- INVESTIGATE: follow up on alerts ----
        elif objective == "investigate":
            a("analysis.temporal_correlation", 0.9, "temporal correlation around events")
            a("analysis.attack_chain", 0.85, "attack chain reconstruction")
            a("threat.ip_reputation", 0.8, "IP reputation check")
            a("threat.domain_reputation", 0.7, "domain reputation check")
            a("threat.cve_lookup", 0.65, "CVE vulnerability lookup")

        # ---- REFRESH: re-check stale data ----
        elif objective == "refresh":
            if stealth < 0.8:
                a("mod1.active_arp", 0.6, "refresh ARP table")
            else:
                a("mod1.passive_arp", 0.5, "passive ARP refresh")

        # ---- RISK_ASSESS ----
        elif objective == "risk_assess":
            a("analysis.risk_score", 0.8, "compute risk scores")
            a("threat.cve_lookup", 0.6, "CVE lookup for found services")
            a("threat.ip_reputation", 0.5, "check IPs against threat feeds")

        # Filter out unavailable techniques.
        plan = [p for p in plan if self._available(p.technique_id)]
        return plan


# ---------------------------------------------------------------------------
# 4.5 — Strategy Planner
# ---------------------------------------------------------------------------

@dataclass
class Objective:
    type: str           # discover | refresh | investigate | enumerate | monitor | analyze | risk_assess
    priority: float
    targets: List[str] = field(default_factory=list)
    stealth: float = 0.5
    context: Dict[str, Any] = field(default_factory=dict)


class StrategyPlanner:
    """Sets high-level objectives based on network state (Phase 4.5).

    The planner works in progressive stages:
      1. DISCOVER  — find who's on the network (ARP, NBNS, SSDP, mDNS, ICMP)
      2. ENUMERATE — get details per device (banners, ports, OS, TLS, SSH, SMB, SNMP)
      3. MONITOR   — capture live traffic to see what's happening (pcap, DNS, DHCP, ARP watch)
      4. ANALYZE   — correlate data (communities, identities, anomalies, graph diff)
      5. INVESTIGATE — follow up on alerts (attack chains, threat intel, CVE)
      6. RISK_ASSESS — score risk for unscored devices
      7. REFRESH   — re-check stale devices
    """

    def plan(
        self,
        situation: NetworkSituation,
        *,
        required_stealth: float = 0.5,
        mode: str = "continuous",
    ) -> List[Objective]:
        objectives: List[Objective] = []
        n_devices = situation.total_devices

        # --- INVESTIGATION — unresolved alerts are always top priority ---
        if situation.unresolved_alerts > 0:
            objectives.append(Objective(
                type="investigate",
                priority=0.95,
                targets=[],
                stealth=required_stealth,
                context={"unresolved_alerts": situation.unresolved_alerts},
            ))

        # --- DISCOVERY — if coverage is below threshold ---
        if situation.overall_coverage_pct < 70.0:
            objectives.append(Objective(
                type="discover",
                priority=0.9,
                targets=[],
                stealth=required_stealth,
                context={"coverage_pct": situation.overall_coverage_pct},
            ))

        # --- ENUMERATE — devices with knowledge gaps ---
        shallow = [d.ip for d in situation.devices if len(d.gaps) >= 1]
        if shallow:
            objectives.append(Objective(
                type="enumerate",
                priority=0.85,
                targets=shallow[:10],
                stealth=required_stealth,
                context={"reason": "knowledge_gaps", "gap_count": len(shallow)},
            ))

        # --- MONITOR — always capture traffic to learn what's happening ---
        # This is critical — without capture, we never see actual traffic patterns
        if n_devices >= 1:
            objectives.append(Objective(
                type="monitor",
                priority=0.75,
                targets=[],
                stealth=required_stealth,
                context={"reason": "traffic_capture", "devices": n_devices},
            ))

        # --- ANALYZE — once we have some data, correlate and infer ---
        if n_devices >= 3:
            objectives.append(Objective(
                type="analyze",
                priority=0.65,
                targets=[],
                stealth=required_stealth,
                context={"reason": "data_correlation", "devices": n_devices},
            ))

        # --- RISK ASSESSMENT — unscored devices ---
        unscored = [d.ip for d in situation.devices if not d.risk_assessed]
        if unscored:
            objectives.append(Objective(
                type="risk_assess",
                priority=0.55,
                targets=unscored[:20],
                context={"reason": "unscored_devices", "count": len(unscored)},
            ))

        # --- REFRESH — stale data ---
        if situation.stale_devices:
            objectives.append(Objective(
                type="refresh",
                priority=0.4,
                targets=situation.stale_devices[:20],
                stealth=max(required_stealth, 0.5),
                context={"reason": "stale_data"},
            ))

        objectives.sort(key=lambda o: -o.priority)
        return objectives
