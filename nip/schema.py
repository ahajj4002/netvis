#!/usr/bin/env python3
"""NIP Phase 0.2 — Unified Result Schema.

Every technique returns a `TechniqueResult` containing standardised `Finding`
objects so the Brain can consume output without custom parsers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str = "res") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class Finding:
    """One discrete piece of intelligence produced by a technique."""
    category: str          # e.g. "device", "service", "vulnerability", "anomaly"
    severity: str = "info" # info | low | medium | high | critical
    confidence: float = 1.0
    entity: str = ""       # IP, MAC, domain, service-id …
    summary: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TechniqueResult:
    """Canonical envelope for every technique execution result."""
    technique_id: str
    timestamp: str = field(default_factory=_utc_now_iso)
    targets: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    confidence: float = 1.0
    detection_risk: float = 0.0
    next_suggestions: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    result_id: str = field(default_factory=lambda: _new_id("res"))

    # ── helpers ──

    def add_finding(self, category: str, *, severity: str = "info",
                    confidence: float = 1.0, entity: str = "",
                    summary: str = "", detail: Optional[Dict[str, Any]] = None) -> Finding:
        f = Finding(
            category=category,
            severity=severity,
            confidence=confidence,
            entity=entity,
            summary=summary,
            detail=dict(detail or {}),
        )
        self.findings.append(f)
        return f

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_legacy_log(cls, technique_id: str, log: dict) -> "TechniqueResult":
        """Wrap a pre-existing JSON log into a TechniqueResult envelope."""
        result_data = log.get("result") or {}
        nip_meta = log.get("nip") or {}
        started = log.get("started_at", "")
        finished = log.get("finished_at", "")
        dur = 0.0
        try:
            s = datetime.fromisoformat(str(started))
            f = datetime.fromisoformat(str(finished))
            dur = (f - s).total_seconds()
        except Exception:
            pass

        tr = cls(
            technique_id=technique_id,
            timestamp=finished or started or _utc_now_iso(),
            duration_seconds=dur,
            raw_data=result_data,
        )
        # Auto-generate findings from common result shapes.
        if isinstance(result_data, dict):
            for key in ("devices", "hosts", "discovered"):
                items = result_data.get(key)
                if isinstance(items, list):
                    for item in items:
                        entity = ""
                        if isinstance(item, dict):
                            entity = item.get("ip") or item.get("mac") or ""
                        elif isinstance(item, str):
                            entity = item
                        if entity:
                            tr.add_finding("device", entity=entity, summary=f"Discovered {entity}")
            for key in ("open_ports", "services"):
                items = result_data.get(key)
                if isinstance(items, list):
                    for item in items:
                        entity = ""
                        if isinstance(item, dict):
                            entity = f"{item.get('ip', '')}:{item.get('port', '')}"
                        elif isinstance(item, (int, str)):
                            entity = str(item)
                        if entity:
                            tr.add_finding("service", entity=entity, summary=f"Service {entity}")
            for key in ("alerts", "anomalies"):
                items = result_data.get(key)
                if isinstance(items, list):
                    for item in items:
                        msg = item.get("message", "") if isinstance(item, dict) else str(item)
                        tr.add_finding("anomaly", severity="medium", entity="", summary=msg)
        return tr
