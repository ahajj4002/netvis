#!/usr/bin/env python3
"""Module 7 helper: build a detection matrix by correlating scan logs with IDS outputs.

This script is intentionally "reporting oriented" for coursework:
- Reads our module JSON logs under logs/mod*/
- Correlates scan time windows with Suricata EVE JSON (eve.json) and/or Zeek notice.log
- Emits a machine-readable JSON "detection matrix" plus an optional Markdown table

It does not run any scans or IDS; it only parses logs you already collected in your lab.
"""

from __future__ import annotations

import argparse
import json
import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _parse_iso8601(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    s = ts.strip()
    # Common normalizations: Z suffix, +0000 timezone, etc.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Convert "+0000" to "+00:00"
    if re.match(r".*[+-]\\d{4}$", s):
        s = s[:-2] + ":" + s[-2:]
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _dt_to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _safe_read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_suricata_rules_index(path: Path) -> Dict[str, str]:
    """Parse local suricata.rules file to map SID -> message string (best-effort)."""
    if not path or not path.exists():
        return {}
    text = path.read_text(encoding="utf-8", errors="ignore")
    out: Dict[str, str] = {}
    # Multi-line rules: match msg then sid within the same rule body.
    for m in re.finditer(r'msg\\s*:\\s*\"([^\"]+)\"\\s*;.*?sid\\s*:\\s*(\\d+)\\s*;', text, flags=re.S):
        msg = m.group(1).strip()
        sid = m.group(2).strip()
        out[sid] = msg
    return out


def _iter_module_logs(logs_dir: Path) -> Iterable[Tuple[str, Path, Dict[str, Any]]]:
    """Yield (module, path, json) for each log file."""
    if not logs_dir.exists():
        return
    for mod_dir in sorted(p for p in logs_dir.iterdir() if p.is_dir() and p.name.startswith("mod")):
        for path in sorted(mod_dir.glob("*.json")):
            data = _safe_read_json(path)
            if not isinstance(data, dict):
                continue
            yield (mod_dir.name, path, data)


def _load_suricata_eve(path: Path) -> List[Tuple[datetime, Dict[str, Any]]]:
    events: List[Tuple[datetime, Dict[str, Any]]] = []
    if not path:
        return events
    if not path.exists():
        return events

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("event_type") != "alert":
                continue
            dt = _parse_iso8601(str(obj.get("timestamp", "")))
            if not dt:
                continue
            events.append((dt, obj))

    events.sort(key=lambda x: x[0])
    return events


def _load_zeek_notice(path: Path) -> List[Tuple[datetime, Dict[str, Any]]]:
    """Parse Zeek notice.log (TSV with #fields header)."""
    events: List[Tuple[datetime, Dict[str, Any]]] = []
    if not path:
        return events
    if not path.exists():
        return events

    fields: List[str] = []

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                # "#fields\t<field1>\t<field2>..."
                parts = line.split("\t")
                fields = parts[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                # Unknown format
                continue

            parts = line.split("\t")
            if len(parts) != len(fields):
                continue
            rec = {fields[i]: parts[i] for i in range(len(fields))}

            ts_raw = rec.get("ts", "")
            try:
                tsf = float(ts_raw)
            except Exception:
                continue
            dt = datetime.fromtimestamp(tsf, tz=timezone.utc)
            events.append((dt, rec))

    events.sort(key=lambda x: x[0])
    return events


def _events_in_window(events: List[Tuple[datetime, Dict[str, Any]]], start: datetime, end: datetime) -> List[Tuple[datetime, Dict[str, Any]]]:
    if not events:
        return []
    dts = [e[0] for e in events]
    lo = bisect_left(dts, start)
    hi = bisect_right(dts, end)
    return events[lo:hi]


@dataclass
class ScanWindow:
    session_id: str
    module: str
    technique: str
    started_at: datetime
    finished_at: datetime
    meta: Dict[str, Any]


def _extract_windows_from_log(module: str, data: Dict[str, Any]) -> List[ScanWindow]:
    """Return one or more scan windows from a module log.

    For Module 4, we emit one window per profile/variant because it runs multiple experiments.
    """
    session_id = str(data.get("session_id", ""))
    started_at = _parse_iso8601(str(data.get("started_at", "")))
    finished_at = _parse_iso8601(str(data.get("finished_at", "")))
    result = data.get("result") or {}

    if not session_id or not isinstance(result, dict):
        return []

    # Module 4 has nested profiles with their own started_at/finished_at.
    if module == "mod4":
        windows: List[ScanWindow] = []
        tech = str(result.get("technique", "mod4_experiment"))

        def add_window(suffix: str, node: Dict[str, Any], extra_meta: Dict[str, Any]):
            s = _parse_iso8601(str(node.get("started_at", ""))) or started_at
            e = _parse_iso8601(str(node.get("finished_at", ""))) or finished_at
            if not s or not e:
                return
            windows.append(
                ScanWindow(
                    session_id=f"{session_id}:{suffix}",
                    module=module,
                    technique=f"{tech}:{suffix}",
                    started_at=s,
                    finished_at=e,
                    meta={**extra_meta},
                )
            )

        if tech == "fixed_rate_scan_profiles":
            profiles = result.get("profiles") or {}
            if isinstance(profiles, dict):
                for name, node in profiles.items():
                    if isinstance(node, dict):
                        add_window(name, node, {"profile": name, "delay_seconds_config": node.get("delay_seconds_config")})
        elif tech == "randomized_jitter":
            for name in ("fixed", "uniform", "exponential"):
                node = result.get(name)
                if isinstance(node, dict):
                    add_window(name, node, {"variant": name, "base_delay_seconds": result.get("base_delay_seconds")})
        elif tech == "target_order_randomization":
            for name in ("sequential", "shuffled"):
                node = result.get(name)
                if isinstance(node, dict):
                    add_window(name, node, {"variant": name, "delay_seconds": result.get("delay_seconds")})
        else:
            # Fallback: one window
            if started_at and finished_at:
                windows.append(
                    ScanWindow(
                        session_id=session_id,
                        module=module,
                        technique=tech,
                        started_at=started_at,
                        finished_at=finished_at,
                        meta={},
                    )
                )
        return windows

    # All other modules: single window if timestamps exist.
    technique = str(result.get("technique", module))
    if not started_at or not finished_at:
        return []

    meta: Dict[str, Any] = {}
    for k in ("scanner_local_ip", "targets", "host", "ports", "network", "interface"):
        if k in data:
            meta[k] = data.get(k)
        if isinstance(result, dict) and k in result:
            meta[k] = result.get(k)
    return [
        ScanWindow(
            session_id=session_id,
            module=module,
            technique=technique,
            started_at=started_at,
            finished_at=finished_at,
            meta=meta,
        )
    ]


def build_detection_matrix(
    *,
    logs_dir: Path,
    suricata_eve: Optional[Path],
    zeek_notice: Optional[Path],
    out_json: Optional[Path],
    out_md: Optional[Path],
) -> Dict[str, Any]:
    suri_events = _load_suricata_eve(suricata_eve) if suricata_eve else []
    zeek_events = _load_zeek_notice(zeek_notice) if zeek_notice else []
    sid_to_rule_msg = _load_suricata_rules_index(PROJECT_ROOT / "mod7" / "suricata.rules")
    sid_to_sig: Dict[str, str] = {}

    windows: List[ScanWindow] = []
    for module, _path, data in _iter_module_logs(logs_dir):
        windows.extend(_extract_windows_from_log(module, data))
    windows.sort(key=lambda w: (w.started_at, w.session_id))

    rows = []
    for w in windows:
        suri_hits = _events_in_window(suri_events, w.started_at, w.finished_at)
        zeek_hits = _events_in_window(zeek_events, w.started_at, w.finished_at)

        by_sid: Dict[str, int] = {}
        for _dt, ev in suri_hits:
            alert = ev.get("alert") or {}
            sid = str(alert.get("signature_id", "unknown"))
            sig = str(alert.get("signature", "")).strip()
            if sid not in sid_to_sig and sig:
                sid_to_sig[sid] = sig
            by_sid[sid] = by_sid.get(sid, 0) + 1

        by_note: Dict[str, int] = {}
        for _dt, rec in zeek_hits:
            note = str(rec.get("note", "unknown"))
            by_note[note] = by_note.get(note, 0) + 1

        detected = (len(suri_hits) > 0) or (len(zeek_hits) > 0)
        rows.append(
            {
                "session_id": w.session_id,
                "module": w.module,
                "technique": w.technique,
                "started_at": _dt_to_iso(w.started_at),
                "finished_at": _dt_to_iso(w.finished_at),
                "meta": w.meta,
                "detection": {
                    "detected": detected,
                    "suricata": {
                        "alerts_total": len(suri_hits),
                        "by_signature_id": by_sid,
                        "sample": [
                            {
                                "ts": _dt_to_iso(dt),
                                "sid": (ev.get("alert") or {}).get("signature_id"),
                                "sig": (ev.get("alert") or {}).get("signature"),
                                "src_ip": ev.get("src_ip"),
                                "dest_ip": ev.get("dest_ip"),
                                "proto": ev.get("proto"),
                            }
                            for dt, ev in suri_hits[:10]
                        ],
                    },
                    "zeek": {
                        "notices_total": len(zeek_hits),
                        "by_note": by_note,
                        "sample": [
                            {
                                "ts": _dt_to_iso(dt),
                                "note": rec.get("note"),
                                "msg": rec.get("msg"),
                                "src": rec.get("src"),
                                "dst": rec.get("dst"),
                                "id.orig_h": rec.get("id.orig_h"),
                                "id.resp_h": rec.get("id.resp_h"),
                            }
                            for dt, rec in zeek_hits[:10]
                        ],
                    },
                },
            }
        )

    # Summary by technique
    by_tech: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        tech = r["technique"]
        ent = by_tech.setdefault(tech, {"sessions": 0, "detected_sessions": 0, "suricata_alerts": 0, "zeek_notices": 0})
        ent["sessions"] += 1
        if r["detection"]["detected"]:
            ent["detected_sessions"] += 1
        ent["suricata_alerts"] += int(r["detection"]["suricata"]["alerts_total"])
        ent["zeek_notices"] += int(r["detection"]["zeek"]["notices_total"])

    summary = {
        "by_technique": {
            k: {
                **v,
                "detection_rate": (v["detected_sessions"] / max(1, v["sessions"])),
            }
            for k, v in sorted(by_tech.items(), key=lambda x: (-x[1]["detection_rate"], x[0]))
        }
    }

    # Per-rule detection rate table (Suricata SIDs and Zeek notices) across techniques/windows.
    tech_total = {}
    tech_sid_windows: Dict[str, Dict[str, int]] = {}
    tech_sid_alerts: Dict[str, Dict[str, int]] = {}
    tech_note_windows: Dict[str, Dict[str, int]] = {}
    tech_note_counts: Dict[str, Dict[str, int]] = {}

    for r in rows:
        tech = r["technique"]
        tech_total[tech] = tech_total.get(tech, 0) + 1

        by_sid = (r.get("detection") or {}).get("suricata", {}).get("by_signature_id", {}) or {}
        if tech not in tech_sid_windows:
            tech_sid_windows[tech] = {}
            tech_sid_alerts[tech] = {}
        for sid, cnt in by_sid.items():
            if int(cnt) <= 0:
                continue
            tech_sid_windows[tech][sid] = tech_sid_windows[tech].get(sid, 0) + 1
            tech_sid_alerts[tech][sid] = tech_sid_alerts[tech].get(sid, 0) + int(cnt)

        by_note = (r.get("detection") or {}).get("zeek", {}).get("by_note", {}) or {}
        if tech not in tech_note_windows:
            tech_note_windows[tech] = {}
            tech_note_counts[tech] = {}
        for note, cnt in by_note.items():
            if int(cnt) <= 0:
                continue
            tech_note_windows[tech][note] = tech_note_windows[tech].get(note, 0) + 1
            tech_note_counts[tech][note] = tech_note_counts[tech].get(note, 0) + int(cnt)

    all_sids = sorted({sid for r in rows for sid in ((r.get("detection") or {}).get("suricata", {}).get("by_signature_id", {}) or {}).keys()} | set(sid_to_rule_msg.keys()))
    all_notes = sorted({note for r in rows for note in ((r.get("detection") or {}).get("zeek", {}).get("by_note", {}) or {}).keys()})

    suricata_rule_rates = []
    for sid in all_sids:
        by_technique = {}
        for tech, total in sorted(tech_total.items(), key=lambda x: x[0]):
            windows_with = int(tech_sid_windows.get(tech, {}).get(sid, 0))
            alerts_total = int(tech_sid_alerts.get(tech, {}).get(sid, 0))
            by_technique[tech] = {
                "windows_total": int(total),
                "windows_with_alert": windows_with,
                "detection_rate": (windows_with / max(1, int(total))),
                "alerts_total": alerts_total,
            }
        suricata_rule_rates.append(
            {
                "sid": sid,
                "msg": sid_to_rule_msg.get(sid, ""),
                "signature": sid_to_sig.get(sid, ""),
                "by_technique": by_technique,
            }
        )

    zeek_notice_rates = []
    for note in all_notes:
        by_technique = {}
        for tech, total in sorted(tech_total.items(), key=lambda x: x[0]):
            windows_with = int(tech_note_windows.get(tech, {}).get(note, 0))
            notices_total = int(tech_note_counts.get(tech, {}).get(note, 0))
            by_technique[tech] = {
                "windows_total": int(total),
                "windows_with_notice": windows_with,
                "detection_rate": (windows_with / max(1, int(total))),
                "notices_total": notices_total,
            }
        zeek_notice_rates.append({"note": note, "by_technique": by_technique})

    matrix = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "logs_dir": str(logs_dir),
            "suricata_eve": str(suricata_eve) if suricata_eve else None,
            "zeek_notice": str(zeek_notice) if zeek_notice else None,
            "rows": len(rows),
        },
        "rows": rows,
        "summary": summary,
        "per_rule_detection_rates": {
            "suricata": suricata_rule_rates,
            "zeek": zeek_notice_rates,
            "note": "Detection rate here is per scan-window (session/time-profile) where the rule produced >=1 alert/notice.",
        },
    }

    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    if out_md:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        lines.append("# Detection Matrix (Auto-Correlated)")
        lines.append("")
        lines.append("| Session | Technique | Detected | Suricata alerts | Zeek notices | Window |")
        lines.append("|---|---|---:|---:|---:|---|")
        for r in rows:
            det = "yes" if r["detection"]["detected"] else "no"
            lines.append(
                f"| `{r['session_id']}` | `{r['technique']}` | {det} | {r['detection']['suricata']['alerts_total']} | {r['detection']['zeek']['notices_total']} | {r['started_at']} .. {r['finished_at']} |"
            )
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append("| Technique | Sessions | Detected sessions | Detection rate | Suricata alerts | Zeek notices |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for tech, v in matrix["summary"]["by_technique"].items():
            lines.append(
                f"| `{tech}` | {v['sessions']} | {v['detected_sessions']} | {v['detection_rate']:.2f} | {v['suricata_alerts']} | {v['zeek_notices']} |"
            )

        lines.append("")
        lines.append("## Suricata Per-Rule Detection Rates (By Technique)")
        lines.append("")
        lines.append("| SID | Msg | Technique | Windows | Windows w/ Alert | Detection rate | Alerts |")
        lines.append("|---:|---|---|---:|---:|---:|---:|")
        for rule in matrix["per_rule_detection_rates"]["suricata"]:
            sid = rule.get("sid", "")
            msg = rule.get("msg", "") or rule.get("signature", "")
            for tech, ent in (rule.get("by_technique") or {}).items():
                lines.append(
                    f"| {sid} | `{msg}` | `{tech}` | {ent['windows_total']} | {ent['windows_with_alert']} | {ent['detection_rate']:.2f} | {ent['alerts_total']} |"
                )

        if matrix["per_rule_detection_rates"]["zeek"]:
            lines.append("")
            lines.append("## Zeek Notice Detection Rates (By Technique)")
            lines.append("")
            lines.append("| Notice | Technique | Windows | Windows w/ Notice | Detection rate | Notices |")
            lines.append("|---|---|---:|---:|---:|---:|")
            for rule in matrix["per_rule_detection_rates"]["zeek"]:
                note = rule.get("note", "")
                for tech, ent in (rule.get("by_technique") or {}).items():
                    lines.append(
                        f"| `{note}` | `{tech}` | {ent['windows_total']} | {ent['windows_with_notice']} | {ent['detection_rate']:.2f} | {ent['notices_total']} |"
                    )
        out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return matrix


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build detection matrix by correlating scan logs with Suricata/Zeek output.")
    p.add_argument("--logs-dir", default=str(PROJECT_ROOT / "logs"), help="Path to logs/ directory")
    p.add_argument("--suricata-eve", default="", help="Path to Suricata eve.json (optional)")
    p.add_argument("--zeek-notice", default="", help="Path to Zeek notice.log (optional)")
    p.add_argument("--out-json", default=str(PROJECT_ROOT / "report" / "detection_matrix.json"), help="Output JSON path")
    p.add_argument("--out-md", default=str(PROJECT_ROOT / "report" / "detection_matrix.md"), help="Output Markdown path")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logs_dir = Path(args.logs_dir)
    suri = Path(args.suricata_eve) if args.suricata_eve else None
    zeek = Path(args.zeek_notice) if args.zeek_notice else None
    out_json = Path(args.out_json) if args.out_json else None
    out_md = Path(args.out_md) if args.out_md else None

    matrix = build_detection_matrix(
        logs_dir=logs_dir,
        suricata_eve=suri if suri and suri.exists() else None,
        zeek_notice=zeek if zeek and zeek.exists() else None,
        out_json=out_json,
        out_md=out_md,
    )
    print(f"[mod7] detection matrix: rows={matrix['inputs']['rows']} out={out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
