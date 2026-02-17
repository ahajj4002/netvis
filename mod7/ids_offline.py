#!/usr/bin/env python3
"""Module 7 helper: run Suricata/Zeek offline against a PCAP (coursework/lab use).

This is intentionally best-effort:
- If Suricata/Zeek are not installed, we return a structured error instead of crashing.
- Outputs are written under report/ so the UI can point detection-matrix at them.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _tail(text: str, limit: int = 4000) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[-limit:]


def suricata_offline(
    *,
    pcap_path: str,
    rules_path: Optional[str] = None,
    config_path: Optional[str] = None,
    out_dir: Optional[str] = None,
    timeout_seconds: int = 120,
) -> Dict[str, Any]:
    """Run Suricata in offline mode against a PCAP and produce eve.json."""
    pcap = Path(str(pcap_path)).expanduser().resolve()
    if not pcap.exists():
        return {"technique": "suricata_offline", "error": "pcap_not_found", "pcap_path": str(pcap)}

    suri = shutil.which("suricata")
    if not suri:
        return {"technique": "suricata_offline", "error": "suricata_not_installed", "pcap_path": str(pcap)}

    rules = Path(rules_path).expanduser().resolve() if rules_path else (PROJECT_ROOT / "mod7" / "suricata.rules")
    if not rules.exists():
        return {"technique": "suricata_offline", "error": "rules_not_found", "rules_path": str(rules), "pcap_path": str(pcap)}

    out_base = Path(out_dir).expanduser().resolve() if out_dir else (PROJECT_ROOT / "report" / "suricata")
    out_base.mkdir(parents=True, exist_ok=True)
    run_dir = out_base / f"run_{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)

    cmd = [suri]
    if config_path:
        cfg = Path(config_path).expanduser().resolve()
        cmd += ["-c", str(cfg)]
    cmd += ["-r", str(pcap), "-S", str(rules), "-l", str(run_dir), "-k", "none"]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1, int(timeout_seconds)))
    except subprocess.TimeoutExpired:
        return {"technique": "suricata_offline", "error": "timeout", "command": cmd, "pcap_path": str(pcap), "run_dir": str(run_dir)}
    except Exception as exc:
        return {"technique": "suricata_offline", "error": f"exec_failed_{type(exc).__name__}", "command": cmd, "pcap_path": str(pcap)}

    eve = run_dir / "eve.json"
    alerts_total = 0
    by_sid: Dict[str, int] = {}
    if eve.exists():
        try:
            with eve.open("r", encoding="utf-8", errors="ignore") as f:
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
                    alerts_total += 1
                    sid = str((obj.get("alert") or {}).get("signature_id", "unknown"))
                    by_sid[sid] = by_sid.get(sid, 0) + 1
        except Exception:
            pass

        # Keep a stable path for the UI defaults.
        latest = out_base / "eve.json"
        try:
            latest.write_text(eve.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
        except Exception:
            pass

    return {
        "technique": "suricata_offline",
        "pcap_path": str(pcap),
        "rules_path": str(rules),
        "config_path": str(config_path) if config_path else None,
        "run_dir": str(run_dir),
        "eve_json": str(eve) if eve.exists() else "",
        "eve_json_latest": str((out_base / "eve.json")) if (out_base / "eve.json").exists() else "",
        "alerts_total": alerts_total,
        "alerts_by_sid": by_sid,
        "returncode": int(res.returncode),
        "stdout_tail": _tail(res.stdout or ""),
        "stderr_tail": _tail(res.stderr or ""),
        "note": "If you already run Suricata as a service, you can point detection-matrix at /var/log/suricata/eve.json instead.",
    }


def zeek_offline(
    *,
    pcap_path: str,
    script_path: Optional[str] = None,
    out_dir: Optional[str] = None,
    timeout_seconds: int = 120,
) -> Dict[str, Any]:
    """Run Zeek against a PCAP and produce notice.log and related logs."""
    pcap = Path(str(pcap_path)).expanduser().resolve()
    if not pcap.exists():
        return {"technique": "zeek_offline", "error": "pcap_not_found", "pcap_path": str(pcap)}

    zeek_bin = shutil.which("zeek")
    if not zeek_bin:
        return {"technique": "zeek_offline", "error": "zeek_not_installed", "pcap_path": str(pcap)}

    script = Path(script_path).expanduser().resolve() if script_path else (PROJECT_ROOT / "mod7" / "zeek" / "scan_detect.zeek")
    if not script.exists():
        return {"technique": "zeek_offline", "error": "script_not_found", "script_path": str(script), "pcap_path": str(pcap)}

    out_base = Path(out_dir).expanduser().resolve() if out_dir else (PROJECT_ROOT / "report" / "zeek")
    out_base.mkdir(parents=True, exist_ok=True)
    run_dir = out_base / f"run_{int(time.time())}"
    run_dir.mkdir(parents=True, exist_ok=True)

    cmd = [zeek_bin, "-C", "-r", str(pcap), str(script)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1, int(timeout_seconds)), cwd=str(run_dir))
    except subprocess.TimeoutExpired:
        return {"technique": "zeek_offline", "error": "timeout", "command": cmd, "pcap_path": str(pcap), "run_dir": str(run_dir)}
    except Exception as exc:
        return {"technique": "zeek_offline", "error": f"exec_failed_{type(exc).__name__}", "command": cmd, "pcap_path": str(pcap)}

    notice = run_dir / "notice.log"
    notices_total = 0
    if notice.exists():
        try:
            with notice.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("#") or not line.strip():
                        continue
                    notices_total += 1
        except Exception:
            pass

        # Keep a stable path for the UI defaults.
        latest = out_base / "notice.log"
        try:
            latest.write_text(notice.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
        except Exception:
            pass

    return {
        "technique": "zeek_offline",
        "pcap_path": str(pcap),
        "script_path": str(script),
        "run_dir": str(run_dir),
        "notice_log": str(notice) if notice.exists() else "",
        "notice_log_latest": str((out_base / "notice.log")) if (out_base / "notice.log").exists() else "",
        "notices_total": notices_total,
        "returncode": int(res.returncode),
        "stdout_tail": _tail(res.stdout or ""),
        "stderr_tail": _tail(res.stderr or ""),
        "note": "Zeek writes logs to the run_dir; use detection-matrix to correlate notice.log with scan windows.",
    }


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description="Offline IDS helpers (Suricata/Zeek) for NetVis.")
    sub = p.add_subparsers(dest="tool", required=True)

    p_s = sub.add_parser("suricata")
    p_s.add_argument("--pcap", required=True)
    p_s.add_argument("--rules", default="")
    p_s.add_argument("--config", default="")
    p_s.add_argument("--out-dir", default="")
    p_s.add_argument("--timeout", type=int, default=120)

    p_z = sub.add_parser("zeek")
    p_z.add_argument("--pcap", required=True)
    p_z.add_argument("--script", default="")
    p_z.add_argument("--out-dir", default="")
    p_z.add_argument("--timeout", type=int, default=120)

    args = p.parse_args()
    if args.tool == "suricata":
        result = suricata_offline(
            pcap_path=args.pcap,
            rules_path=args.rules or None,
            config_path=args.config or None,
            out_dir=args.out_dir or None,
            timeout_seconds=args.timeout,
        )
    else:
        result = zeek_offline(
            pcap_path=args.pcap,
            script_path=args.script or None,
            out_dir=args.out_dir or None,
            timeout_seconds=args.timeout,
        )

    print(json.dumps(result, indent=2))
    return 0 if "error" not in result else 2


if __name__ == "__main__":
    raise SystemExit(main())

