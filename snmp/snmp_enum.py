#!/usr/bin/env python3
"""SNMP enumeration techniques (NIP extensions).

Implements:
- snmp.walk (read-only SNMPv2c walk via local snmpwalk binary when available)

Community string bruteforce is intentionally not implemented.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import time
from typing import Dict, List, Optional

from toolkit.utils import ensure_private_target, new_session_id, utc_now_iso, write_json_log


def _snmpwalk_available() -> bool:
    return bool(shutil.which("snmpwalk"))


def _run_snmpwalk(*, target: str, community: str, oid: str, timeout: int = 2, retries: int = 1, max_lines: int = 5000) -> Dict[str, object]:
    if not _snmpwalk_available():
        raise RuntimeError("snmpwalk is not available on this system.")
    cmd = [
        "snmpwalk",
        "-v2c",
        "-c",
        str(community),
        "-t",
        str(int(timeout)),
        "-r",
        str(int(retries)),
        str(target),
        str(oid),
    ]
    t0 = time.time()
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=max(5, int(timeout) * 20))
    except subprocess.TimeoutExpired:
        return {"oid": oid, "ok": False, "error": "timeout", "lines": []}
    dur = max(0.0001, time.time() - t0)
    out = res.stdout or ""
    err = (res.stderr or "").strip()
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... ({len(lines) - max_lines} more lines truncated)"]
    ok = (res.returncode == 0) and bool(lines)
    return {"oid": oid, "ok": ok, "returncode": int(res.returncode), "duration_seconds": dur, "error": err, "lines": lines}


def _parse_system(lines: List[str]) -> Dict[str, str]:
    out = {}
    for ln in lines or []:
        if "=" not in ln:
            continue
        left, right = ln.split("=", 1)
        key = left.strip()
        val = right.strip()
        if "sysDescr.0" in key:
            out["sysDescr"] = val
        if "sysName.0" in key:
            out["sysName"] = val
        if "sysLocation.0" in key:
            out["sysLocation"] = val
        if "sysContact.0" in key:
            out["sysContact"] = val
    return out


def snmp_walk(target: str, *, community: str = "public", mode: str = "system") -> Dict[str, object]:
    """SNMP walk of selected OID trees.

    mode:
    - system: only SNMPv2-MIB::system subtree (fast)
    - full: add interface + routing + ARP tables (can be slow/noisy)
    """
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    mode = (mode or "system").strip().lower()
    oids = ["1.3.6.1.2.1.1"]  # system
    if mode == "full":
        oids.extend(
            [
                "1.3.6.1.2.1.2.2.1",  # ifTable
                "1.3.6.1.2.1.4.21",  # ipRouteTable
                "1.3.6.1.2.1.4.22",  # ipNetToMediaTable (ARP)
            ]
        )

    results = []
    system_info = {}
    for oid in oids:
        r = _run_snmpwalk(target=target, community=community, oid=oid, timeout=2, retries=1, max_lines=5000)
        results.append(r)
        if oid == "1.3.6.1.2.1.1" and r.get("ok") and isinstance(r.get("lines"), list):
            system_info = _parse_system(r.get("lines") or [])

    ok_any = any(bool(r.get("ok")) for r in results)
    dur = max(0.0001, time.time() - start)

    return {
        "technique": "snmp_walk",
        "target": str(target),
        "community": str(community),
        "mode": mode,
        "started_at": started_at,
        "scan_duration_seconds": dur,
        "ok_any": ok_any,
        "system": system_info,
        "walks": results,
        "notes": "SNMP walk is read-only. Community bruteforce is intentionally not implemented.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="SNMP enumeration")
    parser.add_argument("--target", required=True)
    parser.add_argument("--community", default="public")
    parser.add_argument("--mode", default="system", choices=["system", "full"])
    args = parser.parse_args()

    result = snmp_walk(args.target, community=args.community, mode=args.mode)
    sid = new_session_id("snmp-walk")
    write_json_log("snmp", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

