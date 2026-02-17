#!/usr/bin/env python3
"""SMB / Windows enumeration techniques (NIP extensions).

Implements:
- smb.enum_shares
- smb.enum_sessions (best-effort)
- smb.os_discovery

Behavior:
- Uses local tools when available (`smbclient`, `rpcclient`, `nmap` scripts).
- Falls back gracefully with informative output when tools are missing.
"""

from __future__ import annotations

import argparse
import re
import shutil
import socket
import subprocess
import time
from typing import Dict, List

from toolkit.utils import ensure_private_target, new_session_id, utc_now_iso, write_json_log


def _which(cmd: str) -> str:
    return str(shutil.which(cmd) or "")


def _run(cmd: List[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((host, int(port))) == 0
        s.close()
        return bool(ok)
    except Exception:
        return False


def smb_enum_shares(target: str) -> Dict[str, object]:
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    out = {
        "technique": "smb_enum_shares",
        "target": str(target),
        "started_at": started_at,
        "scan_duration_seconds": 0.0,
        "port_445_open": _tcp_open(str(target), 445),
        "method": "",
        "shares": [],
        "notes": "",
    }
    if not out["port_445_open"]:
        out["notes"] = "SMB port 445 is closed/unreachable."
        out["scan_duration_seconds"] = max(0.0001, time.time() - start)
        return out

    # Prefer smbclient guest/null listing.
    if _which("smbclient"):
        try:
            # -g gives parseable output: "Disk|sharename|comment"
            cmd = ["smbclient", "-L", f"//{target}", "-N", "-g"]
            res = _run(cmd, timeout=20)
            out["method"] = "smbclient"
            rows = []
            for ln in (res.stdout or "").splitlines():
                ln = ln.strip()
                if not ln or "|" not in ln:
                    continue
                parts = ln.split("|")
                if len(parts) < 3:
                    continue
                stype, name, comment = parts[0], parts[1], parts[2]
                if stype.lower() in ("disk", "ipc", "printer"):
                    rows.append({"share": name, "type": stype, "comment": comment})
            out["shares"] = rows
            if not rows and (res.stderr or "").strip():
                out["notes"] = (res.stderr or "").strip()[:400]
        except Exception as e:
            out["method"] = "smbclient (failed)"
            out["notes"] = str(e)
    elif _which("nmap"):
        try:
            # nmap smb-enum-shares script.
            cmd = ["nmap", "-p", "445", "--script", "smb-enum-shares", str(target)]
            res = _run(cmd, timeout=40)
            out["method"] = "nmap:smb-enum-shares"
            raw = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
            shares = []
            for ln in raw.splitlines():
                m = re.search(r"\\\\[^\\]+\\([A-Za-z0-9_\\-$]+)", ln)
                if m:
                    shares.append({"share": m.group(1), "type": "unknown", "comment": ""})
            out["shares"] = sorted(list({s["share"]: s for s in shares}.values()), key=lambda x: x["share"])
            out["notes"] = "Parsed from nmap output."
        except Exception as e:
            out["method"] = "nmap:smb-enum-shares (failed)"
            out["notes"] = str(e)
    else:
        out["method"] = "none"
        out["notes"] = "Neither smbclient nor nmap is available."

    out["scan_duration_seconds"] = max(0.0001, time.time() - start)
    return out


def smb_enum_sessions(target: str) -> Dict[str, object]:
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    out = {
        "technique": "smb_enum_sessions",
        "target": str(target),
        "started_at": started_at,
        "scan_duration_seconds": 0.0,
        "method": "",
        "sessions": [],
        "notes": "",
    }

    if _which("rpcclient"):
        try:
            # Requires null session allowance; often denied on hardened hosts.
            cmd = ["rpcclient", "-N", "-U", "%", str(target), "-c", "enumdomusers"]
            res = _run(cmd, timeout=20)
            out["method"] = "rpcclient:enumdomusers"
            rows = []
            for ln in (res.stdout or "").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                m = re.search(r"user:\[(.*?)\].*rid:\[(0x[0-9a-fA-F]+)\]", ln)
                if m:
                    rows.append({"user": m.group(1), "rid": m.group(2)})
            out["sessions"] = rows
            if not rows:
                out["notes"] = ((res.stderr or "").strip() or "No null-session user/session data returned.")[:400]
        except Exception as e:
            out["method"] = "rpcclient (failed)"
            out["notes"] = str(e)
    elif _which("nmap"):
        try:
            cmd = ["nmap", "-p", "445", "--script", "smb-enum-sessions", str(target)]
            res = _run(cmd, timeout=40)
            out["method"] = "nmap:smb-enum-sessions"
            raw = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
            rows = []
            for ln in raw.splitlines():
                if "account_used:" in ln or "session" in ln.lower():
                    rows.append({"raw": ln.strip()[:300]})
            out["sessions"] = rows
            if not rows:
                out["notes"] = "No session info parsed from nmap output."
        except Exception as e:
            out["method"] = "nmap:smb-enum-sessions (failed)"
            out["notes"] = str(e)
    else:
        out["method"] = "none"
        out["notes"] = "Neither rpcclient nor nmap is available."

    out["scan_duration_seconds"] = max(0.0001, time.time() - start)
    return out


def smb_os_discovery(target: str) -> Dict[str, object]:
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    out = {
        "technique": "smb_os_discovery",
        "target": str(target),
        "started_at": started_at,
        "scan_duration_seconds": 0.0,
        "method": "",
        "os": "",
        "hostname": "",
        "domain": "",
        "smb_dialect": "",
        "notes": "",
    }

    if _which("nmap"):
        try:
            cmd = ["nmap", "-p", "445", "--script", "smb-os-discovery", str(target)]
            res = _run(cmd, timeout=45)
            txt = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
            out["method"] = "nmap:smb-os-discovery"
            for ln in txt.splitlines():
                l = ln.strip()
                if "OS:" in l and not out["os"]:
                    out["os"] = l.split("OS:", 1)[1].strip()
                elif "Computer name:" in l and not out["hostname"]:
                    out["hostname"] = l.split("Computer name:", 1)[1].strip()
                elif "Domain name:" in l and not out["domain"]:
                    out["domain"] = l.split("Domain name:", 1)[1].strip()
                elif "SMBv1" in l or "dialect" in l.lower():
                    out["smb_dialect"] = l
            if not out["os"] and not out["hostname"]:
                out["notes"] = "No SMB OS fields parsed from nmap output."
        except Exception as e:
            out["method"] = "nmap:smb-os-discovery (failed)"
            out["notes"] = str(e)
    elif _which("rpcclient"):
        try:
            cmd = ["rpcclient", "-N", "-U", "%", str(target), "-c", "srvinfo"]
            res = _run(cmd, timeout=20)
            out["method"] = "rpcclient:srvinfo"
            txt = (res.stdout or "").strip()
            out["notes"] = txt[:500]
            for ln in txt.splitlines():
                ll = ln.strip().lower()
                if "platform id" in ll and not out["os"]:
                    out["os"] = ln.strip()
        except Exception as e:
            out["method"] = "rpcclient:srvinfo (failed)"
            out["notes"] = str(e)
    else:
        out["method"] = "none"
        out["notes"] = "Neither nmap nor rpcclient is available."

    out["scan_duration_seconds"] = max(0.0001, time.time() - start)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="SMB enumeration")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("enum-shares")
    p1.add_argument("--target", required=True)

    p2 = sub.add_parser("enum-sessions")
    p2.add_argument("--target", required=True)

    p3 = sub.add_parser("os-discovery")
    p3.add_argument("--target", required=True)

    args = parser.parse_args()
    if args.cmd == "enum-shares":
        result = smb_enum_shares(args.target)
        sid = new_session_id("smb-shares")
    elif args.cmd == "enum-sessions":
        result = smb_enum_sessions(args.target)
        sid = new_session_id("smb-sessions")
    elif args.cmd == "os-discovery":
        result = smb_os_discovery(args.target)
        sid = new_session_id("smb-os")
    else:
        raise SystemExit(2)

    write_json_log("smb", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

