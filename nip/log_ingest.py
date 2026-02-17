#!/usr/bin/env python3
"""NIP Phase 2.5 — Log Ingestion Pipeline.

Parsers for syslog, DHCP lease files, auth/RADIUS logs, and firewall logs.
Each parser yields structured dicts that the server can push into the event
bus / graph / observations tables.

Usage:
    events = parse_syslog_file("/var/log/syslog")
    events = parse_dhcp_leases("/var/lib/dhcp/dhcpd.leases")
    events = parse_auth_log("/var/log/auth.log")
    events = parse_firewall_log("/var/log/ufw.log")
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Syslog parser (RFC 3164 style)
# ---------------------------------------------------------------------------

_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _syslog_ts(month: str, day: str, time_s: str, year: Optional[int] = None) -> str:
    yr = year or datetime.now().year
    mo = _MONTHS.get(month, 1)
    try:
        return datetime(yr, mo, int(day), *map(int, time_s.split(":"))).isoformat()
    except Exception:
        return datetime.now().isoformat()


def parse_syslog_lines(lines: List[str], *, year: Optional[int] = None) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for line in lines:
        m = _SYSLOG_RE.match(line.strip())
        if not m:
            continue
        ts = _syslog_ts(m.group("month"), m.group("day"), m.group("time"), year)
        events.append({
            "type": "syslog",
            "timestamp": ts,
            "host": m.group("host"),
            "process": m.group("process"),
            "pid": m.group("pid") or "",
            "message": m.group("message"),
        })
    return events


def parse_syslog_file(path: str, *, year: Optional[int] = None, limit: int = 50000) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    lines = p.read_text(errors="replace").splitlines()[-limit:]
    return parse_syslog_lines(lines, year=year)


# ---------------------------------------------------------------------------
# DHCP lease file parser (ISC dhcpd.leases style)
# ---------------------------------------------------------------------------

_LEASE_START = re.compile(r"^lease\s+(\S+)\s+\{")
_LEASE_HW = re.compile(r"hardware\s+ethernet\s+([0-9a-fA-F:]+)")
_LEASE_HOST = re.compile(r'client-hostname\s+"([^"]+)"')
_LEASE_STARTS = re.compile(r"starts\s+\d+\s+(\S+\s+\S+)")
_LEASE_ENDS = re.compile(r"ends\s+\d+\s+(\S+\s+\S+)")


def parse_dhcp_leases(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    text = p.read_text(errors="replace")
    leases: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for line in text.splitlines():
        line = line.strip()
        m = _LEASE_START.match(line)
        if m:
            current = {"type": "dhcp_lease", "ip": m.group(1), "mac": "", "hostname": "", "starts": "", "ends": ""}
            continue
        if current is None:
            continue
        m = _LEASE_HW.search(line)
        if m:
            current["mac"] = m.group(1).upper()
        m = _LEASE_HOST.search(line)
        if m:
            current["hostname"] = m.group(1)
        m = _LEASE_STARTS.search(line)
        if m:
            current["starts"] = m.group(1).replace("/", "-")
        m = _LEASE_ENDS.search(line)
        if m:
            current["ends"] = m.group(1).replace("/", "-")
        if line == "}":
            if current.get("ip"):
                current["timestamp"] = current.get("starts") or datetime.now().isoformat()
                leases.append(current)
            current = None
    return leases


# ---------------------------------------------------------------------------
# Auth / RADIUS log parser
# ---------------------------------------------------------------------------

_AUTH_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+\S+:\s+(?P<message>.+)$"
)

_AUTH_ACCEPT = re.compile(r"(?:Accepted|authenticated)\s+\S+\s+for\s+(\S+)\s+from\s+(\S+)", re.I)
_AUTH_FAIL = re.compile(r"(?:Failed|rejected|invalid)\s+\S*\s*for\s+(\S+)\s+from\s+(\S+)", re.I)


def parse_auth_log(path: str, *, year: Optional[int] = None, limit: int = 50000) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    events: List[Dict[str, Any]] = []
    for line in p.read_text(errors="replace").splitlines()[-limit:]:
        m = _AUTH_RE.match(line.strip())
        if not m:
            continue
        ts = _syslog_ts(m.group("month"), m.group("day"), m.group("time"), year)
        msg = m.group("message")
        ev: Dict[str, Any] = {
            "type": "auth",
            "timestamp": ts,
            "host": m.group("host"),
            "message": msg,
            "auth_result": "unknown",
        }
        ma = _AUTH_ACCEPT.search(msg)
        if ma:
            ev["auth_result"] = "accept"
            ev["user"] = ma.group(1)
            ev["src_ip"] = ma.group(2)
        mf = _AUTH_FAIL.search(msg)
        if mf:
            ev["auth_result"] = "fail"
            ev["user"] = mf.group(1)
            ev["src_ip"] = mf.group(2)
        events.append(ev)
    return events


# ---------------------------------------------------------------------------
# Firewall log parser (ufw / iptables style)
# ---------------------------------------------------------------------------

_FW_RE = re.compile(
    r"SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*?"
    r"PROTO=(?P<proto>\S+)(?:.*?SPT=(?P<spt>\d+))?(?:.*?DPT=(?P<dpt>\d+))?"
)

_FW_ACTION_RE = re.compile(r"\[UFW\s+(\w+)\]|\b(ACCEPT|DROP|REJECT|BLOCK)\b", re.I)


def parse_firewall_log(path: str, *, year: Optional[int] = None, limit: int = 50000) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    events: List[Dict[str, Any]] = []
    for line in p.read_text(errors="replace").splitlines()[-limit:]:
        m = _FW_RE.search(line)
        if not m:
            continue
        ts_match = _SYSLOG_RE.match(line.strip())
        ts = ""
        if ts_match:
            ts = _syslog_ts(ts_match.group("month"), ts_match.group("day"), ts_match.group("time"), year)
        else:
            ts = datetime.now().isoformat()

        action = "unknown"
        act_m = _FW_ACTION_RE.search(line)
        if act_m:
            action = (act_m.group(1) or act_m.group(2) or "unknown").upper()

        events.append({
            "type": "firewall",
            "timestamp": ts,
            "action": action,
            "src_ip": m.group("src"),
            "dst_ip": m.group("dst"),
            "protocol": m.group("proto"),
            "src_port": int(m.group("spt") or 0),
            "dst_port": int(m.group("dpt") or 0),
            "raw": line.strip()[:500],
        })
    return events


# ---------------------------------------------------------------------------
# Unified ingestion helper
# ---------------------------------------------------------------------------

def ingest_log_file(path: str, *, log_type: str = "auto", year: Optional[int] = None) -> Dict[str, Any]:
    """Parse a log file and return structured events + summary."""
    p = Path(path)
    if not p.exists():
        return {"ok": False, "error": f"File not found: {path}", "events": []}

    if log_type == "auto":
        name = p.name.lower()
        if "dhcp" in name or "lease" in name:
            log_type = "dhcp"
        elif "auth" in name or "radius" in name:
            log_type = "auth"
        elif "ufw" in name or "firewall" in name or "iptables" in name:
            log_type = "firewall"
        else:
            log_type = "syslog"

    parser_map = {
        "syslog": lambda: parse_syslog_file(path, year=year),
        "dhcp": lambda: parse_dhcp_leases(path),
        "auth": lambda: parse_auth_log(path, year=year),
        "firewall": lambda: parse_firewall_log(path, year=year),
    }

    parser = parser_map.get(log_type)
    if not parser:
        return {"ok": False, "error": f"Unknown log_type: {log_type}", "events": []}

    events = parser()
    return {
        "ok": True,
        "log_type": log_type,
        "path": str(p),
        "events": events,
        "count": len(events),
    }
