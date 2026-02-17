#!/usr/bin/env python3
"""Common helpers for NetVis reconnaissance modules."""

from __future__ import annotations

import ipaddress
import json
import os
import random
import socket
import time
import uuid
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_session_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def ensure_private_target(target: str) -> None:
    """Guardrail: refuse non-private scan targets.

    This project is intended for lab coursework. We allow:
    - RFC1918 private IPv4 ranges (10/8, 172.16/12, 192.168/16)
    - Loopback (127/8, ::1)
    - Link-local (169.254/16, fe80::/10)
    - IPv6 unique-local (fc00::/7)
    """
    if target is None:
        raise ValueError("Target must not be None")
    t = str(target).strip()
    if not t:
        raise ValueError("Target must not be empty")
    if t.lower() == "localhost":
        return

    try:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            ok = bool(net.is_private or net.is_loopback or net.is_link_local)
        else:
            ip = ipaddress.ip_address(t)
            ok = bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except Exception as exc:
        raise ValueError(f"Invalid target (expected IP or CIDR): {t}") from exc

    if not ok:
        raise ValueError(f"Refusing to scan non-private target: {t}")


def hosts_from_network(network: str, max_hosts: int | None = None) -> List[str]:
    net = ipaddress.ip_network(network, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if max_hosts is not None:
        return hosts[:max_hosts]
    return hosts


def infer_local_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


def infer_default_network(local_ip: str | None = None, prefix: int = 24) -> str:
    ip = local_ip or infer_local_ip()
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return str(net)


def random_mac() -> str:
    # Locally administered unicast MAC.
    octets = [0x02, random.randint(0x00, 0x7F)] + [random.randint(0x00, 0xFF) for _ in range(4)]
    return ":".join(f"{o:02x}" for o in octets)


def safe_json(value: Any) -> Any:
    if is_dataclass(value):
        return safe_json(asdict(value))
    if isinstance(value, dict):
        return {str(k): safe_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [safe_json(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def write_json_log(module: str, session_id: str, payload: Dict[str, Any]) -> Path:
    out_dir = LOG_DIR / module
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{session_id}.json"
    data = {
        "session_id": session_id,
        "module": module,
        "generated_at": utc_now_iso(),
        **payload,
    }
    out_file.write_text(json.dumps(safe_json(data), indent=2), encoding="utf-8")
    return out_file


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    if pct <= 0:
        return float(min(values))
    if pct >= 100:
        return float(max(values))
    ordered = sorted(values)
    idx = (len(ordered) - 1) * (pct / 100.0)
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    frac = idx - lo
    return ordered[lo] * (1.0 - frac) + ordered[hi] * frac


def shuffled_tuples(hosts: Iterable[str], ports: Iterable[int]) -> List[Tuple[str, int]]:
    tuples = [(h, p) for h in hosts for p in ports]
    random.shuffle(tuples)
    return tuples


def sleep_with_jitter(base_delay: float, mode: str = "none", jitter_arg: float = 0.0) -> float:
    """Sleep according to jitter mode and return actual delay used."""
    delay = base_delay
    if mode == "uniform" and jitter_arg > 0:
        delay = random.uniform(max(0.0, base_delay - jitter_arg), base_delay + jitter_arg)
    elif mode == "exponential" and jitter_arg > 0:
        # jitter_arg is lambda rate in 1/sec space; clamp high values.
        lam = max(1e-6, jitter_arg)
        delay = random.expovariate(lam)
    if delay > 0:
        time.sleep(delay)
    return delay


def tx_packets_on_interface(interface: str) -> int:
    """Return interface TX packet counter from /sys or netstat fallback."""
    sys_path = Path(f"/sys/class/net/{interface}/statistics/tx_packets")
    if sys_path.exists():
        try:
            return int(sys_path.read_text(encoding="utf-8").strip())
        except Exception:
            pass

    # macOS fallback via netstat -I <if>
    try:
        import subprocess

        res = subprocess.run(["netstat", "-I", interface], capture_output=True, text=True, timeout=3)
        lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
        if len(lines) >= 2:
            hdr = lines[0].split()
            vals = lines[1].split()
            if "Opkts" in hdr:
                idx = hdr.index("Opkts")
                return int(vals[idx])
    except Exception:
        pass
    return -1


def promisc_flag_on_interface(interface: str) -> bool | None:
    """Best-effort check whether an interface is currently in PROMISC mode."""
    try:
        import subprocess

        if sys.platform.startswith("linux"):
            res = subprocess.run(["ip", "link", "show", "dev", interface], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                return "PROMISC" in res.stdout
        # macOS/BSD (and Linux fallback)
        res = subprocess.run(["ifconfig", interface], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            return "PROMISC" in res.stdout
    except Exception:
        return None
    return None


def elapsed_ms(start_ts: float) -> float:
    return (time.time() - start_ts) * 1000.0
