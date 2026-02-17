#!/usr/bin/env python3
"""SSH deep analysis techniques (NIP extensions).

Implements:
- ssh.host_key_fingerprint (host keys as persistent device identifiers)
- ssh.algorithm_audit (best-effort; uses nmap ssh2-enum-algos when available)
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
import time
from typing import Dict, List, Optional

from toolkit.utils import ensure_private_target, new_session_id, utc_now_iso, write_json_log


def _which(cmd: str) -> str:
    return str(shutil.which(cmd) or "")


def _run(cmd: List[str], *, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _parse_ssh_keyscan(output: str) -> List[dict]:
    keys = []
    for ln in (output or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        if len(parts) < 3:
            continue
        host, keytype, keydata = parts[0], parts[1], parts[2]
        keys.append({"host": host, "key_type": keytype, "key_data": keydata, "known_hosts_line": ln})
    return keys


def ssh_host_key_fingerprint(target: str, *, port: int = 22, timeout_seconds: int = 4) -> Dict[str, object]:
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    if not _which("ssh-keyscan"):
        raise RuntimeError("ssh-keyscan is not available on this system.")
    if not _which("ssh-keygen"):
        raise RuntimeError("ssh-keygen is not available on this system.")

    # Pull multiple key types if possible.
    scan_cmd = ["ssh-keyscan", "-p", str(int(port)), "-T", str(int(max(1, timeout_seconds))), "-t", "rsa,ecdsa,ed25519", str(target)]
    res = _run(scan_cmd, timeout=int(max(3, timeout_seconds + 2)))
    keys = _parse_ssh_keyscan(res.stdout or "")

    fingerprints = []
    for k in keys:
        try:
            with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
                tmp.write(k["known_hosts_line"] + "\n")
                tmp_path = tmp.name
            fp = _run(["ssh-keygen", "-lf", tmp_path], timeout=3)
            # Example: "256 SHA256:.... host (ED25519)"
            line = (fp.stdout or "").strip().splitlines()[:1]
            fp_line = line[0].strip() if line else ""
            bits = 0
            fph = ""
            if fp_line:
                parts = fp_line.split()
                if parts and parts[0].isdigit():
                    bits = int(parts[0])
                if len(parts) >= 2:
                    fph = parts[1]
            fingerprints.append({"key_type": k["key_type"], "bits": bits, "fingerprint": fph, "raw": fp_line})
        except Exception:
            continue

    dur = max(0.0001, time.time() - start)
    return {
        "technique": "ssh_host_key_fingerprint",
        "target": str(target),
        "port": int(port),
        "started_at": started_at,
        "scan_duration_seconds": dur,
        "keys_found": len(keys),
        "fingerprints": fingerprints,
        "notes": "Host keys are stable identifiers across IP/MAC changes; compare fingerprints to track a device over time.",
    }


def ssh_algorithm_audit(target: str, *, port: int = 22, timeout_seconds: int = 10) -> Dict[str, object]:
    ensure_private_target(target)
    started_at = utc_now_iso()
    start = time.time()

    # Best-effort approach:
    # - If nmap exists, use ssh2-enum-algos script for offered algorithms.
    # - Otherwise, fall back to key-type-only assessment from ssh-keyscan.
    out = {
        "technique": "ssh_algorithm_audit",
        "target": str(target),
        "port": int(port),
        "started_at": started_at,
        "scan_duration_seconds": 0.0,
        "method": "",
        "algorithms": {},
        "weak_algorithms": [],
        "notes": "",
    }

    nmap_path = _which("nmap")
    if nmap_path:
        cmd = ["nmap", "-p", str(int(port)), "--script", "ssh2-enum-algos", str(target)]
        try:
            res = _run(cmd, timeout=int(max(8, timeout_seconds)))
            txt = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
            out["method"] = "nmap:ssh2-enum-algos"
            out["algorithms"]["raw"] = txt.strip()
            # Basic weak flagging (text scan)
            weak = []
            for token in ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "3des-cbc", "hmac-md5", "hmac-sha1", "arcfour"):
                if token in txt:
                    weak.append(token)
            out["weak_algorithms"] = sorted(list(set(weak)))
            out["notes"] = "Weak list is heuristic; review full raw output."
        except Exception as e:
            out["method"] = "nmap:ssh2-enum-algos (failed)"
            out["notes"] = str(e)
    else:
        # Fallback: key types from ssh-keyscan.
        try:
            if not _which("ssh-keyscan"):
                raise RuntimeError("ssh-keyscan not available")
            scan_cmd = ["ssh-keyscan", "-p", str(int(port)), "-T", "3", "-t", "rsa,ecdsa,ed25519", str(target)]
            res = _run(scan_cmd, timeout=6)
            keys = _parse_ssh_keyscan(res.stdout or "")
            key_types = sorted(list({k["key_type"] for k in keys if k.get("key_type")}))
            out["method"] = "ssh-keyscan:key-types"
            out["algorithms"]["host_key_types"] = key_types
            weak = []
            if key_types and all(kt == "ssh-rsa" for kt in key_types):
                weak.append("ssh-rsa (only)")
            out["weak_algorithms"] = weak
            out["notes"] = "Full KEX/cipher/MAC audit requires nmap ssh2-enum-algos or an SSH library; this fallback checks only host key types."
        except Exception as e:
            out["method"] = "ssh-keyscan:key-types (failed)"
            out["notes"] = str(e)

    out["scan_duration_seconds"] = max(0.0001, time.time() - start)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="SSH deep analysis")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("host-key-fp")
    p1.add_argument("--target", required=True)
    p1.add_argument("--port", type=int, default=22)

    p2 = sub.add_parser("algo-audit")
    p2.add_argument("--target", required=True)
    p2.add_argument("--port", type=int, default=22)

    args = parser.parse_args()

    if args.cmd == "host-key-fp":
        result = ssh_host_key_fingerprint(args.target, port=int(args.port))
        sid = new_session_id("ssh-hostkey")
    elif args.cmd == "algo-audit":
        result = ssh_algorithm_audit(args.target, port=int(args.port))
        sid = new_session_id("ssh-audit")
    else:
        raise SystemExit(2)

    write_json_log("ssh", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

