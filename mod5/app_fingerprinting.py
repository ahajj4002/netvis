#!/usr/bin/env python3
"""Module 5: Application-layer fingerprinting (NetVis toolkit).

Implements:
- 5a Banner grabbing
- 5b TLS certificate inspection (uses openssl CLI if available)
- 5c HTTP header analysis
- 5d TCP stack fingerprinting (lightweight signature matching)
- 5e DNS enumeration + passive DNS monitoring

Outputs structured JSON logs under logs/mod5/.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, AsyncSniffer, conf, fragment, send, sniff, sr1

from toolkit.utils import (
    ensure_private_target,
    infer_local_ip,
    new_session_id,
    percentile,
    promisc_flag_on_interface,
    tx_packets_on_interface,
    utc_now_iso,
    write_json_log,
)

conf.verb = 0


# ------------------------------
# 5a Banner grabbing
# ------------------------------

def grab_banner_tcp(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            sock.close()
            return ""

        # For protocols that don't send banners automatically, send minimal probe
        if port in (80, 8080, 8000):
            sock.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif port == 25:
            # SMTP: wait for banner
            pass

        data = sock.recv(1024)
        sock.close()
        return data.decode("utf-8", errors="ignore").strip()[:400]
    except Exception:
        return ""


def grab_banner_https(host: str, port: int = 443, timeout: float = 3.0) -> str:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ss.settimeout(timeout)
                ss.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                data = ss.recv(2048)
                return data.decode("utf-8", errors="ignore").strip()[:600]
    except Exception:
        return ""


def _split_product_version(value: str) -> Tuple[str, str]:
    """Best-effort split like 'Apache/2.4.57' -> ('Apache', '2.4.57')."""
    v = (value or "").strip()
    if not v:
        return "", ""
    token = v.split()[0]
    token = token.split(";", 1)[0]
    token = token.split("(", 1)[0].strip()
    if "/" in token:
        prod, ver = token.split("/", 1)
        return prod.strip(), ver.strip()
    return token.strip(), ""


def _parse_http_like_banner(banner: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if not banner:
        return headers
    lines = banner.replace("\r\n", "\n").split("\n")
    for ln in lines:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def parse_banner_intel(port: int, banner: str) -> Dict[str, str]:
    """Extract service/version/OS hints from a raw banner string."""
    out = {"service": "", "product": "", "version": "", "os_hint": "", "raw": banner or ""}
    b = (banner or "").strip()
    if not b:
        return out

    if port == 22 and b.startswith("SSH-"):
        out["service"] = "SSH"
        m = re.search(r"^SSH-\\d\\.\\d-([^\\s]+)\\s*(.*)$", b)
        if m:
            ident = m.group(1).strip()
            rest = m.group(2).strip()
            if "_" in ident:
                prod, ver = ident.split("_", 1)
                out["product"] = prod
                out["version"] = ver
            else:
                out["product"] = ident
            if rest:
                out["os_hint"] = rest[:120]
        return out

    if port == 21:
        out["service"] = "FTP"
        low = b.lower()
        patterns = [
            ("vsftpd", r"vsftpd\\s+([0-9.]+)"),
            ("proftpd", r"proftpd\\s+([0-9.]+)"),
            ("filezilla", r"filezilla\\s+server\\s+([0-9.]+)"),
            ("pure-ftpd", r"pure-ftpd\\s+([0-9.]+)"),
        ]
        for prod, pat in patterns:
            m = re.search(pat, low)
            if m:
                out["product"] = prod
                out["version"] = m.group(1)
                return out
        return out

    if port == 25:
        out["service"] = "SMTP"
        low = b.lower()
        for prod in ("postfix", "exim", "sendmail", "microsoft"):
            if prod in low:
                out["product"] = prod
                break
        m = re.search(r"\\b(postfix|exim|sendmail)[/\\s]([0-9][0-9a-zA-Z.\\-]+)", low)
        if m:
            out["product"] = m.group(1)
            out["version"] = m.group(2)
        return out

    if port in (80, 8080, 8000, 443):
        out["service"] = "HTTPS" if port == 443 else "HTTP"
        hdrs = _parse_http_like_banner(b)
        server = hdrs.get("Server", "")
        prod, ver = _split_product_version(server)
        out["product"] = prod or server[:120]
        out["version"] = ver
        m = re.search(r"\\(([^)]+)\\)", server)
        if m:
            out["os_hint"] = m.group(1)[:120]
        return out

    return out


def banner_grabbing(host: str, ports: List[int], timeout: float = 2.0) -> Dict[str, object]:
    ensure_private_target(host)
    results = []
    for port in ports:
        if port == 443:
            banner = grab_banner_https(host, port=port, timeout=timeout)
        else:
            banner = grab_banner_tcp(host, port, timeout=timeout)
        intel = parse_banner_intel(port, banner)
        results.append({
            "port": port,
            "banner": banner,
            "has_banner": bool(banner),
            "intel": intel,
        })

    return {
        "technique": "banner_grabbing",
        "host": host,
        "ports": ports,
        "timeout_seconds": timeout,
        "results": results,
    }


# ------------------------------
# 5b TLS certificate inspection
# ------------------------------

def _openssl_available() -> bool:
    try:
        subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=2)
        return True
    except Exception:
        return False


def _parse_openssl_x509_text(text: str) -> Dict[str, object]:
    out: Dict[str, object] = {
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "serial": "",
        "signature_algorithm": "",
        "public_key_bits": None,
        "sans": [],
    }

    # Subject / issuer / serial / dates
    m = re.search(r"Subject: (.*)", text)
    if m:
        out["subject"] = m.group(1).strip()
    m = re.search(r"Issuer: (.*)", text)
    if m:
        out["issuer"] = m.group(1).strip()
    m = re.search(r"Serial Number:\s*([0-9A-Fa-f:]+)", text)
    if m:
        out["serial"] = m.group(1).strip()
    m = re.search(r"Not Before: (.*)", text)
    if m:
        out["not_before"] = m.group(1).strip()
    m = re.search(r"Not After ?: (.*)", text)
    if m:
        out["not_after"] = m.group(1).strip()

    m = re.search(r"Signature Algorithm: (.*)", text)
    if m:
        out["signature_algorithm"] = m.group(1).strip()

    m = re.search(r"Public-Key: \((\d+) bit\)", text)
    if m:
        out["public_key_bits"] = int(m.group(1))

    # SANs
    san_block = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", text)
    if san_block:
        sans = san_block.group(1)
        out["sans"] = [s.strip() for s in sans.split(",") if s.strip()]

    return out


def tls_certificate_inspection(host: str, port: int = 443, timeout: float = 6.0) -> Dict[str, object]:
    if not _openssl_available():
        return {
            "technique": "tls_certificate_inspection",
            "host": host,
            "port": port,
            "error": "openssl_not_available",
            "fallback": "Use openssl in the course VM for full chain extraction.",
        }

    # Fetch chain via s_client
    try:
        cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts", "-verify", "5"]
        res = subprocess.run(cmd, input="".encode(), capture_output=True, timeout=timeout)
        out = res.stdout.decode("utf-8", errors="ignore")
    except Exception as exc:
        return {
            "technique": "tls_certificate_inspection",
            "host": host,
            "port": port,
            "error": f"s_client_failed_{type(exc).__name__}",
        }

    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, flags=re.S)

    chain = []
    with tempfile.TemporaryDirectory() as td:
        for i, pem in enumerate(pems):
            pem_path = os.path.join(td, f"cert_{i}.pem")
            with open(pem_path, "w", encoding="utf-8") as f:
                f.write(pem)

            try:
                txt = subprocess.run(
                    ["openssl", "x509", "-in", pem_path, "-noout", "-text"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                ).stdout
                chain.append({
                    "index": i,
                    **_parse_openssl_x509_text(txt),
                })
            except Exception:
                chain.append({"index": i, "error": "x509_parse_failed"})

    return {
        "technique": "tls_certificate_inspection",
        "host": host,
        "port": port,
        "cert_chain_length": len(chain),
        "chain": chain,
        "leakage_notes": {
            "prompt": "Report org/infrastructure hints from CN/SANs/issuer alone (no traffic decryption needed).",
        },
    }


# ------------------------------
# 5c HTTP header analysis
# ------------------------------

def http_header_analysis(host: str, port: int = 80, timeout: float = 3.0, use_tls: bool = False) -> Dict[str, object]:
    ensure_private_target(host)
    req = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetVis-Recon\r\nConnection: close\r\n\r\n"
    ).encode("utf-8")

    raw = b""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.send(req)
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw:
                break
        sock.close()
    except Exception as exc:
        return {
            "technique": "http_header_analysis",
            "host": host,
            "port": port,
            "use_tls": use_tls,
            "error": f"request_failed_{type(exc).__name__}",
        }

    head = raw.split(b"\r\n\r\n", 1)[0].decode("utf-8", errors="ignore")
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()

    # Detect internal IP leakage in forwarding headers (best-effort heuristic).
    xff = headers.get("X-Forwarded-For", "")
    leaked_private_ips = []
    if xff:
        for part in xff.split(","):
            cand = part.strip()
            try:
                ip = ipaddress.ip_address(cand)
                if ip.is_private:
                    leaked_private_ips.append(cand)
            except Exception:
                continue

    cache_header_keys = [
        "Via",
        "Age",
        "X-Cache",
        "X-Cache-Hits",
        "X-Served-By",
        "Server-Timing",
        "CF-Cache-Status",
        "CF-RAY",
        "X-Amz-Cf-Pop",
        "X-Amz-Cf-Id",
        "X-Proxy-Cache",
        "X-Cache-Status",
    ]
    caching_indicators = [{"header": k, "value": headers.get(k, "")} for k in cache_header_keys if k in headers]

    findings = {
        "server_software": headers.get("Server", ""),
        "framework": headers.get("X-Powered-By", ""),
        "internal_ip_leak": headers.get("X-Forwarded-For", ""),
        "internal_ip_leak_detected": bool(leaked_private_ips),
        "internal_ip_leak_private_ips": leaked_private_ips,
        "caching_layer": {
            "detected": bool(caching_indicators),
            "indicators": caching_indicators,
        },
        "security_headers": {
            "hsts": "Strict-Transport-Security" in headers,
            "csp": "Content-Security-Policy" in headers,
            "x_frame_options": "X-Frame-Options" in headers,
            "x_content_type_options": "X-Content-Type-Options" in headers,
            "referrer_policy": "Referrer-Policy" in headers,
        },
    }

    posture = "unknown"
    score = 0
    for k, present in findings["security_headers"].items():
        if present:
            score += 1
    if score >= 4:
        posture = "strong"
    elif score >= 2:
        posture = "moderate"
    else:
        posture = "weak"

    return {
        "technique": "http_header_analysis",
        "host": host,
        "port": port,
        "use_tls": use_tls,
        "status_line": status_line,
        "headers": headers,
        "findings": findings,
        "security_posture": posture,
    }


# ------------------------------
# 5d TCP stack fingerprinting
# ------------------------------

def tcp_stack_fingerprint(host: str, dport: int = 80, timeout: float = 1.0) -> Dict[str, object]:
    ensure_private_target(host)

    db_path = Path(__file__).resolve().parent / "tcp_fingerprint_db.json"
    db = {"version": None, "signatures": []}
    try:
        db = json.loads(db_path.read_text(encoding="utf-8"))
    except Exception:
        db = {"version": None, "signatures": []}

    signatures = db.get("signatures") if isinstance(db, dict) else []
    if not isinstance(signatures, list):
        signatures = []

    local_ip = ""
    try:
        local_ip = conf.route.route(host)[1] or ""
    except Exception:
        local_ip = ""

    probes = [
        {
            "name": "syn_smallwin_opts",
            "window": 1024,
            "options": [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (0, 0)), ("WScale", 7)],
            "fragment_size": None,
            "payload_len": 0,
        },
        {
            "name": "syn_midwin_opts",
            "window": 8192,
            "options": [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (0, 0)), ("WScale", 8)],
            "fragment_size": None,
            "payload_len": 0,
        },
        {
            "name": "syn_largewin_opts",
            "window": 65535,
            "options": [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (0, 0)), ("WScale", 6)],
            "fragment_size": None,
            "payload_len": 0,
        },
        {
            "name": "syn_noopts",
            "window": 16384,
            "options": [],
            "fragment_size": None,
            "payload_len": 0,
        },
        {
            "name": "syn_fragmented",
            "window": 1024,
            "options": [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (0, 0)), ("WScale", 7)],
            "fragment_size": 8,
            "payload_len": 64,
        },
    ]

    def summarize_tcp_options(opts) -> Tuple[List[str], List[Dict[str, object]]]:
        kinds = []
        detailed = []
        for o in opts or []:
            try:
                kind = str(o[0])
            except Exception:
                kind = str(o)
            val = None
            try:
                val = o[1]
            except Exception:
                val = None
            kinds.append(kind)
            if isinstance(val, (bytes, bytearray)):
                val = val.hex()[:64]
            detailed.append({"kind": kind, "value": val})
        return kinds, detailed

    def send_probe(pr: Dict[str, object]) -> Dict[str, object]:
        sport = random.randint(1024, 65535)
        ip = IP(dst=host, flags="DF")
        tcp = TCP(
            sport=sport,
            dport=dport,
            flags="S",
            seq=random.randint(0, 2**32 - 1),
            window=int(pr["window"]),
            options=pr["options"],
        )

        resp = None
        if pr.get("fragment_size"):
            payload_len = int(pr.get("payload_len") or 0)
            base = ip / tcp / Raw(load=b"A" * max(1, payload_len))
            frags = fragment(base, fragsize=int(pr["fragment_size"]))

            dst_filter = local_ip or infer_local_ip()
            bpf = f"tcp and src host {host} and dst host {dst_filter}"
            sniffer = AsyncSniffer(filter=bpf, timeout=timeout, count=1, store=True)
            sniffer.start()
            for f in frags:
                send(f, verbose=False)
            sniffer.join()
            if sniffer.results:
                resp = sniffer.results[0]
        else:
            resp = sr1(ip / tcp, timeout=timeout, verbose=False)

        if resp is None:
            return {"probe": pr["name"], "error": "no_response"}

        if resp.haslayer(TCP):
            tcp_r = resp[TCP]
            ip_r = resp[IP]
            kinds, detailed = summarize_tcp_options(tcp_r.options)

            # RST to clean up if we elicited SYN-ACK
            try:
                if int(tcp_r.flags) & 0x12:
                    send(IP(dst=host) / TCP(sport=sport, dport=dport, flags="R", seq=tcp_r.ack), verbose=False)
            except Exception:
                pass

            return {
                "probe": pr["name"],
                "ttl": int(ip_r.ttl),
                "window": int(tcp_r.window),
                "df": bool(ip_r.flags.DF),
                "tcp_flags": int(tcp_r.flags),
                "options_kinds": kinds,
                "options": detailed,
            }

        if resp.haslayer(ICMP):
            ic = resp[ICMP]
            return {
                "probe": pr["name"],
                "icmp_type": int(ic.type),
                "icmp_code": int(ic.code),
            }

        return {"probe": pr["name"], "error": "unexpected_response"}

    responses = [send_probe(pr) for pr in probes]

    # Aggregate observed features
    ttl_vals = [r["ttl"] for r in responses if "ttl" in r]
    win_vals = [r["window"] for r in responses if "window" in r]
    df_vals = [r["df"] for r in responses if "df" in r]
    opt_sets = [set(r.get("options_kinds", [])) for r in responses if "options_kinds" in r]
    opt_orders = [r.get("options_kinds", []) for r in responses if "options_kinds" in r]
    frag_responded = any(r.get("probe") == "syn_fragmented" and ("ttl" in r or "icmp_type" in r) for r in responses)

    def is_subsequence(pattern: List[str], observed: List[str]) -> bool:
        if not pattern:
            return True
        j = 0
        for x in observed:
            if j < len(pattern) and x == pattern[j]:
                j += 1
        return j == len(pattern)

    def score_signature(sig: Dict[str, object]) -> Dict[str, object]:
        ttl_min = int(sig.get("ttl_min") or 0)
        ttl_max = int(sig.get("ttl_max") or 255)
        want_df = sig.get("df")
        required_opts = set(sig.get("required_options") or [])
        order_any = sig.get("option_orders_any") or []
        win_any = set(sig.get("window_values_any") or [])

        total = 0
        score = 0
        matched = []

        # TTL range
        total += 1
        if ttl_vals and any(ttl_min <= t <= ttl_max for t in ttl_vals):
            score += 1
            matched.append("ttl")

        # DF bit
        if want_df is not None:
            total += 1
            if df_vals and any(bool(d) == bool(want_df) for d in df_vals):
                score += 1
                matched.append("df")

        # Window match
        if win_any:
            total += 1
            if win_vals and any(w in win_any for w in win_vals):
                score += 1
                matched.append("window")

        # Required options
        if required_opts:
            total += 1
            if opt_sets and any(required_opts.issubset(s) for s in opt_sets):
                score += 1
                matched.append("required_options")

        # Option order (as subsequence)
        if order_any:
            total += 1
            try:
                patterns = [list(p) for p in order_any if isinstance(p, list)]
            except Exception:
                patterns = []
            if opt_orders and any(is_subsequence(pat, obs) for pat in patterns for obs in opt_orders):
                score += 1
                matched.append("option_order")

        conf_score = (score / total) if total else 0.0
        return {"name": sig.get("name", "unknown"), "confidence": round(conf_score, 3), "matched": matched}

    scored = [score_signature(s) for s in signatures if isinstance(s, dict)]
    scored.sort(key=lambda x: -float(x.get("confidence") or 0.0))
    best = scored[0] if scored else {"name": "unknown", "confidence": 0.0, "matched": []}

    return {
        "technique": "tcp_stack_fingerprinting",
        "host": host,
        "dport": dport,
        "timeout_seconds": timeout,
        "fingerprint_db": {"path": str(db_path), "version": db.get("version") if isinstance(db, dict) else None},
        "probes_sent": [p["name"] for p in probes],
        "fragmentation_probe_responded": frag_responded,
        "responses": responses,
        "best_guess": best.get("name", "unknown"),
        "confidence": best.get("confidence", 0.0),
        "all_scores": scored[:10],
        "note": "Validate against known OS targets in the lab and report confidence/false positives.",
    }


# ------------------------------
# 5e DNS enumeration + passive DNS
# ------------------------------

def _dig_available() -> bool:
    try:
        subprocess.run(["dig", "+short", "example.com"], capture_output=True, text=True, timeout=2)
        return True
    except Exception:
        return False


def dns_query_scapy(name: str, qtype: str, server: str = "8.8.8.8", timeout: float = 2.0) -> List[str]:
    out = []
    try:
        pkt = IP(dst=server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype))
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp and resp.haslayer(DNS):
            dns = resp[DNS]
            for i in range(dns.ancount):
                rr = dns.an[i]
                out.append(str(rr.rdata))
    except Exception:
        pass
    return out


def _ptr_qname_for_ip(ip_str: str) -> str:
    ip = ipaddress.ip_address(ip_str)
    if ip.version == 4:
        parts = ip_str.split(".")
        return ".".join(reversed(parts)) + ".in-addr.arpa"
    # IPv6 nibble reverse
    hexstr = ip.exploded.replace(":", "")
    return ".".join(reversed(list(hexstr))) + ".ip6.arpa"


def reverse_dns_lookup(ip_str: str, server: str = "8.8.8.8") -> List[str]:
    try:
        ipaddress.ip_address(ip_str)
    except Exception:
        return []

    if _dig_available():
        try:
            res = subprocess.run(["dig", "+short", "-x", ip_str, f"@{server}"], capture_output=True, text=True, timeout=5)
            return [ln.strip().rstrip(".") for ln in res.stdout.splitlines() if ln.strip()]
        except Exception:
            return []

    # Scapy fallback: PTR query against the reverse name.
    qname = _ptr_qname_for_ip(ip_str)
    out = dns_query_scapy(qname, "PTR", server=server)
    return [str(x).rstrip(".") for x in out]


def dns_enumeration(
    domain: str,
    server: str = "8.8.8.8",
    reverse_cidr: str | None = None,
    reverse_max: int = 256,
) -> Dict[str, object]:
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SRV", "CNAME"]
    results: Dict[str, List[str]] = {}

    if _dig_available():
        for rt in record_types:
            try:
                res = subprocess.run(["dig", "+short", rt, domain, f"@{server}"], capture_output=True, text=True, timeout=5)
                lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
                results[rt] = lines
            except Exception:
                results[rt] = []

        # AXFR attempts against nameservers
        axfr = []
        for ns in results.get("NS", [])[:5]:
            ns_host = ns.rstrip(".")
            try:
                res = subprocess.run(["dig", "AXFR", domain, f"@{ns_host}"], capture_output=True, text=True, timeout=8)
                success = "Transfer failed" not in res.stdout and "connection timed out" not in res.stdout
                axfr.append({"ns": ns_host, "success": bool(success), "output_lines": res.stdout.splitlines()[:50]})
            except Exception as exc:
                axfr.append({"ns": ns_host, "success": False, "error": type(exc).__name__})
    else:
        for rt in record_types:
            results[rt] = dns_query_scapy(domain, rt, server=server)
        axfr = [{"ns": None, "success": False, "error": "dig_not_available"}]

    # Reverse DNS over discovered IPs (from A/AAAA answers).
    discovered_ips: List[str] = []
    for rt in ("A", "AAAA"):
        for val in results.get(rt, []):
            try:
                ipaddress.ip_address(val)
                discovered_ips.append(val)
            except Exception:
                continue
    discovered_ips = sorted(list(dict.fromkeys(discovered_ips)))  # stable unique

    reverse_dns = {}
    for ip_str in discovered_ips[:50]:
        reverse_dns[ip_str] = reverse_dns_lookup(ip_str, server=server)

    reverse_sweep = {"enabled": False, "cidr": reverse_cidr, "max": reverse_max, "results": {}, "hits": 0}
    if reverse_cidr:
        # Guardrail: PTR sweeps are only allowed on private CIDRs.
        ensure_private_target(reverse_cidr)
        reverse_sweep["enabled"] = True
        try:
            net = ipaddress.ip_network(reverse_cidr, strict=False)
            limit = max(1, min(int(reverse_max), 4096))
            for ip in list(net.hosts())[:limit]:
                ip_str = str(ip)
                ans = reverse_dns_lookup(ip_str, server=server)
                if ans:
                    reverse_sweep["results"][ip_str] = ans
        except Exception:
            reverse_sweep["results"] = {}
        reverse_sweep["hits"] = len(reverse_sweep["results"])

    return {
        "technique": "dns_enumeration",
        "domain": domain,
        "server": server,
        "records": results,
        "axfr_attempts": axfr,
        "discovered_ips": discovered_ips,
        "reverse_dns": reverse_dns,
        "reverse_sweep": reverse_sweep,
        "reverse_dns_note": "Reverse sweeps are restricted to private CIDRs and capped to avoid accidental large-scale scanning.",
    }


def passive_dns_monitor(interface: str, duration: int = 60) -> Dict[str, object]:
    promisc_before = promisc_flag_on_interface(interface)
    tx_before = tx_packets_on_interface(interface)

    queries = []
    domains = {}

    def handler(pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qd:
            try:
                qn = pkt[DNS].qd.qname
                if isinstance(qn, bytes):
                    qn = qn.decode("utf-8", errors="ignore")
                qn = str(qn).rstrip(".")
                src = pkt[IP].src if pkt.haslayer(IP) else ""
                queries.append({"src_ip": src, "domain": qn, "ts": utc_now_iso()})
                domains[qn] = domains.get(qn, 0) + 1
            except Exception:
                pass

    sniff(
        iface=interface,
        filter="udp port 53",
        prn=handler,
        store=False,
        timeout=duration,
        promisc=True,
    )

    promisc_after = promisc_flag_on_interface(interface)
    tx_after = tx_packets_on_interface(interface)
    tx_delta = (tx_after - tx_before) if (tx_before >= 0 and tx_after >= 0) else None

    top = sorted(domains.items(), key=lambda x: -x[1])[:25]

    return {
        "technique": "passive_dns_monitor",
        "interface": interface,
        "duration_seconds": duration,
        "promiscuous_mode_requested": True,
        "promiscuous_flag_before": promisc_before,
        "promiscuous_flag_after": promisc_after,
        "query_count": len(queries),
        "top_domains": top,
        "zero_transmit_verification": {
            "tx_before": tx_before,
            "tx_after": tx_after,
            "tx_delta": tx_delta,
            "note": "Tool sends no packets; TX delta may include background system traffic.",
        },
        "queries": queries[-200:],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Module 5: application fingerprinting")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_banner = sub.add_parser("banner")
    p_banner.add_argument("--host", required=True)
    p_banner.add_argument("--ports", default="21,22,25,80,443")
    p_banner.add_argument("--timeout", type=float, default=2.0)

    p_tls = sub.add_parser("tls")
    p_tls.add_argument("--host", required=True)
    p_tls.add_argument("--port", type=int, default=443)

    p_http = sub.add_parser("http")
    p_http.add_argument("--host", required=True)
    p_http.add_argument("--port", type=int, default=80)
    p_http.add_argument("--tls", action="store_true")

    p_tcpfp = sub.add_parser("tcpfp")
    p_tcpfp.add_argument("--host", required=True)
    p_tcpfp.add_argument("--dport", type=int, default=80)

    p_dns = sub.add_parser("dns")
    p_dns.add_argument("--domain", required=True)
    p_dns.add_argument("--server", default="8.8.8.8")
    p_dns.add_argument("--reverse-cidr", default="", help="Optional private CIDR for PTR sweep (lab only)")
    p_dns.add_argument("--reverse-max", type=int, default=256, help="Max PTR lookups for reverse sweep")

    p_pdns = sub.add_parser("passive-dns")
    p_pdns.add_argument("--interface", required=True)
    p_pdns.add_argument("--duration", type=int, default=60)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    session = new_session_id(f"mod5-{args.mode}")
    started_at = utc_now_iso()
    scanner_local_ip = infer_local_ip()

    if args.mode == "banner":
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        result = banner_grabbing(args.host, ports, timeout=args.timeout)
    elif args.mode == "tls":
        result = tls_certificate_inspection(args.host, port=args.port)
    elif args.mode == "http":
        result = http_header_analysis(args.host, port=args.port, use_tls=bool(args.tls))
    elif args.mode == "tcpfp":
        result = tcp_stack_fingerprint(args.host, dport=args.dport)
    elif args.mode == "dns":
        # Domain can be public; rubric says public DNS. Still safe to query. No private restriction.
        result = dns_enumeration(
            args.domain,
            server=args.server,
            reverse_cidr=(args.reverse_cidr or None),
            reverse_max=int(args.reverse_max or 256),
        )
    elif args.mode == "passive-dns":
        result = passive_dns_monitor(args.interface, duration=args.duration)
    else:
        raise ValueError("Unknown mode")

    finished_at = utc_now_iso()
    out = write_json_log("mod5", session, {"started_at": started_at, "finished_at": finished_at, "scanner_local_ip": scanner_local_ip, "result": result})
    print(f"[mod5] {args.mode} complete. log={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
