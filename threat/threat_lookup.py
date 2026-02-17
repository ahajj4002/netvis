#!/usr/bin/env python3
"""Threat intelligence helpers (NIP extensions).

Implements:
- threat.cve_lookup (NVD API lookup by product/version keyword)
- threat.ip_reputation (local feed match + GeoIP-lite placeholder)
- threat.domain_reputation (entropy + local feed match)
- threat.feed_sync (local feed merge + retroactive matching helper)

These are intentionally lab-friendly and avoid external paid services.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_json_load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _safe_json_dump(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = float(len(s))
    e = 0.0
    for v in c.values():
        p = float(v) / n
        e -= p * math.log(p, 2)
    return float(e)


def cve_lookup(product: str, version: str, *, max_results: int = 20, api_key: str = "") -> Dict[str, object]:
    """Query NVD CVE API by keyword (product + version)."""
    p = str(product or "").strip()
    v = str(version or "").strip()
    if not p:
        return {"ok": False, "error": "product_required", "cves": []}
    keyword = f"{p} {v}".strip()
    qs = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": int(max(1, min(200, max_results)))})
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{qs}"

    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
        data = json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception as e:
        return {"ok": False, "error": str(e), "query": keyword, "url": url, "cves": []}

    out = []
    vulns = data.get("vulnerabilities") or []
    for item in vulns:
        c = (item or {}).get("cve") or {}
        cve_id = str(c.get("id") or "")
        if not cve_id:
            continue
        desc = ""
        for d in c.get("descriptions") or []:
            if str(d.get("lang") or "").lower() == "en":
                desc = str(d.get("value") or "")
                break
        cvss = 0.0
        sev = ""
        try:
            metrics = c.get("metrics") or {}
            # Prefer v3.1, then v3.0, then v2.
            if metrics.get("cvssMetricV31"):
                m = metrics["cvssMetricV31"][0]["cvssData"]
                cvss = float(m.get("baseScore") or 0.0)
                sev = str(m.get("baseSeverity") or "")
            elif metrics.get("cvssMetricV30"):
                m = metrics["cvssMetricV30"][0]["cvssData"]
                cvss = float(m.get("baseScore") or 0.0)
                sev = str(m.get("baseSeverity") or "")
            elif metrics.get("cvssMetricV2"):
                m = metrics["cvssMetricV2"][0]["cvssData"]
                cvss = float(m.get("baseScore") or 0.0)
                sev = str(m.get("baseSeverity") or "")
        except Exception:
            pass
        out.append(
            {
                "cve_id": cve_id,
                "published": c.get("published"),
                "last_modified": c.get("lastModified"),
                "cvss": cvss,
                "severity": sev,
                "description": desc[:400],
            }
        )
    out.sort(key=lambda r: -float(r.get("cvss") or 0.0))
    return {"ok": True, "query": keyword, "url": url, "count": len(out), "cves": out[: int(max_results)]}


def ip_reputation_check(ips: List[str], indicators: dict) -> Dict[str, object]:
    ip_set = set(str(i).strip() for i in (ips or []) if str(i).strip())
    bad_ips = set(str(i).strip() for i in (indicators.get("ips") or []) if str(i).strip())
    matches = sorted(list(ip_set & bad_ips))
    rows = [{"ip": ip, "match": True, "source": "local_indicator_feed"} for ip in matches]
    return {"ok": True, "total": len(ip_set), "matches": rows, "geo_data": []}


def domain_reputation_check(domains: List[str], indicators: dict, *, dga_threshold: float = 0.75) -> Dict[str, object]:
    doms = [str(d).strip().lower().strip(".") for d in (domains or []) if str(d).strip()]
    bad_domains = set(str(d).strip().lower().strip(".") for d in (indicators.get("domains") or []) if str(d).strip())

    matches = []
    dga_scores = []
    for d in doms:
        if d in bad_domains:
            matches.append({"domain": d, "match": True, "source": "local_indicator_feed"})
        left = d.split(".")[0] if "." in d else d
        e = _entropy(left)
        ln = len(left)
        score = 0.0
        if e >= 3.5:
            score += 0.5
        if ln >= 20:
            score += 0.3
        if re.search(r"[0-9]", left):
            score += 0.2
        score = max(0.0, min(score, 1.0))
        if score >= float(dga_threshold):
            dga_scores.append({"domain": d, "score": score, "entropy": e, "left_len": ln})

    return {"ok": True, "total": len(doms), "matches": matches, "dga_scores": dga_scores}


def feed_sync(
    *,
    base_feed_path: Path,
    additional_feed_paths: List[Path],
    retroactive_ips: List[str],
    retroactive_domains: List[str],
) -> Dict[str, object]:
    """Merge local feeds and run retroactive matching on provided historical indicators."""
    base = _safe_json_load(base_feed_path)
    merged_ips = set(str(i).strip() for i in (base.get("ips") or []) if str(i).strip())
    merged_domains = set(str(d).strip().lower().strip(".") for d in (base.get("domains") or []) if str(d).strip())

    loaded = []
    for p in additional_feed_paths or []:
        obj = _safe_json_load(p)
        ips = set(str(i).strip() for i in (obj.get("ips") or []) if str(i).strip())
        doms = set(str(d).strip().lower().strip(".") for d in (obj.get("domains") or []) if str(d).strip())
        merged_ips |= ips
        merged_domains |= doms
        loaded.append({"path": str(p), "ips": len(ips), "domains": len(doms)})

    merged = {
        "generated_at": _utc_now_iso(),
        "ips": sorted(list(merged_ips)),
        "domains": sorted(list(merged_domains)),
        "sources": [{"path": str(base_feed_path), "ips": len(base.get("ips") or []), "domains": len(base.get("domains") or [])}] + loaded,
    }
    _safe_json_dump(base_feed_path, merged)

    retro_ips = set(str(i).strip() for i in (retroactive_ips or []) if str(i).strip())
    retro_doms = set(str(d).strip().lower().strip(".") for d in (retroactive_domains or []) if str(d).strip())
    ip_matches = sorted(list(retro_ips & merged_ips))
    dom_matches = sorted(list(retro_doms & merged_domains))

    return {
        "ok": True,
        "base_feed_path": str(base_feed_path),
        "indicators_updated": {"ips": len(merged_ips), "domains": len(merged_domains)},
        "sources_loaded": merged.get("sources") or [],
        "retroactive_matches": {"ips": ip_matches, "domains": dom_matches, "total": len(ip_matches) + len(dom_matches)},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Threat intel helpers")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("cve-lookup")
    p1.add_argument("--product", required=True)
    p1.add_argument("--version", default="")
    p1.add_argument("--max-results", type=int, default=20)
    p1.add_argument("--api-key", default=os.environ.get("NVD_API_KEY", ""))

    args = parser.parse_args()
    if args.cmd == "cve-lookup":
        r = cve_lookup(args.product, args.version, max_results=int(args.max_results), api_key=str(args.api_key or ""))
        print(json.dumps(r, indent=2))
        return 0
    raise SystemExit(2)


if __name__ == "__main__":
    raise SystemExit(main())

