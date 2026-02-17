#!/usr/bin/env python3
"""WiFi passive scan technique (NIP extensions).

Implements:
- wifi.passive_scan (monitor-mode capture of beacon/probe frames)

Deauth tests are intentionally not implemented.
"""

from __future__ import annotations

import argparse
import time
from collections import defaultdict
from typing import Dict, List, Optional

from scapy.all import AsyncSniffer, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, conf

from toolkit.utils import elapsed_ms, new_session_id, utc_now_iso, write_json_log

conf.verb = 0


def _ssid_from_pkt(pkt) -> str:
    try:
        if pkt.haslayer(Dot11Elt):
            el = pkt[Dot11Elt]
            while isinstance(el, Dot11Elt):
                if int(getattr(el, "ID", -1)) == 0:
                    info = bytes(getattr(el, "info", b"") or b"")
                    return info.decode("utf-8", errors="ignore")
                el = el.payload if isinstance(el.payload, Dot11Elt) else None
    except Exception:
        pass
    return ""


def _channel_from_pkt(pkt) -> int:
    try:
        if pkt.haslayer(Dot11Elt):
            el = pkt[Dot11Elt]
            while isinstance(el, Dot11Elt):
                if int(getattr(el, "ID", -1)) == 3:  # DS Parameter Set (channel)
                    info = bytes(getattr(el, "info", b"") or b"")
                    if info:
                        return int(info[0])
                el = el.payload if isinstance(el.payload, Dot11Elt) else None
    except Exception:
        pass
    return 0


def _enc_hint(pkt) -> str:
    # Very lightweight capability hint.
    try:
        if pkt.haslayer(Dot11Beacon):
            cap = pkt[Dot11Beacon].cap
            if "privacy" in str(cap).lower():
                # Could be WEP/WPA/WPA2/WPA3 depending on RSN IE; keep generic.
                return "encrypted"
            return "open"
    except Exception:
        pass
    return "unknown"


def wifi_passive_scan(interface: str, duration: int) -> Dict[str, object]:
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    start = time.time()
    started_at = utc_now_iso()

    ssids = {}  # bssid -> details
    clients = defaultdict(set)  # client -> set(ssid/bssid hints)
    probe_history = defaultdict(set)  # client -> ssid list
    frames = 0

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(Dot11):
                return
            d11 = pkt[Dot11]
            frames += 1
            bssid = str(getattr(d11, "addr3", "") or "")
            src = str(getattr(d11, "addr2", "") or "")
            dst = str(getattr(d11, "addr1", "") or "")
            ssid = _ssid_from_pkt(pkt)
            ch = _channel_from_pkt(pkt)

            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                if bssid:
                    row = ssids.get(bssid) or {
                        "bssid": bssid,
                        "ssid": "",
                        "channel": 0,
                        "encryption": "unknown",
                        "first_seen": utc_now_iso(),
                        "last_seen": utc_now_iso(),
                        "frames": 0,
                    }
                    row["last_seen"] = utc_now_iso()
                    row["frames"] = int(row.get("frames") or 0) + 1
                    if ssid:
                        row["ssid"] = ssid
                    if ch:
                        row["channel"] = int(ch)
                    enc = _enc_hint(pkt)
                    if enc and enc != "unknown":
                        row["encryption"] = enc
                    ssids[bssid] = row

            if pkt.haslayer(Dot11ProbeReq):
                client = src
                if client:
                    if ssid:
                        probe_history[client].add(ssid)
                    if bssid:
                        clients[client].add(bssid)
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, prn=handler, store=False, monitor=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    ssid_rows = list(ssids.values())
    ssid_rows.sort(key=lambda r: (r.get("ssid") or "", r.get("bssid") or ""))
    client_rows = []
    for c, seen in clients.items():
        client_rows.append({"client_mac": c, "seen_bssids": sorted(list(seen))[:50], "probed_ssids": sorted(list(probe_history.get(c) or set()))[:100]})
    client_rows.sort(key=lambda r: r.get("client_mac") or "")

    return {
        "technique": "wifi_passive_scan",
        "interface": iface,
        "started_at": started_at,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "frames_observed": frames,
        "ssids": ssid_rows[:500],
        "bssids": [r.get("bssid") for r in ssid_rows[:500]],
        "clients": client_rows[:500],
        "probe_history": {k: sorted(list(v))[:100] for k, v in list(probe_history.items())[:500]},
        "notes": "Interface must support monitor mode and be configured appropriately for full visibility.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="WiFi passive scan")
    parser.add_argument("--interface", default=str(conf.iface))
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()

    result = wifi_passive_scan(args.interface, int(args.duration))
    sid = new_session_id("wifi-passive")
    write_json_log("wifi", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

