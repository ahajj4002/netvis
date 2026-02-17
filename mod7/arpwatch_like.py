#!/usr/bin/env python3
"""Module 7: ARP anomaly monitoring (arpwatch-style) for Module 1 techniques.

- Observes ARP traffic passively
- Alerts on new IP->MAC bindings and MAC changes

Outputs structured JSON logs under logs/mod7/.
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass, asdict
from typing import Dict, List

from scapy.all import ARP, sniff, conf

from toolkit.utils import infer_local_ip, new_session_id, promisc_flag_on_interface, tx_packets_on_interface, utc_now_iso, write_json_log

conf.verb = 0


@dataclass
class ArpEvent:
    ts: str
    event: str  # new_binding | mac_change
    ip: str
    mac: str
    prev_mac: str = ""


def arpwatch_monitor(interface: str, duration: int = 300) -> Dict[str, object]:
    table: Dict[str, str] = {}
    events: List[ArpEvent] = []

    promisc_before = promisc_flag_on_interface(interface)
    tx_before = tx_packets_on_interface(interface)

    start = time.time()

    def handler(pkt):
        if ARP not in pkt:
            return
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        now = utc_now_iso()

        if ip not in table:
            table[ip] = mac
            events.append(ArpEvent(ts=now, event="new_binding", ip=ip, mac=mac))
        elif table[ip] != mac:
            prev = table[ip]
            table[ip] = mac
            events.append(ArpEvent(ts=now, event="mac_change", ip=ip, mac=mac, prev_mac=prev))

    sniff(
        iface=interface,
        filter="arp",
        prn=handler,
        store=False,
        timeout=duration,
        promisc=True,
    )

    promisc_after = promisc_flag_on_interface(interface)
    tx_after = tx_packets_on_interface(interface)
    tx_delta = (tx_after - tx_before) if (tx_before >= 0 and tx_after >= 0) else None

    return {
        "technique": "arpwatch_style_monitor",
        "interface": interface,
        "duration_seconds": duration,
        "promiscuous_mode_requested": True,
        "promiscuous_flag_before": promisc_before,
        "promiscuous_flag_after": promisc_after,
        "bindings": [{"ip": ip, "mac": mac} for ip, mac in sorted(table.items())],
        "event_count": len(events),
        "events": [asdict(e) for e in events[-200:]],
        "zero_transmit_verification": {
            "tx_before": tx_before,
            "tx_after": tx_after,
            "tx_delta": tx_delta,
            "tool_generated_packets": 0,
        },
        "coverage_notes": "Run during Module 1 active/passive to capture binding changes and randomization effects.",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Module 7: arpwatch-style ARP anomaly monitor")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--duration", type=int, default=300)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    session = new_session_id("mod7-arpwatch")
    started_at = utc_now_iso()
    scanner_local_ip = infer_local_ip()
    result = arpwatch_monitor(args.interface, duration=args.duration)
    finished_at = utc_now_iso()
    out = write_json_log("mod7", session, {"started_at": started_at, "finished_at": finished_at, "scanner_local_ip": scanner_local_ip, "result": result})
    print(f"[mod7] arpwatch monitor complete. log={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
