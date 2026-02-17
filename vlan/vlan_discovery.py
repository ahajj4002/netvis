#!/usr/bin/env python3
"""VLAN / L2 discovery (passive) (NIP extensions).

Implements:
- vlan.discovery (CDP/LLDP/DTP sniffing)

Disruptive lab-only attacks (double tagging, DTP negotiation, CAM overflow) are
intentionally not implemented.
"""

from __future__ import annotations

import argparse
import time
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

from scapy.all import AsyncSniffer, Ether, conf

# Ensure contrib layers are registered.
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPlatform, CDPMsgPortID, CDPMsgNativeVLAN, CDPMsgIPGateway, CDPMsgMgmtAddr
from scapy.contrib.lldp import LLDPDU
from scapy.contrib.dtp import DTP

from toolkit.utils import elapsed_ms, new_session_id, utc_now_iso, write_json_log

conf.verb = 0


def vlan_discovery(interface: str, duration: int) -> Dict[str, object]:
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    start = time.time()
    started_at = utc_now_iso()

    cdp = []
    lldp = []
    dtp = []
    vlan_ids = set()
    switch_models = set()
    mgmt_ips = set()
    frames = 0

    def handler(pkt):
        nonlocal frames
        frames += 1
        try:
            src_mac = str(pkt[Ether].src) if pkt.haslayer(Ether) else ""

            if pkt.haslayer(CDPv2_HDR):
                hdr = pkt[CDPv2_HDR]
                row = {"src_mac": src_mac, "ttl": int(getattr(hdr, "ttl", 0) or 0)}
                try:
                    for tlv in list(getattr(hdr, "msg", []) or []):
                        if isinstance(tlv, CDPMsgDeviceID):
                            row["device_id"] = getattr(tlv, "val", b"").decode("utf-8", errors="ignore").strip()
                        elif isinstance(tlv, CDPMsgPlatform):
                            plat = getattr(tlv, "val", b"").decode("utf-8", errors="ignore").strip()
                            row["platform"] = plat
                            if plat:
                                switch_models.add(plat)
                        elif isinstance(tlv, CDPMsgPortID):
                            row["port_id"] = getattr(tlv, "val", b"").decode("utf-8", errors="ignore").strip()
                        elif isinstance(tlv, CDPMsgNativeVLAN):
                            vid = int(getattr(tlv, "vlan", 0) or 0)
                            row["native_vlan"] = vid
                            if vid:
                                vlan_ids.add(vid)
                        elif isinstance(tlv, CDPMsgIPGateway):
                            # gateway addresses may be present as bytes; store as string best-effort
                            row["ip_gateway_raw"] = str(getattr(tlv, "addr", "") or getattr(tlv, "val", ""))
                        elif isinstance(tlv, CDPMsgMgmtAddr):
                            row["mgmt_addr_raw"] = str(getattr(tlv, "addr", "") or getattr(tlv, "val", ""))
                except Exception:
                    pass
                cdp.append(row)

            if pkt.haslayer(LLDPDU):
                # LLDP parsing in scapy is TLV-based; dump a compact representation.
                try:
                    du = pkt[LLDPDU]
                    row = {"src_mac": src_mac, "raw": du.summary()}
                    lldp.append(row)
                except Exception:
                    pass

            if pkt.haslayer(DTP):
                try:
                    d = pkt[DTP]
                    row = {"src_mac": src_mac, "raw": d.summary()}
                    dtp.append(row)
                except Exception:
                    pass
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    return {
        "technique": "vlan_discovery",
        "interface": iface,
        "started_at": started_at,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "frames_observed": frames,
        "vlan_ids": sorted(list(vlan_ids)),
        "switch_models": sorted(list(switch_models)),
        "switch_mgmt_ips": sorted(list(mgmt_ips)),
        "cdp_sample": cdp[:100],
        "lldp_sample": lldp[:100],
        "dtp_sample": dtp[:100],
        "counts": {"cdp": len(cdp), "lldp": len(lldp), "dtp": len(dtp)},
        "notes": "This is passive discovery only; lab-only VLAN hopping tests are intentionally not implemented.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="VLAN discovery (CDP/LLDP/DTP sniffing)")
    parser.add_argument("--interface", default=str(conf.iface))
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()

    result = vlan_discovery(args.interface, int(args.duration))
    sid = new_session_id("vlan-discover")
    write_json_log("vlan", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

