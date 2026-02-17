#!/usr/bin/env python3
"""Multicast/broadcast discovery protocols (NIP extensions).

Implements:
- discovery.mdns (active)
- discovery.mdns_passive (passive)
- discovery.ssdp_upnp (active)
- discovery.nbns (active)
- discovery.llmnr (passive)
- discovery.wsd (active)

Notes:
- These techniques can reveal rich asset identity info (hostnames, models, services)
  that port scanning alone won't discover.
- Active probes are designed to be low-impact (small number of multicast/broadcast frames).
"""

from __future__ import annotations

import argparse
import socket
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from scapy.all import (
    AsyncSniffer,
    DNS,
    DNSQR,
    Ether,
    IP,
    UDP,
    conf,
    send,
)

from scapy.layers.netbios import (
    NBNSHeader,
    NBNSNodeStatusRequest,
    NBNSNodeStatusResponse,
    NBNSNodeStatusResponseService,
)

from toolkit.utils import elapsed_ms, new_session_id, utc_now_iso, write_json_log

conf.verb = 0


def _safe_decode(v) -> str:
    try:
        if isinstance(v, (bytes, bytearray)):
            return v.decode("utf-8", errors="ignore").strip()
        return str(v).strip()
    except Exception:
        return ""


# ------------------------------
# mDNS
# ------------------------------

def mdns_discovery(interface: str, *, timeout: float = 2.5, max_service_types: int = 24, max_instances: int = 40) -> Dict[str, object]:
    """Active mDNS service discovery via _services._dns-sd._udp.local PTR query."""
    iface = str(interface or conf.iface)
    started_at = utc_now_iso()
    start = time.time()

    # Store observed records by (name,type)->values
    records: List[dict] = []
    service_types: List[str] = []

    def handler(pkt):
        try:
            if not pkt.haslayer(DNS):
                return
            dns = pkt[DNS]
            if int(getattr(dns, "qr", 0) or 0) != 1:
                return
            # answers + additional
            for rrset in (getattr(dns, "an", None), getattr(dns, "ar", None)):
                rr = rrset
                while rr:
                    try:
                        name = _safe_decode(getattr(rr, "rrname", b""))
                        rtype = int(getattr(rr, "type", 0) or 0)
                        rdata = getattr(rr, "rdata", None)
                        val = _safe_decode(rdata)
                        rec = {"name": name, "type": rtype, "value": val}
                        records.append(rec)
                        # PTR to _services._dns-sd._udp.local returns service types.
                        if name.endswith("_services._dns-sd._udp.local.") and rtype == 12 and val:
                            service_types.append(val)
                    except Exception:
                        pass
                    rr = getattr(rr, "payload", None)
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="udp port 5353", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        qname = "_services._dns-sd._udp.local"
        pkt = IP(dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(rd=0, qd=DNSQR(qname=qname, qtype="PTR"))
        # Two tries helps on noisy lab segments.
        send(pkt, iface=iface, count=2, inter=0.2, verbose=0)
        time.sleep(max(0.2, float(timeout)))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    # Normalize and cap.
    service_types = sorted(list({s for s in service_types if s}))[: max(0, int(max_service_types))]
    duration = max(0.0001, time.time() - start)

    return {
        "technique": "mdns_discovery",
        "interface": iface,
        "started_at": started_at,
        "scan_duration_seconds": duration,
        "service_types": service_types,
        "records_sample": records[: max_instances],
        "records_total": len(records),
    }


def mdns_passive_monitor(interface: str, duration: int) -> Dict[str, object]:
    """Passive mDNS monitor on UDP/5353."""
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    start = time.time()

    hostnames = set()
    services = []
    frames = 0

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(DNS):
                return
            frames += 1
            dns = pkt[DNS]
            # collect answer names as hostnames
            rr = getattr(dns, "an", None)
            while rr:
                try:
                    name = _safe_decode(getattr(rr, "rrname", b""))
                    rtype = int(getattr(rr, "type", 0) or 0)
                    val = _safe_decode(getattr(rr, "rdata", None))
                    if name.endswith(".local.") and name.count(".") >= 2:
                        hostnames.add(name.rstrip("."))
                    if rtype in (12, 16, 33):  # PTR, TXT, SRV
                        services.append({"name": name, "type": rtype, "value": val})
                except Exception:
                    pass
                rr = getattr(rr, "payload", None)
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="udp port 5353", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    return {
        "technique": "mdns_passive_monitor",
        "interface": iface,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "frames_observed": frames,
        "hostnames": sorted(list(hostnames))[:200],
        "services_sample": services[:400],
        "services_total": len(services),
    }


# ------------------------------
# SSDP / UPnP
# ------------------------------

def _parse_ssdp_response(resp: str) -> Dict[str, str]:
    out = {}
    lines = [ln.strip() for ln in (resp or "").split("\r\n") if ln.strip()]
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        out[k.strip().lower()] = v.strip()
    return out


def _fetch_upnp_description(url: str, timeout: float = 2.0) -> Dict[str, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            xml = r.read()
        root = ET.fromstring(xml)
        # UPnP device description is usually under /root/device/*
        device = None
        for el in root.iter():
            if el.tag.endswith("device"):
                device = el
                break
        if device is None:
            return {}

        def find_text(tag: str) -> str:
            for el in device.iter():
                if el.tag.endswith(tag):
                    return (el.text or "").strip()
            return ""

        return {
            "friendlyName": find_text("friendlyName"),
            "manufacturer": find_text("manufacturer"),
            "modelName": find_text("modelName"),
            "modelNumber": find_text("modelNumber"),
            "serialNumber": find_text("serialNumber"),
            "UDN": find_text("UDN"),
        }
    except Exception:
        return {}


def ssdp_upnp_discovery(interface: str, *, timeout: float = 3.0, fetch_description: bool = True) -> Dict[str, object]:
    """Active SSDP M-SEARCH and optional UPnP description fetch."""
    iface = str(interface or conf.iface)
    started_at = utc_now_iso()
    start = time.time()

    # Multicast socket
    msg = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 1",
            "ST: ssdp:all",
            "",
            "",
        ]
    ).encode("utf-8", errors="ignore")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(max(0.2, float(timeout)))
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
    except Exception:
        pass

    responses = []
    seen = set()
    end = time.time() + max(0.2, float(timeout))
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            break
        except Exception:
            break
        ip = addr[0]
        txt = data.decode("utf-8", errors="ignore")
        hdr = _parse_ssdp_response(txt)
        key = (ip, hdr.get("usn", ""), hdr.get("location", ""))
        if key in seen:
            continue
        seen.add(key)
        row = {
            "ip": ip,
            "st": hdr.get("st", ""),
            "usn": hdr.get("usn", ""),
            "server": hdr.get("server", ""),
            "location": hdr.get("location", ""),
            "cache_control": hdr.get("cache-control", ""),
        }
        if fetch_description and row["location"].startswith("http"):
            row["description"] = _fetch_upnp_description(row["location"], timeout=2.0)
        responses.append(row)

    try:
        sock.close()
    except Exception:
        pass

    duration = max(0.0001, time.time() - start)
    return {
        "technique": "ssdp_upnp_discovery",
        "interface": iface,
        "started_at": started_at,
        "scan_duration_seconds": duration,
        "devices": responses,
        "count": len(responses),
    }


# ------------------------------
# NBNS (NetBIOS)
# ------------------------------

def nbns_node_status_query(hosts: List[str], *, timeout: float = 1.2) -> Dict[str, object]:
    """Send NBNS Node Status Request to hosts and parse names/MAC.

    Implemented via standard UDP sockets (no raw sockets), so it does not require root.
    """
    started_at = utc_now_iso()
    start = time.time()
    results = []

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(0.2, float(timeout)))

    for h in hosts or []:
        h = str(h).strip()
        if not h:
            continue
        try:
            # NBNS request payload.
            payload = bytes(NBNSHeader(NAME_TRN_ID=int(time.time() * 1000) & 0xFFFF) / NBNSNodeStatusRequest())
            sock.sendto(payload, (h, 137))
        except Exception:
            continue

    end = time.time() + max(0.2, float(timeout))
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            break
        except Exception:
            break
        ip = str(addr[0] or "")
        if not data:
            continue
        try:
            pkt = NBNSHeader(data)
        except Exception:
            continue
        if not pkt.haslayer(NBNSNodeStatusResponse):
            continue
        resp = pkt[NBNSNodeStatusResponse]
        mac = _safe_decode(getattr(resp, "MAC_ADDRESS", "")) or ""
        names = []
        try:
            for s in getattr(resp, "NODE_NAME", []) or []:
                if isinstance(s, NBNSNodeStatusResponseService):
                    names.append(
                        {
                            "name": _safe_decode(getattr(s, "NETBIOS_NAME", b"")).strip(),
                            "suffix": str(getattr(s, "SUFFIX", "") or ""),
                            "flags": int(getattr(s, "NAME_FLAGS", 0) or 0),
                        }
                    )
        except Exception:
            pass
        results.append({"ip": ip, "mac": mac, "names": names})

    try:
        sock.close()
    except Exception:
        pass

    duration = max(0.0001, time.time() - start)
    return {
        "technique": "nbns_node_status_query",
        "started_at": started_at,
        "scan_duration_seconds": duration,
        "hosts": hosts or [],
        "results": results,
        "count": len(results),
        "notes": "NBNS can reveal Windows hostnames/workgroup names; logged-in user enumeration typically requires SMB.",
    }


# ------------------------------
# LLMNR (passive)
# ------------------------------

def llmnr_passive_monitor(interface: str, duration: int) -> Dict[str, object]:
    """Passive LLMNR monitor (UDP/5355)."""
    iface = str(interface or conf.iface)
    dur = max(1, int(duration))
    start = time.time()
    frames = 0
    hostnames = set()
    failed_lookups = []

    def handler(pkt):
        nonlocal frames
        try:
            if not pkt.haslayer(DNS):
                return
            frames += 1
            dns = pkt[DNS]
            if dns.qd:
                qname = _safe_decode(getattr(dns.qd, "qname", b""))
                if qname:
                    failed_lookups.append({"qname": qname, "src": pkt[IP].src if pkt.haslayer(IP) else "", "ts": utc_now_iso()})
            # Hostnames sometimes appear in answers
            rr = getattr(dns, "an", None)
            while rr:
                try:
                    name = _safe_decode(getattr(rr, "rrname", b""))
                    if name:
                        hostnames.add(name.rstrip("."))
                except Exception:
                    pass
                rr = getattr(rr, "payload", None)
        except Exception:
            return

    sniffer = AsyncSniffer(iface=iface, filter="udp port 5355", prn=handler, store=False, promisc=True)
    try:
        sniffer.start()
        time.sleep(float(dur))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    return {
        "technique": "llmnr_passive_monitor",
        "interface": iface,
        "capture_duration_seconds": dur,
        "capture_elapsed_ms": elapsed_ms(start),
        "frames_observed": frames,
        "hostnames": sorted(list(hostnames))[:200],
        "failed_lookups_sample": failed_lookups[:200],
        "alerts": {
            "llmnr_poison_suspected": False,
            "notes": "This implementation is passive only; poisoning detection requires tracking unexpected responders.",
        },
    }


# ------------------------------
# WS-Discovery (active)
# ------------------------------

_WSD_PROBE = """<?xml version="1.0" encoding="utf-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
  xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
  xmlns:dn="http://www.w3.org/2005/08/addressing">
  <e:Header>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
    <w:MessageID>uuid:{msgid}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
  </e:Header>
  <e:Body>
    <d:Probe/>
  </e:Body>
</e:Envelope>
"""


def wsd_discovery(interface: str, *, timeout: float = 3.0) -> Dict[str, object]:
    """Active WS-Discovery probe on 239.255.255.250:3702."""
    iface = str(interface or conf.iface)
    started_at = utc_now_iso()
    start = time.time()

    msgid = f"{int(time.time()*1000)}"
    payload = _WSD_PROBE.format(msgid=msgid).encode("utf-8", errors="ignore")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(max(0.2, float(timeout)))
    try:
        sock.sendto(payload, ("239.255.255.250", 3702))
    except Exception:
        pass

    devices = []
    seen = set()
    end = time.time() + max(0.2, float(timeout))
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            break
        except Exception:
            break
        ip = addr[0]
        xml = data.decode("utf-8", errors="ignore")
        if (ip, xml[:80]) in seen:
            continue
        seen.add((ip, xml[:80]))
        # Best-effort parse for Types and XAddrs.
        types = ""
        xaddrs = ""
        try:
            root = ET.fromstring(xml)
            for el in root.iter():
                if el.tag.endswith("Types"):
                    types = (el.text or "").strip()
                if el.tag.endswith("XAddrs"):
                    xaddrs = (el.text or "").strip()
        except Exception:
            pass
        devices.append({"ip": ip, "types": types, "xaddrs": xaddrs})

    try:
        sock.close()
    except Exception:
        pass

    duration = max(0.0001, time.time() - start)
    return {
        "technique": "wsd_discovery",
        "interface": iface,
        "started_at": started_at,
        "scan_duration_seconds": duration,
        "devices": devices,
        "count": len(devices),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Multicast/broadcast discovery techniques")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_m = sub.add_parser("mdns", help="Active mDNS discovery")
    p_m.add_argument("--interface", default=str(conf.iface))
    p_m.add_argument("--timeout", type=float, default=2.5)

    p_mp = sub.add_parser("mdns-passive", help="Passive mDNS monitor")
    p_mp.add_argument("--interface", default=str(conf.iface))
    p_mp.add_argument("--duration", type=int, default=60)

    p_s = sub.add_parser("ssdp", help="SSDP/UPnP discovery")
    p_s.add_argument("--interface", default=str(conf.iface))
    p_s.add_argument("--timeout", type=float, default=3.0)
    p_s.add_argument("--no-fetch", action="store_true", help="Do not fetch UPnP description XML")

    p_n = sub.add_parser("nbns", help="NBNS node status query")
    p_n.add_argument("--hosts", default="", help="Comma-separated host list")
    p_n.add_argument("--timeout", type=float, default=1.2)

    p_l = sub.add_parser("llmnr-passive", help="LLMNR passive monitor")
    p_l.add_argument("--interface", default=str(conf.iface))
    p_l.add_argument("--duration", type=int, default=60)

    p_w = sub.add_parser("wsd", help="WS-Discovery probe")
    p_w.add_argument("--interface", default=str(conf.iface))
    p_w.add_argument("--timeout", type=float, default=3.0)

    args = parser.parse_args()

    if args.cmd == "mdns":
        result = mdns_discovery(args.interface, timeout=float(args.timeout))
        sid = new_session_id("discovery-mdns")
    elif args.cmd == "mdns-passive":
        result = mdns_passive_monitor(args.interface, int(args.duration))
        sid = new_session_id("discovery-mdns-passive")
    elif args.cmd == "ssdp":
        result = ssdp_upnp_discovery(args.interface, timeout=float(args.timeout), fetch_description=(not bool(args.no_fetch)))
        sid = new_session_id("discovery-ssdp")
    elif args.cmd == "nbns":
        hosts = [h.strip() for h in str(args.hosts or "").split(",") if h.strip()]
        result = nbns_node_status_query(hosts, timeout=float(args.timeout))
        sid = new_session_id("discovery-nbns")
    elif args.cmd == "llmnr-passive":
        result = llmnr_passive_monitor(args.interface, int(args.duration))
        sid = new_session_id("discovery-llmnr-passive")
    elif args.cmd == "wsd":
        result = wsd_discovery(args.interface, timeout=float(args.timeout))
        sid = new_session_id("discovery-wsd")
    else:
        raise SystemExit(2)

    write_json_log("discovery", sid, {"result": result})
    print(sid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
