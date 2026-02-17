#!/usr/bin/env python3
"""Module 7: NetFlow-based rate/pattern detection (NetVis toolkit).

This is a lab-side detector (not a scanner). It listens for NetFlow v5 exports and
emits timestamped alerts with simple classifications:
- port_scan: many unique destination ports from a single source within a time window
- horizontal_scan: many unique destination IPs for a single destination port
- long_flow: unusually long flows (exporter uptime-derived)

Outputs structured JSON logs under logs/mod7/.
"""

from __future__ import annotations

import argparse
import socket
import struct
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from toolkit.utils import new_session_id, utc_now_iso, write_json_log


@dataclass
class NetFlowV5Header:
    version: int
    count: int
    sys_uptime_ms: int
    unix_secs: int
    unix_nsecs: int
    flow_sequence: int
    engine_type: int
    engine_id: int
    sampling_interval: int


@dataclass
class NetFlowV5Record:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    first_ms: int
    last_ms: int
    tcp_flags: int


def parse_netflow_v5(data: bytes) -> Tuple[NetFlowV5Header | None, List[NetFlowV5Record]]:
    if len(data) < 24:
        return None, []
    try:
        version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, eng_type, eng_id, samp = struct.unpack(
            "!HHIIIIBBH", data[:24]
        )
    except Exception:
        return None, []
    if version != 5 or count <= 0:
        return None, []

    hdr = NetFlowV5Header(
        version=int(version),
        count=int(count),
        sys_uptime_ms=int(sys_uptime),
        unix_secs=int(unix_secs),
        unix_nsecs=int(unix_nsecs),
        flow_sequence=int(flow_seq),
        engine_type=int(eng_type),
        engine_id=int(eng_id),
        sampling_interval=int(samp),
    )

    records: List[NetFlowV5Record] = []
    offset = 24
    rec_fmt = "!IIIHHIIIIHHBBBBHHBBH"
    rec_len = struct.calcsize(rec_fmt)  # 48
    for _ in range(hdr.count):
        if offset + rec_len > len(data):
            break
        rec = data[offset : offset + rec_len]
        try:
            (
                srcaddr,
                dstaddr,
                _nexthop,
                _input,
                _output,
                dpkts,
                doctets,
                first,
                last,
                sport,
                dport,
                _pad1,
                tcp_flags,
                prot,
                _tos,
                _src_as,
                _dst_as,
                _src_mask,
                _dst_mask,
                _pad2,
            ) = struct.unpack(rec_fmt, rec)
        except Exception:
            break

        records.append(
            NetFlowV5Record(
                src_ip=socket.inet_ntoa(struct.pack("!I", srcaddr)),
                dst_ip=socket.inet_ntoa(struct.pack("!I", dstaddr)),
                src_port=int(sport),
                dst_port=int(dport),
                protocol=int(prot),
                packets=int(dpkts),
                bytes=int(doctets),
                first_ms=int(first),
                last_ms=int(last),
                tcp_flags=int(tcp_flags),
            )
        )
        offset += rec_len

    return hdr, records


def flow_times_utc(hdr: NetFlowV5Header, rec: NetFlowV5Record) -> Tuple[str, str]:
    """Convert exporter-uptime timestamps to UTC ISO strings (best-effort)."""
    export_time = hdr.unix_secs + (hdr.unix_nsecs / 1_000_000_000.0)
    boot_time = export_time - (hdr.sys_uptime_ms / 1000.0)
    start = boot_time + (rec.first_ms / 1000.0)
    end = boot_time + (rec.last_ms / 1000.0)
    return (
        datetime.fromtimestamp(start, tz=timezone.utc).isoformat(),
        datetime.fromtimestamp(end, tz=timezone.utc).isoformat(),
    )


def netflow_detect(
    listen_host: str,
    listen_port: int,
    duration: int,
    window_seconds: int,
    unique_port_threshold: int,
    unique_dst_threshold: int,
    long_flow_ms: int,
) -> Dict[str, object]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_host, listen_port))
    sock.settimeout(1.0)

    start = time.time()
    alerts: List[Dict[str, object]] = []

    # Sliding-window state (keyed by src_ip).
    # entries: list of (ts, dst_ip, dst_port)
    recent: Dict[str, List[Tuple[float, str, int]]] = {}
    last_alert_ts: Dict[Tuple[str, str], float] = {}  # (src, type) -> last time

    records_total = 0
    packets_total = 0
    bytes_total = 0

    def should_emit(key: Tuple[str, str], now: float, cooldown: float = 3.0) -> bool:
        last = last_alert_ts.get(key, 0.0)
        if now - last >= cooldown:
            last_alert_ts[key] = now
            return True
        return False

    while time.time() - start < duration:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            continue

        hdr, recs = parse_netflow_v5(data)
        if not hdr:
            continue

        now = time.time()
        for r in recs:
            records_total += 1
            packets_total += int(r.packets)
            bytes_total += int(r.bytes)

            start_iso, end_iso = flow_times_utc(hdr, r)

            # Long flow detection (exporter uptime units).
            dur_ms = max(0, int(r.last_ms) - int(r.first_ms))
            if dur_ms >= long_flow_ms and should_emit((r.src_ip, "long_flow"), now, cooldown=2.0):
                alerts.append(
                    {
                        "ts": utc_now_iso(),
                        "type": "long_flow",
                        "src_ip": r.src_ip,
                        "dst_ip": r.dst_ip,
                        "dst_port": r.dst_port,
                        "protocol": r.protocol,
                        "flow_start_utc": start_iso,
                        "flow_end_utc": end_iso,
                        "flow_duration_ms": dur_ms,
                        "bytes": r.bytes,
                        "packets": r.packets,
                    }
                )

            # Update sliding window for scan detection.
            lst = recent.setdefault(r.src_ip, [])
            lst.append((now, r.dst_ip, int(r.dst_port)))
            cutoff = now - float(window_seconds)
            # prune
            while lst and lst[0][0] < cutoff:
                lst.pop(0)

            # Unique dst ports per src within window (vertical scan / port scan)
            unique_ports = {p for _t, _dip, p in lst}
            if len(unique_ports) >= unique_port_threshold and should_emit((r.src_ip, "port_scan"), now):
                alerts.append(
                    {
                        "ts": utc_now_iso(),
                        "type": "port_scan",
                        "src_ip": r.src_ip,
                        "window_seconds": window_seconds,
                        "unique_dst_ports": len(unique_ports),
                        "ports_sample": sorted(list(unique_ports))[:40],
                    }
                )

            # Unique dst IPs per (src, dst_port) within window (horizontal scan)
            port_to_dsts: Dict[int, set] = {}
            for _t, dip, dp in lst:
                port_to_dsts.setdefault(dp, set()).add(dip)
            for dp, dsts in port_to_dsts.items():
                if len(dsts) >= unique_dst_threshold and should_emit((r.src_ip, f"horizontal_{dp}"), now):
                    alerts.append(
                        {
                            "ts": utc_now_iso(),
                            "type": "horizontal_scan",
                            "src_ip": r.src_ip,
                            "dst_port": dp,
                            "window_seconds": window_seconds,
                            "unique_dst_hosts": len(dsts),
                            "dst_hosts_sample": sorted(list(dsts))[:40],
                        }
                    )

    sock.close()

    return {
        "technique": "netflow_v5_detection",
        "listen": {"host": listen_host, "port": listen_port},
        "duration_seconds": duration,
        "window_seconds": window_seconds,
        "thresholds": {
            "unique_port_threshold": unique_port_threshold,
            "unique_dst_threshold": unique_dst_threshold,
            "long_flow_ms": long_flow_ms,
        },
        "records_total": records_total,
        "packets_total": packets_total,
        "bytes_total": bytes_total,
        "alert_count": len(alerts),
        "alerts": alerts[-500:],
        "note": "Use during Modules 2–4 scans to compare scan timing profiles vs. flow-based detection.",
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Module 7: NetFlow v5 detection (alerting).")
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--listen-port", type=int, default=2055)
    p.add_argument("--duration", type=int, default=60)
    p.add_argument("--window-seconds", type=int, default=10)
    p.add_argument("--unique-port-threshold", type=int, default=20)
    p.add_argument("--unique-dst-threshold", type=int, default=15)
    p.add_argument("--long-flow-ms", type=int, default=30000)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    session = new_session_id("mod7-netflow-detect")
    started_at = utc_now_iso()

    result = netflow_detect(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        duration=args.duration,
        window_seconds=args.window_seconds,
        unique_port_threshold=args.unique_port_threshold,
        unique_dst_threshold=args.unique_dst_threshold,
        long_flow_ms=args.long_flow_ms,
    )

    finished_at = utc_now_iso()
    out = write_json_log("mod7", session, {"started_at": started_at, "finished_at": finished_at, "result": result})
    print(f"[mod7] netflow detection complete. alerts={result['alert_count']} log={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

