#!/usr/bin/env python3
"""
NetVis - Network Visualization Platform
Backend server for device discovery and traffic analysis
"""

import asyncio
import json
import subprocess
import re
import socket
import struct
import urllib.request
import sqlite3
import uuid
import os
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict, field
import threading
import time

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from nip.events import EventBus
from nip.registry import default_registry, registry_as_list
from nip.schema import TechniqueResult, Finding
from nip.brain import SituationAssessor, TechniqueSelector, StrategyPlanner, NetworkSituation
from nip.log_ingest import ingest_log_file
from nip.quality import compute_all_metrics as compute_quality_metrics

# MAC vendor OUI database (common vendors - expandable)
MAC_VENDORS = {
    "00:00:0C": "Cisco", "00:1A:2B": "Cisco", "00:1B:54": "Cisco",
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
    "00:0D:93": "Apple", "00:10:FA": "Apple", "00:11:24": "Apple", "00:14:51": "Apple",
    "00:16:CB": "Apple", "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple",
    "00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple", "00:23:DF": "Apple",
    "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple", "00:25:BC": "Apple",
    "00:26:08": "Apple", "00:26:4A": "Apple", "00:26:B0": "Apple", "00:26:BB": "Apple",
    "28:CF:DA": "Apple", "34:C0:59": "Apple", "40:6C:8F": "Apple", "44:D8:84": "Apple",
    "5C:59:48": "Apple", "60:69:44": "Apple", "68:A8:6D": "Apple", "70:56:81": "Apple",
    "78:31:C1": "Apple", "78:CA:39": "Apple", "7C:6D:62": "Apple", "80:E6:50": "Apple",
    "84:38:35": "Apple", "88:53:95": "Apple", "8C:58:77": "Apple", "90:8D:6C": "Apple",
    "98:01:A7": "Apple", "98:D6:BB": "Apple", "9C:20:7B": "Apple", "A4:5E:60": "Apple",
    "A4:D1:D2": "Apple", "AC:87:A3": "Apple", "B8:17:C2": "Apple", "B8:C7:5D": "Apple",
    "BC:3B:AF": "Apple", "BC:52:B7": "Apple", "C0:63:94": "Apple", "C8:2A:14": "Apple",
    "C8:69:CD": "Apple", "D0:23:DB": "Apple", "D4:9A:20": "Apple", "D8:30:62": "Apple",
    "DC:2B:2A": "Apple", "E0:B5:2D": "Apple", "E4:8B:7F": "Apple", "F0:B4:79": "Apple",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1A:11": "Google", "3C:5A:B4": "Google", "54:60:09": "Google", "94:EB:2C": "Google",
    "F4:F5:D8": "Google",
    "18:B4:30": "Nest Labs",
    "00:17:88": "Philips Hue",
    "00:04:20": "Roku", "B0:A7:37": "Roku", "DC:3A:5E": "Roku",
    "00:E0:4C": "Realtek",
    "FC:F1:36": "Samsung", "00:26:37": "Samsung", "00:1D:25": "Samsung", 
    "00:1E:75": "Samsung", "00:21:4C": "Samsung", "00:23:39": "Samsung",
    "00:24:54": "Samsung", "00:24:E9": "Samsung", "00:26:5D": "Samsung",
    "58:C1:7A": "Samsung", "84:25:DB": "Samsung", "90:18:7C": "Samsung",
    "00:1C:43": "Samsung", "78:47:1D": "Samsung", "78:BD:BC": "Samsung",
    "AC:5A:F0": "Samsung", "BC:44:86": "Samsung", "C0:97:27": "Samsung",
    "00:AA:70": "Intel", "00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
    "00:0C:F1": "Intel", "00:0E:0C": "Intel", "00:0E:35": "Intel", "00:12:F0": "Intel",
    "00:13:02": "Intel", "00:13:20": "Intel", "00:13:CE": "Intel", "00:13:E8": "Intel",
    "00:15:00": "Intel", "00:15:17": "Intel", "00:16:6F": "Intel", "00:16:76": "Intel",
    "00:16:EA": "Intel", "00:16:EB": "Intel", "00:18:DE": "Intel", "00:19:D1": "Intel",
    "00:19:D2": "Intel", "00:1B:21": "Intel", "00:1B:77": "Intel", "00:1C:BF": "Intel",
    "00:1C:C0": "Intel", "00:1D:E0": "Intel", "00:1D:E1": "Intel", "00:1E:64": "Intel",
    "00:1E:65": "Intel", "00:1E:67": "Intel", "00:1F:3B": "Intel", "00:1F:3C": "Intel",
    "78:2B:CB": "Dell", "00:14:22": "Dell", "00:1A:A0": "Dell", "00:1C:23": "Dell",
    "00:1D:09": "Dell", "00:1E:4F": "Dell", "00:1E:C9": "Dell", "00:21:70": "Dell",
    "00:21:9B": "Dell", "00:22:19": "Dell", "00:23:AE": "Dell", "00:24:E8": "Dell",
    "00:25:64": "Dell", "00:26:B9": "Dell", "14:FE:B5": "Dell", "18:03:73": "Dell",
    "3C:97:0E": "HP", "00:17:A4": "HP", "00:1A:4B": "HP", "00:1C:C4": "HP",
    "00:1E:0B": "HP", "00:1F:29": "HP", "00:21:5A": "HP", "00:22:64": "HP",
    "00:23:7D": "HP", "00:24:81": "HP", "00:25:B3": "HP", "00:26:55": "HP",
    "00:09:2D": "HTC",
    "AC:CF:5C": "TP-Link", "00:27:19": "TP-Link", "14:CC:20": "TP-Link",
    "20:DC:E6": "TP-Link", "54:C8:0F": "TP-Link", "64:70:02": "TP-Link",
    "94:D9:B3": "TP-Link", "B0:4E:26": "TP-Link", "C0:25:E9": "TP-Link",
    "C4:6E:1F": "TP-Link", "E8:94:F6": "TP-Link", "EC:08:6B": "TP-Link",
    "00:14:BF": "Linksys", "00:1A:70": "Linksys", "00:1C:10": "Linksys",
    "00:1D:7E": "Linksys", "00:1E:E5": "Linksys", "00:21:29": "Linksys",
    "00:22:6B": "Linksys", "00:23:69": "Linksys", "00:25:9C": "Linksys",
    "20:AA:4B": "Linksys", "58:6D:8F": "Linksys", "68:7F:74": "Linksys",
    "00:18:01": "Actiontec", "00:1F:90": "Actiontec", "00:20:E0": "Actiontec",
    "00:24:7B": "Actiontec", "00:26:62": "Actiontec",
    "00:18:4D": "Netgear", "00:1B:2F": "Netgear", "00:1E:2A": "Netgear",
    "00:1F:33": "Netgear", "00:22:3F": "Netgear", "00:24:B2": "Netgear",
    "00:26:F2": "Netgear", "20:4E:7F": "Netgear", "28:C6:8E": "Netgear",
    "30:46:9A": "Netgear", "44:94:FC": "Netgear", "6C:B0:CE": "Netgear",
    "84:1B:5E": "Netgear", "9C:3D:CF": "Netgear", "A0:21:B7": "Netgear",
    "A0:63:91": "Netgear", "A4:2B:8C": "Netgear", "B0:7F:B9": "Netgear",
    "C0:3F:0E": "Netgear", "C4:04:15": "Netgear", "C4:3D:C7": "Netgear",
    "CC:40:D0": "Netgear", "E0:46:9A": "Netgear", "E0:91:F5": "Netgear",
    "E4:F4:C6": "Netgear", "F8:7B:8C": "Netgear",
    "F0:9F:C2": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti",
    "18:E8:29": "Ubiquiti", "24:5A:4C": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti", "68:72:51": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti", "B4:FB:E4": "Ubiquiti", "DC:9F:DB": "Ubiquiti",
    "E0:63:DA": "Ubiquiti", "F0:9F:C2": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "00:1F:A7": "Sony", "00:13:A9": "Sony", "00:1A:80": "Sony", "00:1D:BA": "Sony",
    "00:24:BE": "Sony", "04:5D:4B": "Sony", "28:0D:FC": "Sony", "30:17:C8": "Sony",
    "40:B8:37": "Sony", "78:84:3C": "Sony", "AC:9B:0A": "Sony", "B4:52:7E": "Sony",
    "00:1D:C9": "Amazon", "00:FC:8B": "Amazon", "0C:47:C9": "Amazon",
    "10:AE:60": "Amazon", "18:74:2E": "Amazon", "28:EF:01": "Amazon",
    "34:D2:70": "Amazon", "40:B4:CD": "Amazon", "44:65:0D": "Amazon",
    "4C:EF:C0": "Amazon", "50:DC:E7": "Amazon", "50:F5:DA": "Amazon",
    "5C:41:5A": "Amazon", "68:37:E9": "Amazon", "68:54:FD": "Amazon",
    "74:75:48": "Amazon", "74:C2:46": "Amazon", "84:D6:D0": "Amazon",
    "88:71:B1": "Amazon", "A0:02:DC": "Amazon", "AC:63:BE": "Amazon",
    "B4:7C:9C": "Amazon", "F0:27:2D": "Amazon", "F0:4F:7C": "Amazon",
    "FC:65:DE": "Amazon", "FE:27:C2": "Amazon",
    "48:D6:D5": "LG", "00:1C:62": "LG", "00:1E:75": "LG", "00:1F:6B": "LG",
    "00:1F:E3": "LG", "00:22:A9": "LG", "00:24:83": "LG", "00:25:E5": "LG",
    "00:26:E2": "LG", "10:68:3F": "LG", "14:C9:13": "LG", "20:21:A5": "LG",
    "28:CF:E9": "LG", "2C:54:CF": "LG", "30:B4:9E": "LG", "34:4D:F7": "LG",
    "00:80:C8": "D-Link", "00:0D:88": "D-Link", "00:0F:3D": "D-Link",
    "00:11:95": "D-Link", "00:13:46": "D-Link", "00:15:E9": "D-Link",
    "00:17:9A": "D-Link", "00:19:5B": "D-Link", "00:1B:11": "D-Link",
    "00:1C:F0": "D-Link", "00:1E:58": "D-Link", "00:1F:C6": "D-Link",
    "54:B8:0A": "D-Link", "78:54:2E": "D-Link", "90:94:E4": "D-Link",
    "18:62:2C": "Hikvision", "C0:56:E3": "Hikvision", "28:57:BE": "Hikvision",
    "4C:BD:8F": "Hikvision", "54:C4:15": "Hikvision", "7C:1E:52": "Hikvision",
    "00:18:DD": "Silicondust", # HDHomeRun
    "00:50:F2": "Microsoft",
}

# Try to import scapy for packet capture (requires root)
try:
    from scapy.all import sniff, ARP, Ether, IP, TCP, UDP, ICMP, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")

# Try to import nmap
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: python-nmap not available. Install with: pip install python-nmap")


app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
API_KEY = os.environ.get("NETVIS_API_KEY", "").strip()

# -----------------------------
# NIP substrate (Phase 0)
# -----------------------------
# Metadata registry for all recon techniques (coursework + pipeline).
nip_registry = default_registry()
# In-process event bus + bounded event buffer for UI polling/streaming.
nip_bus = EventBus(max_events=2000)
# Optional threat indicator file used by /api/nip/threat/check (Phase 2.4 starter).
NIP_THREAT_FEED_PATH = os.environ.get(
    "NIP_THREAT_FEED_PATH",
    str((Path(__file__).resolve().parent / "samples" / "threat_indicators.json")),
)


@app.before_request
def enforce_optional_api_key():
    """Optional API key guard. Disabled when NETVIS_API_KEY is unset."""
    if not API_KEY:
        return None
    # Keep health/status paths readable without auth to simplify local diagnostics.
    if request.path in ("/api/status", "/api/network/info", "/api/network/diagnose"):
        return None
    provided = request.headers.get("X-API-Key", "")
    if provided != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    return None


@dataclass
class Device:
    """Represents a network device"""
    ip: str
    mac: str = "unknown"
    hostname: str = ""
    vendor: str = ""
    os: str = ""
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    service_banners: Dict[int, str] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""
    is_gateway: bool = False
    is_local: bool = False
    

@dataclass  
class Connection:
    """Represents a connection between two devices"""
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    packet_count: int = 0
    byte_count: int = 0
    last_seen: str = ""
    first_seen: str = ""
    services: List[str] = field(default_factory=list)
    application: str = ""  # Detected application layer protocol


@dataclass
class DNSQuery:
    """Represents a DNS query from a device"""
    src_ip: str
    domain: str
    query_type: str
    resolved_ip: str = ""
    timestamp: str = ""


@dataclass
class Alert:
    """Security alert"""
    alert_type: str
    severity: str  # low, medium, high, critical
    message: str
    src_ip: str = ""
    dst_ip: str = ""
    timestamp: str = ""
    details: Dict = field(default_factory=dict)


class DataStore:
    """Lightweight persistence for assets, flows, findings, and scan jobs."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    ip TEXT PRIMARY KEY,
                    mac TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    os TEXT,
                    is_gateway INTEGER DEFAULT 0,
                    is_local INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT,
                    last_scan_profile TEXT DEFAULT '',
                    metadata_json TEXT DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS services (
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL DEFAULT 'tcp',
                    service TEXT,
                    banner TEXT DEFAULT '',
                    first_seen TEXT,
                    last_seen TEXT,
                    PRIMARY KEY (ip, port, protocol)
                );

                CREATE TABLE IF NOT EXISTS flows (
                    flow_key TEXT PRIMARY KEY,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    application TEXT,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    first_seen TEXT,
                    last_seen TEXT,
                    updated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS dns_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    domain TEXT,
                    query_type TEXT,
                    resolved_ip TEXT,
                    timestamp TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT,
                    severity TEXT,
                    message TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    timestamp TEXT,
                    details_json TEXT
                );

                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    category TEXT,
                    entity TEXT,
                    summary TEXT,
                    payload_json TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id TEXT PRIMARY KEY,
                    profile TEXT,
                    target TEXT,
                    status TEXT,
                    progress INTEGER,
                    message TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    result_json TEXT,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS coursework_jobs (
                    job_id TEXT PRIMARY KEY,
                    module TEXT,
                    action TEXT,
                    params_json TEXT,
                    status TEXT,
                    progress INTEGER,
                    message TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    log_path TEXT,
                    result_json TEXT,
                    error TEXT
                );

                -- -----------------------------
                -- NIP tables (roadmap support)
                -- -----------------------------

                CREATE TABLE IF NOT EXISTS nip_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    window_seconds INTEGER,
                    ip TEXT,
                    bytes_out INTEGER,
                    bytes_in INTEGER,
                    packets_out INTEGER,
                    packets_in INTEGER,
                    unique_dst_ips INTEGER,
                    unique_dst_ports INTEGER,
                    dns_queries INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_nip_metrics_ip_ts ON nip_metrics(ip, timestamp);

                CREATE TABLE IF NOT EXISTS nip_baselines (
                    ip TEXT PRIMARY KEY,
                    computed_at TEXT,
                    window_seconds INTEGER,
                    method TEXT,
                    baseline_json TEXT
                );

                -- Phase 1.1 extended graph node tables
                CREATE TABLE IF NOT EXISTS subnets (
                    cidr TEXT PRIMARY KEY,
                    gateway TEXT,
                    vlan_id TEXT DEFAULT '',
                    device_count INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT
                );

                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    record_type TEXT DEFAULT 'A',
                    value TEXT DEFAULT '',
                    first_seen TEXT,
                    last_seen TEXT,
                    query_count INTEGER DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_dns_records_domain ON dns_records(domain);

                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT DEFAULT '',
                    confidence REAL DEFAULT 0.5,
                    first_seen TEXT,
                    last_seen TEXT,
                    metadata_json TEXT DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_threat_ind_value ON threat_indicators(value);

                -- Phase 2.5 ingested log events
                CREATE TABLE IF NOT EXISTS log_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_type TEXT,
                    timestamp TEXT,
                    source_file TEXT,
                    entity TEXT,
                    summary TEXT,
                    payload_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_log_events_ts ON log_events(timestamp);

                -- Phase 4 brain state
                CREATE TABLE IF NOT EXISTS brain_plans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    generated_at TEXT,
                    situation_json TEXT,
                    objectives_json TEXT,
                    planned_techniques_json TEXT
                );

                -- Phase 7.3 quality snapshots
                CREATE TABLE IF NOT EXISTS quality_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    generated_at TEXT,
                    metrics_json TEXT
                );
                """
            )

    def upsert_device(self, device: Device, scan_profile: str = "", metadata: Optional[dict] = None):
        now = datetime.now().isoformat()
        metadata_json = json.dumps(metadata or {})
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO assets (
                    ip, mac, hostname, vendor, os, is_gateway, is_local,
                    first_seen, last_seen, last_scan_profile, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=excluded.mac,
                    hostname=excluded.hostname,
                    vendor=excluded.vendor,
                    os=excluded.os,
                    is_gateway=excluded.is_gateway,
                    is_local=excluded.is_local,
                    last_seen=excluded.last_seen,
                    last_scan_profile=excluded.last_scan_profile,
                    metadata_json=excluded.metadata_json
                """,
                (
                    device.ip,
                    device.mac,
                    device.hostname,
                    device.vendor,
                    device.os,
                    int(device.is_gateway),
                    int(device.is_local),
                    device.first_seen or now,
                    device.last_seen or now,
                    scan_profile,
                    metadata_json,
                ),
            )

    def upsert_service(self, ip: str, port: int, protocol: str, service: str, banner: str = ""):
        now = datetime.now().isoformat()
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO services (ip, port, protocol, service, banner, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, port, protocol) DO UPDATE SET
                    service=excluded.service,
                    banner=excluded.banner,
                    last_seen=excluded.last_seen
                """,
                (ip, port, protocol, service, banner, now, now),
            )

    def upsert_flow(self, flow_key: str, conn_obj: Connection):
        now = datetime.now().isoformat()
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO flows (
                    flow_key, src_ip, dst_ip, src_port, dst_port, protocol, application,
                    packet_count, byte_count, first_seen, last_seen, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(flow_key) DO UPDATE SET
                    packet_count=excluded.packet_count,
                    byte_count=excluded.byte_count,
                    application=excluded.application,
                    last_seen=excluded.last_seen,
                    updated_at=excluded.updated_at
                """,
                (
                    flow_key,
                    conn_obj.src_ip,
                    conn_obj.dst_ip,
                    conn_obj.src_port,
                    conn_obj.dst_port,
                    conn_obj.protocol,
                    conn_obj.application,
                    conn_obj.packet_count,
                    conn_obj.byte_count,
                    conn_obj.first_seen or now,
                    conn_obj.last_seen or now,
                    now,
                ),
            )

    def add_dns_query(self, q: DNSQuery):
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO dns_queries (src_ip, domain, query_type, resolved_ip, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (q.src_ip, q.domain, q.query_type, q.resolved_ip, q.timestamp),
            )

    def add_alert(self, alert: Alert):
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alerts (alert_type, severity, message, src_ip, dst_ip, timestamp, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_type,
                    alert.severity,
                    alert.message,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.timestamp,
                    json.dumps(alert.details or {}),
                ),
            )

    def add_observation(self, category: str, entity: str, summary: str, payload: Optional[dict] = None):
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO observations (timestamp, category, entity, summary, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (datetime.now().isoformat(), category, entity, summary, json.dumps(payload or {})),
            )

    def clear(self, include_assets: bool = False):
        """Clear persisted runtime telemetry. Optionally clear inventory assets too."""
        with self.lock, self._connect() as conn:
            conn.execute("DELETE FROM flows")
            conn.execute("DELETE FROM dns_queries")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM observations")
            conn.execute("DELETE FROM scan_jobs")
            conn.execute("DELETE FROM coursework_jobs")
            if include_assets:
                conn.execute("DELETE FROM assets")
                conn.execute("DELETE FROM services")

    def create_scan_job(self, job_id: str, profile: str, target: str):
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs (job_id, profile, target, status, progress, message, started_at, result_json, error)
                VALUES (?, ?, ?, 'queued', 0, 'Queued', ?, '{}', '')
                """,
                (job_id, profile, target, datetime.now().isoformat()),
            )

    def update_scan_job(self, job_id: str, *, status: Optional[str] = None, progress: Optional[int] = None,
                        message: Optional[str] = None, result: Optional[dict] = None, error: Optional[str] = None):
        fields = []
        values = []
        if status is not None:
            fields.append("status=?")
            values.append(status)
        if progress is not None:
            fields.append("progress=?")
            values.append(progress)
        if message is not None:
            fields.append("message=?")
            values.append(message)
        if result is not None:
            fields.append("result_json=?")
            values.append(json.dumps(result, default=str))
        if error is not None:
            fields.append("error=?")
            values.append(error)
        if status in {"completed", "failed"}:
            fields.append("completed_at=?")
            values.append(datetime.now().isoformat())

        if not fields:
            return

        values.append(job_id)
        query = f"UPDATE scan_jobs SET {', '.join(fields)} WHERE job_id=?"
        with self.lock, self._connect() as conn:
            conn.execute(query, values)

    def get_scan_job(self, job_id: str) -> Optional[dict]:
        with self.lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM scan_jobs WHERE job_id=?", (job_id,)).fetchone()
        if not row:
            return None
        result_json = {}
        try:
            result_json = json.loads(row["result_json"] or "{}")
        except Exception:
            result_json = {}
        return {
            "job_id": row["job_id"],
            "profile": row["profile"],
            "target": row["target"],
            "status": row["status"],
            "progress": row["progress"],
            "message": row["message"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "result": result_json,
            "error": row["error"],
        }

    def list_scan_jobs(self, limit: int = 20) -> List[dict]:
        with self.lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT job_id FROM scan_jobs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        jobs = []
        for row in rows:
            job = self.get_scan_job(row["job_id"])
            if job:
                jobs.append(job)
        return jobs

    # -----------------------------
    # Coursework job helpers
    # -----------------------------

    def create_coursework_job(self, job_id: str, module: str, action: str, params: dict):
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO coursework_jobs (
                    job_id, module, action, params_json, status, progress, message, started_at, log_path, result_json, error
                ) VALUES (?, ?, ?, ?, 'queued', 0, 'Queued', ?, '', '{}', '')
                """,
                (job_id, module, action, json.dumps(params or {}), datetime.now().isoformat()),
            )

    def update_coursework_job(self, job_id: str, *, status: Optional[str] = None, progress: Optional[int] = None,
                              message: Optional[str] = None, log_path: Optional[str] = None, result: Optional[dict] = None,
                              error: Optional[str] = None):
        fields = []
        values = []
        if status is not None:
            fields.append("status=?")
            values.append(status)
        if progress is not None:
            fields.append("progress=?")
            values.append(progress)
        if message is not None:
            fields.append("message=?")
            values.append(message)
        if log_path is not None:
            fields.append("log_path=?")
            values.append(log_path)
        if result is not None:
            fields.append("result_json=?")
            values.append(json.dumps(result, default=str))
        if error is not None:
            fields.append("error=?")
            values.append(error)
        if status in {"completed", "failed"}:
            fields.append("completed_at=?")
            values.append(datetime.now().isoformat())

        if not fields:
            return

        values.append(job_id)
        query = f"UPDATE coursework_jobs SET {', '.join(fields)} WHERE job_id=?"
        with self.lock, self._connect() as conn:
            conn.execute(query, values)

    def get_coursework_job(self, job_id: str) -> Optional[dict]:
        with self.lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM coursework_jobs WHERE job_id=?", (job_id,)).fetchone()
        if not row:
            return None
        params_json = {}
        result_json = {}
        try:
            params_json = json.loads(row["params_json"] or "{}")
        except Exception:
            params_json = {}
        try:
            result_json = json.loads(row["result_json"] or "{}")
        except Exception:
            result_json = {}
        return {
            "job_id": row["job_id"],
            "module": row["module"],
            "action": row["action"],
            "params": params_json,
            "status": row["status"],
            "progress": row["progress"],
            "message": row["message"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "log_path": row["log_path"],
            "result": result_json,
            "error": row["error"],
        }

    def list_coursework_jobs(self, limit: int = 20) -> List[dict]:
        with self.lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT job_id FROM coursework_jobs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        jobs = []
        for row in rows:
            job = self.get_coursework_job(row["job_id"])
            if job:
                jobs.append(job)
        return jobs

    def get_recent_observations(self, limit: int = 100) -> List[dict]:
        with self.lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM observations ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "timestamp": r["timestamp"],
                "category": r["category"],
                "entity": r["entity"],
                "summary": r["summary"],
                "payload": json.loads(r["payload_json"] or "{}"),
            }
            for r in rows
        ]

    def list_observations_range(self, *, start_ts: str, end_ts: str, like: str = "", limit: int = 200) -> List[dict]:
        """Return observations in a timestamp window (best-effort ISO string comparisons)."""
        lim = max(1, int(limit))
        s0 = str(start_ts or "").strip()
        s1 = str(end_ts or "").strip()
        like_s = str(like or "").strip()
        if not s0 or not s1:
            return []
        with self.lock, self._connect() as conn:
            if like_s:
                pat = f"%{like_s}%"
                rows = conn.execute(
                    """
                    SELECT * FROM observations
                    WHERE timestamp >= ? AND timestamp <= ?
                      AND (entity LIKE ? OR payload_json LIKE ? OR summary LIKE ?)
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (s0, s1, pat, pat, pat, lim),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM observations
                    WHERE timestamp >= ? AND timestamp <= ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (s0, s1, lim),
                ).fetchall()
        out = []
        for r in rows:
            try:
                payload = json.loads(r["payload_json"] or "{}")
            except Exception:
                payload = {}
            out.append(
                {
                    "timestamp": r["timestamp"],
                    "category": r["category"],
                    "entity": r["entity"],
                    "summary": r["summary"],
                    "payload": payload,
                }
            )
        return out

    # -----------------------------
    # Inventory/graph retrieval (NIP helpers)
    # -----------------------------

    def list_assets(self, limit: int = 2000, *, as_of: str = "") -> List[dict]:
        lim = max(1, int(limit))
        as_of_s = str(as_of or "").strip()
        with self.lock, self._connect() as conn:
            if as_of_s:
                rows = conn.execute(
                    """
                    SELECT * FROM assets
                    WHERE (first_seen IS NULL OR first_seen='' OR first_seen <= ?)
                      AND (last_seen IS NULL OR last_seen='' OR last_seen >= ?)
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (as_of_s, as_of_s, lim),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM assets ORDER BY last_seen DESC LIMIT ?",
                    (lim,),
                ).fetchall()
        out = []
        for r in rows:
            try:
                meta = json.loads(r["metadata_json"] or "{}")
            except Exception:
                meta = {}
            out.append(
                {
                    "ip": r["ip"],
                    "mac": r["mac"] or "",
                    "hostname": r["hostname"] or "",
                    "vendor": r["vendor"] or "",
                    "os": r["os"] or "",
                    "is_gateway": bool(r["is_gateway"]),
                    "is_local": bool(r["is_local"]),
                    "first_seen": r["first_seen"] or "",
                    "last_seen": r["last_seen"] or "",
                    "last_scan_profile": r["last_scan_profile"] or "",
                    "metadata": meta,
                }
            )
        return out

    def list_services(self, limit: int = 5000, *, as_of: str = "") -> List[dict]:
        lim = max(1, int(limit))
        as_of_s = str(as_of or "").strip()
        with self.lock, self._connect() as conn:
            if as_of_s:
                rows = conn.execute(
                    """
                    SELECT * FROM services
                    WHERE (first_seen IS NULL OR first_seen='' OR first_seen <= ?)
                      AND (last_seen IS NULL OR last_seen='' OR last_seen >= ?)
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (as_of_s, as_of_s, lim),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM services ORDER BY last_seen DESC LIMIT ?",
                    (lim,),
                ).fetchall()
        return [
            {
                "ip": r["ip"],
                "port": int(r["port"]),
                "protocol": r["protocol"] or "tcp",
                "service": r["service"] or "",
                "banner": r["banner"] or "",
                "first_seen": r["first_seen"] or "",
                "last_seen": r["last_seen"] or "",
            }
            for r in rows
        ]

    def list_flows(self, limit: int = 5000, *, as_of: str = "") -> List[dict]:
        lim = max(1, int(limit))
        as_of_s = str(as_of or "").strip()
        with self.lock, self._connect() as conn:
            if as_of_s:
                rows = conn.execute(
                    """
                    SELECT * FROM flows
                    WHERE (first_seen IS NULL OR first_seen='' OR first_seen <= ?)
                      AND (last_seen IS NULL OR last_seen='' OR last_seen >= ?)
                    ORDER BY last_seen DESC
                    LIMIT ?
                    """,
                    (as_of_s, as_of_s, lim),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM flows ORDER BY last_seen DESC LIMIT ?",
                    (lim,),
                ).fetchall()
        return [
            {
                "flow_key": r["flow_key"],
                "src_ip": r["src_ip"],
                "dst_ip": r["dst_ip"],
                "src_port": int(r["src_port"] or 0),
                "dst_port": int(r["dst_port"] or 0),
                "protocol": r["protocol"] or "",
                "application": r["application"] or "",
                "packet_count": int(r["packet_count"] or 0),
                "byte_count": int(r["byte_count"] or 0),
                "first_seen": r["first_seen"] or "",
                "last_seen": r["last_seen"] or "",
                "updated_at": r["updated_at"] or "",
            }
            for r in rows
        ]

    def list_alerts(self, limit: int = 1000) -> List[dict]:
        lim = max(1, int(limit))
        with self.lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (lim,)).fetchall()
        return [dict(r) for r in rows]

    # -----------------------------
    # NIP metrics + baselines (temporal engine)
    # -----------------------------

    def add_nip_metric(self, metric: dict) -> None:
        """Insert a single NIP metrics window row (best-effort)."""
        if not isinstance(metric, dict):
            return
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO nip_metrics (
                    timestamp, window_seconds, ip, bytes_out, bytes_in, packets_out, packets_in,
                    unique_dst_ips, unique_dst_ports, dns_queries
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(metric.get("timestamp") or ""),
                    int(metric.get("window_seconds") or 0),
                    str(metric.get("ip") or ""),
                    int(metric.get("bytes_out") or 0),
                    int(metric.get("bytes_in") or 0),
                    int(metric.get("packets_out") or 0),
                    int(metric.get("packets_in") or 0),
                    int(metric.get("unique_dst_ips") or 0),
                    int(metric.get("unique_dst_ports") or 0),
                    int(metric.get("dns_queries") or 0),
                ),
            )

    def list_nip_metrics(self, *, ip: str = "", limit: int = 400) -> List[dict]:
        lim = max(1, int(limit))
        ip_s = str(ip or "").strip()
        with self.lock, self._connect() as conn:
            if ip_s:
                rows = conn.execute(
                    "SELECT * FROM nip_metrics WHERE ip=? ORDER BY id DESC LIMIT ?",
                    (ip_s, lim),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM nip_metrics ORDER BY id DESC LIMIT ?",
                    (lim,),
                ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "timestamp": r["timestamp"],
                    "window_seconds": int(r["window_seconds"] or 0),
                    "ip": r["ip"],
                    "bytes_out": int(r["bytes_out"] or 0),
                    "bytes_in": int(r["bytes_in"] or 0),
                    "packets_out": int(r["packets_out"] or 0),
                    "packets_in": int(r["packets_in"] or 0),
                    "unique_dst_ips": int(r["unique_dst_ips"] or 0),
                    "unique_dst_ports": int(r["unique_dst_ports"] or 0),
                    "dns_queries": int(r["dns_queries"] or 0),
                }
            )
        return out

    def list_nip_metrics_range(self, *, ip: str, start_ts: str, end_ts: str, limit: int = 500) -> List[dict]:
        """Return metrics for one IP within a timestamp window (best-effort ISO string comparisons)."""
        lim = max(1, int(limit))
        ip_s = str(ip or "").strip()
        s0 = str(start_ts or "").strip()
        s1 = str(end_ts or "").strip()
        if not ip_s or not s0 or not s1:
            return []
        with self.lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM nip_metrics
                WHERE ip=? AND timestamp >= ? AND timestamp <= ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (ip_s, s0, s1, lim),
            ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "timestamp": r["timestamp"],
                    "window_seconds": int(r["window_seconds"] or 0),
                    "ip": r["ip"],
                    "bytes_out": int(r["bytes_out"] or 0),
                    "bytes_in": int(r["bytes_in"] or 0),
                    "packets_out": int(r["packets_out"] or 0),
                    "packets_in": int(r["packets_in"] or 0),
                    "unique_dst_ips": int(r["unique_dst_ips"] or 0),
                    "unique_dst_ports": int(r["unique_dst_ports"] or 0),
                    "dns_queries": int(r["dns_queries"] or 0),
                }
            )
        return out

    def upsert_nip_baseline(self, *, ip: str, baseline: dict, window_seconds: int, method: str = "ewma") -> None:
        now = datetime.now().isoformat()
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO nip_baselines (ip, computed_at, window_seconds, method, baseline_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    computed_at=excluded.computed_at,
                    window_seconds=excluded.window_seconds,
                    method=excluded.method,
                    baseline_json=excluded.baseline_json
                """,
                (str(ip), now, int(window_seconds), str(method), json.dumps(baseline or {})),
            )

    def get_nip_baseline(self, ip: str) -> Optional[dict]:
        ip_s = str(ip or "").strip()
        if not ip_s:
            return None
        with self.lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM nip_baselines WHERE ip=?", (ip_s,)).fetchone()
        if not row:
            return None
        try:
            baseline = json.loads(row["baseline_json"] or "{}")
        except Exception:
            baseline = {}
        return {
            "ip": row["ip"],
            "computed_at": row["computed_at"],
            "window_seconds": int(row["window_seconds"] or 0),
            "method": row["method"] or "",
            "baseline": baseline,
        }

    def list_nip_baselines(self, limit: int = 2000) -> List[dict]:
        lim = max(1, int(limit))
        with self.lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM nip_baselines ORDER BY computed_at DESC LIMIT ?", (lim,)).fetchall()
        out = []
        for r in rows:
            try:
                baseline = json.loads(r["baseline_json"] or "{}")
            except Exception:
                baseline = {}
            out.append(
                {
                    "ip": r["ip"],
                    "computed_at": r["computed_at"],
                    "window_seconds": int(r["window_seconds"] or 0),
                    "method": r["method"] or "",
                    "baseline": baseline,
                }
            )
        return out


# Application port mappings for service detection
APP_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
    80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 
    587: "SMTP-Submit", 853: "DNS-over-TLS",
    993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 3478: "STUN/TURN",
    4443: "Pharos", 5060: "SIP", 5061: "SIPS",
    5222: "XMPP", 5223: "XMPP-SSL", 5228: "Google-Play",
    5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "Kubernetes", 6881: "BitTorrent",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8883: "MQTT-SSL",
    9000: "SonarQube", 9090: "Prometheus", 9100: "Print",
    27017: "MongoDB",
    # Streaming services (common ports)
    554: "RTSP", 1935: "RTMP",
    # Gaming
    3074: "Xbox-Live", 3478: "PlayStation",
    # Cloud services typically use 443 but specific ranges
}

# Known service IP ranges (simplified)
KNOWN_SERVICES = {
    "8.8.8.8": "Google DNS",
    "8.8.4.4": "Google DNS", 
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
}

# Known IP ranges for major services
IP_RANGES = {
    # AWS
    "3.": "Amazon AWS",
    "13.": "Amazon AWS", 
    "18.": "Amazon AWS",
    "23.20.": "Amazon AWS",
    "23.21.": "Amazon AWS",
    "23.22.": "Amazon AWS",
    "23.23.": "Amazon AWS",
    "34.": "Amazon AWS",
    "35.": "Amazon AWS",
    "44.": "Amazon AWS",
    "50.": "Amazon AWS",
    "52.": "Amazon AWS",
    "54.": "Amazon AWS",
    "63.": "Amazon AWS",
    "72.": "Amazon AWS",
    "75.": "Amazon AWS",
    "99.": "Amazon AWS",
    "100.": "Amazon AWS",
    "107.": "Amazon AWS",
    "174.": "Amazon AWS",
    "176.": "Amazon AWS",
    "184.": "Amazon AWS",
    "204.": "Amazon AWS",
    # Google
    "142.250.": "Google",
    "142.251.": "Google",
    "172.217.": "Google",
    "216.58.": "Google",
    "74.125.": "Google",
    "173.194.": "Google",
    "209.85.": "Google",
    "64.233.": "Google",
    # Microsoft/Azure
    "13.64.": "Microsoft Azure",
    "13.65.": "Microsoft Azure",
    "13.66.": "Microsoft Azure",
    "13.67.": "Microsoft Azure",
    "13.68.": "Microsoft Azure",
    "13.69.": "Microsoft Azure",
    "13.70.": "Microsoft Azure",
    "13.71.": "Microsoft Azure",
    "13.72.": "Microsoft Azure",
    "13.73.": "Microsoft Azure",
    "13.74.": "Microsoft Azure",
    "13.75.": "Microsoft Azure",
    "13.76.": "Microsoft Azure",
    "13.77.": "Microsoft Azure",
    "13.78.": "Microsoft Azure",
    "13.79.": "Microsoft Azure",
    "20.": "Microsoft Azure",
    "40.": "Microsoft Azure",
    "51.": "Microsoft Azure",
    "52.": "Microsoft Azure",
    "65.52.": "Microsoft Azure",
    "104.40.": "Microsoft Azure",
    "104.41.": "Microsoft Azure",
    "104.42.": "Microsoft Azure",
    "104.43.": "Microsoft Azure",
    "104.44.": "Microsoft Azure",
    "104.45.": "Microsoft Azure",
    "104.46.": "Microsoft Azure",
    "104.47.": "Microsoft Azure",
    "104.208.": "Microsoft Azure",
    "104.209.": "Microsoft Azure",
    "104.210.": "Microsoft Azure",
    "104.211.": "Microsoft Azure",
    "104.212.": "Microsoft Azure",
    "104.213.": "Microsoft Azure",
    "104.214.": "Microsoft Azure",
    "104.215.": "Microsoft Azure",
    "191.232.": "Microsoft Azure",
    "191.233.": "Microsoft Azure",
    "191.234.": "Microsoft Azure",
    "191.235.": "Microsoft Azure",
    "191.236.": "Microsoft Azure",
    "191.237.": "Microsoft Azure",
    "191.238.": "Microsoft Azure",
    "191.239.": "Microsoft Azure",
    # Cloudflare
    "104.16.": "Cloudflare",
    "104.17.": "Cloudflare",
    "104.18.": "Cloudflare",
    "104.19.": "Cloudflare",
    "104.20.": "Cloudflare",
    "104.21.": "Cloudflare",
    "104.22.": "Cloudflare",
    "104.23.": "Cloudflare",
    "104.24.": "Cloudflare",
    "104.25.": "Cloudflare",
    "104.26.": "Cloudflare",
    "104.27.": "Cloudflare",
    "172.64.": "Cloudflare",
    "172.65.": "Cloudflare",
    "172.66.": "Cloudflare",
    "172.67.": "Cloudflare",
    "162.158.": "Cloudflare",
    "198.41.": "Cloudflare",
    # Akamai
    "23.": "Akamai CDN",
    "95.100.": "Akamai CDN",
    "96.16.": "Akamai CDN",
    "96.17.": "Akamai CDN",
    "184.24.": "Akamai CDN",
    "184.25.": "Akamai CDN",
    "184.26.": "Akamai CDN",
    "184.27.": "Akamai CDN",
    "184.28.": "Akamai CDN",
    "184.29.": "Akamai CDN",
    "184.30.": "Akamai CDN",
    "184.31.": "Akamai CDN",
    # Facebook/Meta
    "157.240.": "Meta/Facebook",
    "31.13.": "Meta/Facebook",
    "179.60.": "Meta/Facebook",
    "185.60.": "Meta/Facebook",
    # Apple
    "17.": "Apple",
    # Netflix
    "45.57.": "Netflix",
    "108.175.": "Netflix",
    "185.2.": "Netflix",
    "185.9.": "Netflix",
    "192.173.": "Netflix",
    "198.38.": "Netflix",
    "198.45.": "Netflix",
    # Special addresses
    "239.255.255.250": "SSDP/UPnP Multicast",
    "224.0.0.": "Multicast",
    "239.": "Multicast",
    "255.255.255.255": "Broadcast",
}

# Cache for IP lookups
ip_info_cache = {}


def identify_ip_service(ip: str) -> str:
    """Quick identification of IP service from known ranges"""
    if ip in KNOWN_SERVICES:
        return KNOWN_SERVICES[ip]
    
    # Check prefixes
    for prefix, service in IP_RANGES.items():
        if ip.startswith(prefix):
            return service
    
    # Check if private
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.') or ip.startswith('172.17.') or ip.startswith('172.18.') or ip.startswith('172.19.') or ip.startswith('172.2') or ip.startswith('172.30.') or ip.startswith('172.31.'):
        return "Private Network"
    
    if ip.startswith('127.'):
        return "Localhost"
    
    if ip == '0.0.0.0':
        return "Any/DHCP"
    
    return ""


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private/reserved range"""
    if not ip:
        return True
    return (
        ip.startswith('192.168.') or 
        ip.startswith('10.') or 
        ip.startswith('172.16.') or ip.startswith('172.17.') or ip.startswith('172.18.') or
        ip.startswith('172.19.') or ip.startswith('172.20.') or ip.startswith('172.21.') or
        ip.startswith('172.22.') or ip.startswith('172.23.') or ip.startswith('172.24.') or
        ip.startswith('172.25.') or ip.startswith('172.26.') or ip.startswith('172.27.') or
        ip.startswith('172.28.') or ip.startswith('172.29.') or ip.startswith('172.30.') or
        ip.startswith('172.31.') or
        ip.startswith('127.') or 
        ip.startswith('0.') or 
        ip.startswith('224.') or 
        ip.startswith('239.') or 
        ip.startswith('255.')
    )


def get_mac_vendor_online(mac: str) -> str:
    """Look up MAC vendor from online API"""
    if not mac:
        return ''
    try:
        # Use macvendors.co free API
        mac_clean = mac.replace(':', '').replace('-', '')[:6]
        url = f"https://api.macvendors.com/{mac_clean}"
        req = urllib.request.Request(url, headers={'User-Agent': 'NetVis/1.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.read().decode('utf-8').strip()
    except:
        return ''


def lookup_ip_info(ip: str) -> dict:
    """Look up detailed IP information using free API"""
    if ip in ip_info_cache:
        return ip_info_cache[ip]
    
    # Skip private/special IPs
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.') or ip.startswith('127.') or ip.startswith('0.') or ip.startswith('224.') or ip.startswith('239.') or ip.startswith('255.'):
        result = {
            'ip': ip,
            'service': identify_ip_service(ip),
            'country': 'Local',
            'city': '',
            'org': 'Private Network',
            'isp': '',
            'is_private': True
        }
        ip_info_cache[ip] = result
        return result
    
    # Use ip-api.com (free, no key required, 45 requests/minute)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query"
        req = urllib.request.Request(url, headers={'User-Agent': 'NetVis/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            if data.get('status') == 'success':
                # Identify service from our database first
                service = identify_ip_service(ip)
                if not service:
                    # Try to identify from org/isp
                    org = data.get('org', '').lower()
                    isp = data.get('isp', '').lower()
                    if 'amazon' in org or 'amazon' in isp or 'aws' in org:
                        service = 'Amazon AWS'
                    elif 'google' in org or 'google' in isp:
                        service = 'Google'
                    elif 'microsoft' in org or 'microsoft' in isp or 'azure' in org:
                        service = 'Microsoft Azure'
                    elif 'cloudflare' in org or 'cloudflare' in isp:
                        service = 'Cloudflare'
                    elif 'akamai' in org or 'akamai' in isp:
                        service = 'Akamai CDN'
                    elif 'facebook' in org or 'meta' in org:
                        service = 'Meta/Facebook'
                    elif 'apple' in org:
                        service = 'Apple'
                    elif 'netflix' in org:
                        service = 'Netflix'
                
                result = {
                    'ip': ip,
                    'service': service,
                    'country': data.get('country', ''),
                    'city': data.get('city', ''),
                    'org': data.get('org', ''),
                    'isp': data.get('isp', ''),
                    'as': data.get('as', ''),
                    'is_private': False
                }
                ip_info_cache[ip] = result
                return result
    except Exception as e:
        pass
    
    # Fallback
    result = {
        'ip': ip,
        'service': identify_ip_service(ip),
        'country': 'Unknown',
        'city': '',
        'org': '',
        'isp': '',
        'is_private': False
    }
    ip_info_cache[ip] = result
    return result


def lookup_mac_vendor(mac: str) -> str:
    """Look up vendor from MAC address OUI"""
    if not mac or mac == "unknown":
        return ""
    
    # Normalize MAC format to XX:XX:XX
    mac_clean = mac.upper().replace("-", ":").replace(".", ":")
    parts = mac_clean.split(":")
    
    # Handle different MAC formats
    if len(parts) == 6:
        # Standard format: AA:BB:CC:DD:EE:FF
        prefix = ":".join(parts[:3])
    elif len(parts) == 3:
        # Cisco format: AABB.CCDD.EEFF -> need to convert
        prefix = mac_clean[:8]
    else:
        prefix = mac_clean[:8]
    
    print(f"    MAC lookup: {mac} -> prefix {prefix}")
    
    if prefix in MAC_VENDORS:
        return MAC_VENDORS[prefix]
    
    # Try online lookup as fallback (macvendors.com API)
    try:
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={'User-Agent': 'NetVis/1.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            vendor = response.read().decode('utf-8').strip()
            if vendor and 'error' not in vendor.lower():
                print(f"    Online lookup found: {vendor}")
                return vendor
    except Exception as e:
        pass
    
    return ""


def resolve_hostname_multi(ip: str) -> str:
    """Try multiple methods to resolve hostname"""
    hostname = ""
    
    # Method 1: Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and not hostname.startswith(ip.replace(".", "-")):
            return hostname
    except Exception:
        pass
    
    # Method 2: mDNS/Bonjour lookup (common on Apple devices)
    try:
        result = subprocess.run(
            ['dns-sd', '-Q', f'{ip.replace(".", "-")}.local'],
            capture_output=True, text=True, timeout=2
        )
        # Parse output for hostname
    except Exception:
        pass
    
    # Method 3: NetBIOS name lookup (Windows devices)
    try:
        result = subprocess.run(
            ['nmblookup', '-A', ip],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.split('\n'):
            if '<00>' in line and 'GROUP' not in line:
                parts = line.strip().split()
                if parts:
                    return parts[0]
    except Exception:
        pass
    
    # Method 4: avahi-resolve (Linux mDNS)
    try:
        result = subprocess.run(
            ['avahi-resolve', '-a', ip],
            capture_output=True, text=True, timeout=2
        )
        if result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1].rstrip('.')
    except Exception:
        pass
    
    return hostname


def guess_device_type(hostname: str, vendor: str, open_ports: List[int]) -> str:
    """Guess device type from available information"""
    hostname_lower = (hostname or "").lower()
    vendor_lower = (vendor or "").lower()
    
    # Router/Gateway indicators
    if any(x in hostname_lower for x in ['router', 'gateway', 'gw', 'rt-', 'ubnt', 'livebox', 'bbox', 'freebox', 'neufbox']):
        return "Router"
    if any(x in vendor_lower for x in ['ubiquiti', 'netgear', 'linksys', 'tp-link', 'asus', 'd-link', 'actiontec']):
        if not open_ports or 80 in open_ports or 443 in open_ports:
            return "Router/AP"
    
    # Apple devices
    if 'apple' in vendor_lower:
        if any(x in hostname_lower for x in ['iphone', 'ipad']):
            return "iPhone/iPad"
        if any(x in hostname_lower for x in ['macbook', 'mbp', 'mba']):
            return "MacBook"
        if any(x in hostname_lower for x in ['imac', 'mac-pro', 'mac-mini']):
            return "Mac Desktop"
        if 'appletv' in hostname_lower or 'apple-tv' in hostname_lower:
            return "Apple TV"
        if 'homepod' in hostname_lower:
            return "HomePod"
        if 'watch' in hostname_lower:
            return "Apple Watch"
        return "Apple Device"
    
    # Smart TVs
    if any(x in hostname_lower for x in ['tv', 'roku', 'firetv', 'chromecast', 'appletv']):
        return "Smart TV/Streaming"
    if any(x in vendor_lower for x in ['roku', 'samsung', 'lg', 'sony', 'vizio']):
        if 'tv' in hostname_lower or not hostname:
            return "Smart TV"
    
    # Gaming
    if any(x in hostname_lower for x in ['playstation', 'ps4', 'ps5', 'xbox', 'nintendo', 'switch']):
        return "Gaming Console"
    
    # Phones
    if any(x in hostname_lower for x in ['phone', 'android', 'galaxy', 'pixel', 'oneplus']):
        return "Smartphone"
    if any(x in vendor_lower for x in ['samsung', 'htc', 'huawei', 'xiaomi', 'oneplus']) and not hostname:
        return "Smartphone"
    
    # Amazon devices
    if 'amazon' in vendor_lower:
        if any(x in hostname_lower for x in ['echo', 'alexa', 'dot']):
            return "Echo/Alexa"
        if 'fire' in hostname_lower:
            return "Fire TV/Tablet"
        return "Amazon Device"
    
    # Google devices
    if 'google' in vendor_lower or 'nest' in vendor_lower:
        if any(x in hostname_lower for x in ['nest', 'thermostat', 'protect']):
            return "Nest Device"
        if any(x in hostname_lower for x in ['home', 'mini', 'hub']):
            return "Google Home"
        return "Google Device"
    
    # Cameras
    if any(x in hostname_lower for x in ['camera', 'cam', 'ipcam', 'doorbell', 'ring']):
        return "Camera"
    if 'hikvision' in vendor_lower:
        return "IP Camera"
    
    # Printers
    if any(x in hostname_lower for x in ['printer', 'print', 'hp', 'canon', 'epson', 'brother']):
        return "Printer"
    if 9100 in open_ports or 515 in open_ports or 631 in open_ports:
        return "Printer"
    
    # NAS/Storage
    if any(x in hostname_lower for x in ['nas', 'synology', 'qnap', 'storage', 'diskstation']):
        return "NAS"
    
    # Servers
    if any(x in hostname_lower for x in ['server', 'srv', 'proxmox', 'esxi', 'docker']):
        return "Server"
    if open_ports and any(p in open_ports for p in [22, 80, 443, 3306, 5432, 8080]):
        if len(open_ports) > 3:
            return "Server"
    
    # Computers
    if any(x in hostname_lower for x in ['laptop', 'desktop', 'pc', 'workstation', 'macbook']):
        return "Computer"
    if any(x in vendor_lower for x in ['dell', 'hp', 'lenovo', 'asus', 'acer', 'intel']):
        return "Computer"
    
    # Virtual machines
    if any(x in vendor_lower for x in ['vmware', 'virtualbox', 'hyper-v']):
        return "Virtual Machine"
    
    # Raspberry Pi
    if 'raspberry' in vendor_lower:
        return "Raspberry Pi"
    
    # IoT/Smart Home
    if any(x in hostname_lower for x in ['iot', 'smart', 'sensor', 'plug', 'bulb', 'hue', 'wemo']):
        return "Smart Home Device"
    if 'philips' in vendor_lower and 'hue' in hostname_lower:
        return "Smart Light"
    
    # ESP32/ESP8266 IoT devices
    if 'espressif' in vendor_lower:
        return "IoT Device (ESP)"
    
    # Smart Innovation - smart home devices
    if 'smart innovation' in vendor_lower:
        return "Smart Home Device"
    
    # WNC - embedded network devices
    if 'wnc' in vendor_lower:
        return "Network Device"
    
    # Arcadyan - ISP routers
    if 'arcadyan' in vendor_lower:
        return "Router"
    
    return "Unknown"


def grab_service_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """Best-effort service banner grab for enriched service profiling."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) != 0:
            sock.close()
            return ""

        try:
            if port in (80, 8080, 8000, 8443, 443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = sock.recv(512)
            sock.close()
            return data.decode("utf-8", errors="ignore").strip()[:200]
        except Exception:
            sock.close()
            return ""
    except Exception:
        return ""


class NetworkScanner:
    """Handles network device discovery"""
    
    def __init__(self):
        self.devices: Dict[str, Device] = {}
        self.local_ip = self._get_local_ip()
        self.gateway_ip = self._get_gateway_ip()
        self.network_cidr = self._get_network_cidr()
        
    def _get_local_ip(self) -> str:
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def _get_gateway_ip(self) -> str:
        """Get the default gateway IP"""
        import platform
        try:
            if platform.system() == 'Darwin':  # macOS
                result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line.startswith('default') or line.startswith('0.0.0.0'):
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
            else:  # Linux
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if 'via' in parts:
                            return parts[parts.index('via') + 1]
        except Exception:
            pass
        return ""
    
    def _get_network_cidr(self) -> str:
        """Get the network CIDR notation"""
        if self.local_ip:
            # Assume /24 for simplicity, could be made more accurate
            parts = self.local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "192.168.1.0/24"
    
    def _get_local_mac(self) -> str:
        """Get MAC address of local machine"""
        import platform
        try:
            if platform.system() == 'Darwin':  # macOS
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if self.local_ip in line:
                        # Look for ether line before this
                        for j in range(max(0, i-5), i):
                            if 'ether' in lines[j]:
                                parts = lines[j].strip().split()
                                if len(parts) >= 2:
                                    return parts[1]
            else:  # Linux
                result = subprocess.run(['ip', 'link'], capture_output=True, text=True)
                # Parse to find MAC
        except Exception as e:
            print(f"Error getting local MAC: {e}")
        return "unknown"
    
    def scan_network_arp(self) -> Dict[str, Device]:
        """Quick ARP scan to discover devices with enrichment"""
        if not SCAPY_AVAILABLE:
            return self._scan_network_ping()
        
        try:
            # ARP scan
            from scapy.all import arping
            answered, _ = arping(self.network_cidr, timeout=2, verbose=False)
            
            now = datetime.now().isoformat()
            discovered_ips = []
            
            # Add the local machine first (ARP won't detect ourselves)
            if self.local_ip and self.local_ip not in self.devices:
                self.devices[self.local_ip] = Device(
                    ip=self.local_ip,
                    mac=self._get_local_mac(),
                    hostname=socket.gethostname(),
                    first_seen=now,
                    last_seen=now,
                    is_local=True
                )
                discovered_ips.append(self.local_ip)
            
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                discovered_ips.append(ip)
                
                if ip not in self.devices:
                    self.devices[ip] = Device(
                        ip=ip,
                        mac=mac,
                        first_seen=now,
                        last_seen=now,
                        is_gateway=(ip == self.gateway_ip),
                        is_local=(ip == self.local_ip)
                    )
                else:
                    self.devices[ip].mac = mac
                    self.devices[ip].last_seen = now
            
            # Enrich devices with vendor and hostname info
            print(f"Enriching {len(discovered_ips)} devices...")
            for ip in discovered_ips:
                device = self.devices[ip]
                
                # Lookup MAC vendor
                if not device.vendor:
                    device.vendor = lookup_mac_vendor(device.mac)
                
                # Try to resolve hostname
                if not device.hostname:
                    device.hostname = resolve_hostname_multi(ip)
                
                # Guess device type
                device_type = guess_device_type(device.hostname, device.vendor, device.open_ports)
                if device_type != "Unknown":
                    device.os = device_type  # Store in os field for now
                
                # Mark as gateway if it's a router at the gateway IP
                if device_type == "Router" or ip == self.gateway_ip:
                    device.is_gateway = True
                
                print(f"  {ip}: {device.hostname or 'no-hostname'} ({device.vendor or 'unknown vendor'}) - {device.os or 'unknown type'}")
                if 'datastore' in globals():
                    datastore.upsert_device(device, scan_profile="arp")
                    if device.open_ports:
                        for port in device.open_ports:
                            datastore.upsert_service(ip, port, "tcp", device.services.get(port, ""))
                    
        except Exception as e:
            print(f"ARP scan error: {e}")
            import traceback
            traceback.print_exc()
            return self._scan_network_ping()
            
        return self.devices
    
    def _scan_network_ping(self) -> Dict[str, Device]:
        """Fallback ping scan"""
        base_ip = '.'.join(self.local_ip.split('.')[:-1])
        now = datetime.now().isoformat()
        
        def ping_host(ip):
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    timeout=2
                )
                return result.returncode == 0
            except Exception:
                return False
        
        # Scan common range
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            if ping_host(ip):
                if ip not in self.devices:
                    self.devices[ip] = Device(
                        ip=ip,
                        first_seen=now,
                        last_seen=now,
                        is_gateway=(ip == self.gateway_ip),
                        is_local=(ip == self.local_ip)
                    )
                else:
                    self.devices[ip].last_seen = now
                if 'datastore' in globals():
                    datastore.upsert_device(self.devices[ip], scan_profile="ping")
                    
        return self.devices
    
    def scan_ports(self, ip: str, ports: List[int] = None, banner_grab: bool = False) -> Device:
        """Scan ports on a device with optional service banner collection."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 
                    993, 995, 3306, 3389, 5432, 8080, 8443]
        
        if ip not in self.devices:
            self.devices[ip] = Device(ip=ip, first_seen=datetime.now().isoformat())
        
        device = self.devices[ip]
        device.open_ports = []
        device.services = {}
        device.service_banners = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    device.open_ports.append(port)
                    device.services[port] = self._get_service_name(port)
                    if banner_grab:
                        banner = grab_service_banner(ip, port)
                        if banner:
                            device.service_banners[port] = banner
                sock.close()
            except Exception:
                pass
        
        if 'datastore' in globals():
            datastore.upsert_device(device, scan_profile="port_scan")
            for port in device.open_ports:
                banner = device.service_banners.get(port, "")
                datastore.upsert_service(ip, port, "tcp", device.services.get(port, ""), banner=banner)

        return device
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for a port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        return services.get(port, f"Port {port}")
    
    def nmap_scan(self, target: str = None) -> Dict[str, Device]:
        """Full nmap scan with OS detection and service enumeration"""
        if not NMAP_AVAILABLE:
            print("nmap not available, using basic scan")
            return self.scan_network_arp()
        
        target = target or self.network_cidr
        nm = nmap.PortScanner()
        
        try:
            # Quick scan: -sn for host discovery
            nm.scan(hosts=target, arguments='-sn')
            
            now = datetime.now().isoformat()
            for host in nm.all_hosts():
                ip = host
                if ip not in self.devices:
                    self.devices[ip] = Device(
                        ip=ip,
                        first_seen=now,
                        last_seen=now,
                        is_gateway=(ip == self.gateway_ip),
                        is_local=(ip == self.local_ip)
                    )
                
                # Get MAC and vendor if available
                if 'mac' in nm[host]['addresses']:
                    self.devices[ip].mac = nm[host]['addresses']['mac']
                if 'vendor' in nm[host] and nm[host]['vendor']:
                    mac = self.devices[ip].mac
                    if mac in nm[host]['vendor']:
                        self.devices[ip].vendor = nm[host]['vendor'][mac]
                        
                # Get hostname
                if 'hostnames' in nm[host]:
                    for hostname_info in nm[host]['hostnames']:
                        if hostname_info.get('name'):
                            self.devices[ip].hostname = hostname_info['name']
                            break
                if 'datastore' in globals():
                    datastore.upsert_device(self.devices[ip], scan_profile="nmap")
                            
        except Exception as e:
            print(f"nmap scan error: {e}")
            
        return self.devices


class TrafficAnalyzer:
    """Analyzes network traffic to identify communication patterns"""
    
    def __init__(self):
        self.connections: Dict[str, Connection] = {}
        self.capture_thread: Optional[threading.Thread] = None
        self.is_capturing = False
        self.packet_buffer: List[dict] = []
        self.lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self._last_flow_persist: Dict[str, float] = {}
        self._persist_interval_sec = 2.0
        
        # Enhanced tracking
        self.dns_queries: List[DNSQuery] = []
        self.alerts: List[Alert] = []
        self.bandwidth_history: Dict[str, List[dict]] = {}  # IP -> [{timestamp, bytes}]
        self.known_devices: Set[str] = set()
        self.port_scan_tracker: Dict[str, Dict[str, int]] = {}  # src_ip -> {dst_ip: port_count}
        
    def start_capture(self, interface: str = None, filter_str: str = ""):
        """Start packet capture in background thread"""
        if not SCAPY_AVAILABLE:
            print("Scapy not available for packet capture")
            return False
            
        if self.is_capturing:
            return True
            
        self.is_capturing = True
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, filter_str),
            daemon=True
        )
        self.capture_thread.start()
        return True
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
            
    def _capture_loop(self, interface: str, filter_str: str):
        """Background capture loop"""
        try:
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            print(f"Capture error: {e}")
            self.is_capturing = False
            
    def _process_packet(self, packet):
        """Process a captured packet with deep inspection"""
        try:
            if IP not in packet:
                return
                
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Determine protocol and ports
            protocol = "IP"
            src_port = 0
            dst_port = 0
            application = ""
            
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
            
            # Detect application from port
            application = APP_PORTS.get(dst_port, APP_PORTS.get(src_port, ""))
            
            # Check for known services
            if dst_ip in KNOWN_SERVICES:
                application = KNOWN_SERVICES[dst_ip]
            elif src_ip in KNOWN_SERVICES:
                application = KNOWN_SERVICES[src_ip]
            
            # DNS deep inspection
            if dst_port == 53 or src_port == 53:
                self._process_dns(packet, src_ip, dst_ip)
            
            # Create connection key
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            
            now = datetime.now().isoformat()
            pkt_len = len(packet)
            now_epoch = time.time()
            self.total_packets += 1
            self.total_bytes += pkt_len
            
            with self.lock:
                if conn_key not in self.connections:
                    self.connections[conn_key] = Connection(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        protocol=protocol,
                        src_port=src_port,
                        dst_port=dst_port,
                        packet_count=1,
                        byte_count=pkt_len,
                        last_seen=now,
                        first_seen=now,
                        application=application
                    )
                else:
                    conn = self.connections[conn_key]
                    conn.packet_count += 1
                    conn.byte_count += pkt_len
                    conn.last_seen = now
                    if not conn.application and application:
                        conn.application = application
                
                # Persist connection state periodically to avoid excessive write pressure
                flow_obj = self.connections[conn_key]
                last_persist = self._last_flow_persist.get(conn_key, 0)
                if 'datastore' in globals() and (now_epoch - last_persist) >= self._persist_interval_sec:
                    datastore.upsert_flow(conn_key, flow_obj)
                    self._last_flow_persist[conn_key] = now_epoch
                
                # Track bandwidth per IP
                for ip in [src_ip, dst_ip]:
                    if ip not in self.bandwidth_history:
                        self.bandwidth_history[ip] = []
                    self.bandwidth_history[ip].append({
                        'timestamp': now,
                        'bytes': pkt_len
                    })
                    # Keep last 1000 entries per IP
                    if len(self.bandwidth_history[ip]) > 1000:
                        self.bandwidth_history[ip] = self.bandwidth_history[ip][-500:]
                
                # Detect port scanning
                self._detect_port_scan(src_ip, dst_ip, dst_port)
                
                # Detect new devices
                self._detect_new_device(src_ip)
                self._detect_new_device(dst_ip)
                    
                # Add to buffer for real-time updates
                self.packet_buffer.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'size': pkt_len,
                    'timestamp': now,
                    'application': application
                })
                
                # Keep buffer manageable
                if len(self.packet_buffer) > 100:
                    self.packet_buffer = self.packet_buffer[-50:]
                    
        except Exception as e:
            pass  # Silently ignore packet processing errors
    
    def _process_dns(self, packet, src_ip, dst_ip):
        """Extract DNS query information"""
        try:
            from scapy.all import DNS, DNSQR, DNSRR
            if DNS in packet:
                dns = packet[DNS]
                now = datetime.now().isoformat()
                
                # DNS Query
                if dns.qd:
                    qname = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                    qname = qname.rstrip('.')
                    query_type = "A"  # Simplified
                    
                    # Find who is making the query (not the DNS server)
                    querier = src_ip if dst_ip.endswith('.1') or dst_ip in ['8.8.8.8', '1.1.1.1'] else dst_ip
                    
                    with self.lock:
                        query = DNSQuery(
                            src_ip=querier,
                            domain=qname,
                            query_type=query_type,
                            timestamp=now
                        )
                        self.dns_queries.append(query)
                        if 'datastore' in globals():
                            datastore.add_dns_query(query)
                        # Keep last 500 DNS queries
                        if len(self.dns_queries) > 500:
                            self.dns_queries = self.dns_queries[-250:]
        except Exception:
            pass
    
    def _detect_port_scan(self, src_ip, dst_ip, dst_port):
        """Detect potential port scanning behavior"""
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = {}
        
        if dst_ip not in self.port_scan_tracker[src_ip]:
            self.port_scan_tracker[src_ip][dst_ip] = set()
        
        self.port_scan_tracker[src_ip][dst_ip].add(dst_port)
        
        # Alert if scanning many ports on same host
        if len(self.port_scan_tracker[src_ip][dst_ip]) > 20:
            self._add_alert(
                "port_scan",
                "high",
                f"Potential port scan detected: {src_ip} scanning {len(self.port_scan_tracker[src_ip][dst_ip])} ports on {dst_ip}",
                src_ip,
                dst_ip,
                {"ports_scanned": len(self.port_scan_tracker[src_ip][dst_ip])}
            )
    
    def _detect_new_device(self, ip):
        """Detect new devices appearing on the network"""
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            if ip not in self.known_devices:
                self.known_devices.add(ip)
                if 'datastore' in globals():
                    datastore.add_observation(
                        "discovery",
                        ip,
                        f"Observed new internal IP {ip}",
                        {"ip": ip},
                    )
                # Only alert after initial discovery period
                if len(self.known_devices) > 5:
                    self._add_alert(
                        "new_device",
                        "medium",
                        f"New device detected on network: {ip}",
                        ip,
                        "",
                        {}
                    )
    
    def _add_alert(self, alert_type, severity, message, src_ip="", dst_ip="", details=None):
        """Add a security alert"""
        now = datetime.now().isoformat()
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            message=message,
            src_ip=src_ip,
            dst_ip=dst_ip,
            timestamp=now,
            details=details or {}
        )
        with self.lock:
            self.alerts.append(alert)
            if 'datastore' in globals():
                datastore.add_alert(alert)
                datastore.add_observation(
                    "alert",
                    f"{alert.src_ip}->{alert.dst_ip}" if alert.dst_ip else (alert.src_ip or "network"),
                    alert.message,
                    {"alert_type": alert.alert_type, "severity": alert.severity, "details": alert.details},
                )
            # Keep last 100 alerts
            if len(self.alerts) > 100:
                self.alerts = self.alerts[-50:]
            
    def get_connections(self) -> List[dict]:
        """Get all captured connections"""
        with self.lock:
            return [asdict(c) for c in self.connections.values()]
            
    def get_recent_packets(self) -> List[dict]:
        """Get recent packets from buffer"""
        with self.lock:
            packets = self.packet_buffer.copy()
            self.packet_buffer.clear()
            return packets
            
    def get_traffic_matrix(self) -> Dict[str, Dict[str, int]]:
        """Get traffic matrix showing bytes between each pair of IPs"""
        matrix = defaultdict(lambda: defaultdict(int))
        
        with self.lock:
            for conn in self.connections.values():
                matrix[conn.src_ip][conn.dst_ip] += conn.byte_count
                
        return {k: dict(v) for k, v in matrix.items()}


SCAN_PROFILES = {
    "quick": {
        "ports": [22, 80, 443],
        "banner_grab": False,
        "max_workers": 20,
    },
    "standard": {
        "ports": [21, 22, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443],
        "banner_grab": False,
        "max_workers": 16,
    },
    "deep": {
        "ports": [
            20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445,
            465, 500, 587, 631, 993, 995, 1433, 1521, 1723, 1883, 2049, 2379, 3000, 3306, 3389, 4000,
            5000, 5001, 5060, 5432, 5900, 6379, 6443, 8000, 8080, 8443, 9000, 9090, 9100, 9200, 27017
        ],
        "banner_grab": True,
        "max_workers": 10,
    },
}


def _discover_hosts_icmp_tcp(network_cidr: str, is_vpn: bool = False) -> List[dict]:
    """Discover hosts with ICMP and TCP probing for routed/VPN topologies."""
    import concurrent.futures

    base_parts = network_cidr.split('/')[0].split('.')[:3]
    ips_to_scan = [f"{'.'.join(base_parts)}.{i}" for i in range(1, 255)]

    def probe_host(ip: str) -> Optional[dict]:
        host_info = {'ip': ip, 'alive': False}

        # ICMP probe first
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                output = result.stdout.decode() if isinstance(result.stdout, bytes) else result.stdout
                host_info['alive'] = True
                ttl = 64
                if 'ttl=' in output.lower():
                    ttl = int(output.lower().split('ttl=')[1].split()[0])
                host_info['ttl'] = ttl
                host_info['os_guess'] = 'Linux/Unix' if ttl <= 64 else ('Windows' if ttl <= 128 else 'Network Device')
        except Exception:
            pass

        # TCP fallback probe
        if not host_info['alive']:
            for port in [80, 443, 22, 445]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    if sock.connect_ex((ip, port)) == 0:
                        host_info['alive'] = True
                        host_info['tcp_detected'] = port
                        sock.close()
                        break
                    sock.close()
                except Exception:
                    pass

        if not host_info['alive']:
            return None

        try:
            host_info['hostname'] = socket.gethostbyaddr(ip)[0]
        except Exception:
            host_info['hostname'] = ''

        now = datetime.now().isoformat()
        if ip not in scanner.devices:
            scanner.devices[ip] = Device(
                ip=ip,
                mac='',
                hostname=host_info.get('hostname', ''),
                vendor='VPN/Tunnel' if is_vpn else '',
                os=host_info.get('os_guess', 'unknown').lower().replace('/', '_').replace(' ', '_'),
                first_seen=now,
                last_seen=now,
                is_gateway=(ip == scanner.gateway_ip),
                is_local=(ip == scanner.local_ip),
                open_ports=[],
                services={}
            )
        else:
            scanner.devices[ip].last_seen = now

        return host_info

    alive_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(probe_host, ip): ip for ip in ips_to_scan}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive_hosts.append(result)
    return alive_hosts


def run_profile_scan(profile: str = "standard", target_network: Optional[str] = None, progress_callback=None) -> dict:
    """Unified scan flow with profile depth and routed-network fallbacks."""
    import concurrent.futures

    profile = profile if profile in SCAN_PROFILES else "standard"
    cfg = SCAN_PROFILES[profile]

    def _progress(p: int, msg: str):
        if progress_callback:
            progress_callback(p, msg)

    _progress(5, "Diagnosing network")
    diagnosis = get_network_diagnosis_internal()
    network_cidr = target_network or scanner.network_cidr

    results = {
        'scan_method': 'arp',
        'profile': profile,
        'network_type': diagnosis.get('network_type', 'lan'),
        'vpn_detected': diagnosis.get('vpn_detected', False),
        'devices_found': 0,
        'alive_hosts': [],
        'issues': diagnosis.get('issues', []),
        'network': network_cidr
    }

    can_arp = diagnosis.get('can_arp_scan', True)
    is_vpn = diagnosis.get('vpn_detected', False)

    # Discovery stage
    _progress(15, "Discovering hosts")
    if can_arp and not is_vpn:
        results['scan_method'] = 'arp'
        scanner.scan_network_arp()
    else:
        results['scan_method'] = 'icmp_tcp'
        results['alive_hosts'] = _discover_hosts_icmp_tcp(network_cidr, is_vpn=is_vpn)

    discovered_ips = list(scanner.devices.keys())
    if not discovered_ips:
        _progress(100, "No devices found")
        results['devices'] = []
        return results

    # Enrichment stage
    _progress(55, f"Enriching {len(discovered_ips)} devices")

    def enrich_one(ip: str):
        device = scanner.devices.get(ip)
        if not device:
            return None
        if not device.vendor and device.mac:
            device.vendor = lookup_mac_vendor(device.mac)
        if not device.hostname:
            device.hostname = resolve_hostname_multi(ip)
        scanner.scan_ports(ip, ports=cfg["ports"], banner_grab=cfg["banner_grab"])
        device = scanner.devices[ip]
        device.os = guess_device_type(device.hostname, device.vendor, device.open_ports)
        datastore.upsert_device(device, scan_profile=profile)
        for port in device.open_ports:
            datastore.upsert_service(
                ip,
                port,
                "tcp",
                device.services.get(port, f"Port {port}"),
                banner=device.service_banners.get(port, ""),
            )
        return asdict(device)

    devices_out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg["max_workers"]) as executor:
        futures = {executor.submit(enrich_one, ip): ip for ip in discovered_ips}
        for future in concurrent.futures.as_completed(futures):
            device_dict = future.result()
            if device_dict:
                devices_out.append(device_dict)

    devices_out.sort(key=lambda d: d.get("ip", ""))
    results['devices'] = devices_out
    results['devices_found'] = len(devices_out)
    datastore.add_observation(
        "scan",
        network_cidr,
        f"{profile} scan completed with {len(devices_out)} devices via {results['scan_method']}",
        {"profile": profile, "network": network_cidr, "method": results['scan_method'], "count": len(devices_out)},
    )
    _progress(100, "Scan complete")
    return results


class ScanJobManager:
    """Background scan execution manager with persisted state."""

    def start(self, profile: str, target: Optional[str]) -> str:
        job_id = str(uuid.uuid4())
        datastore.create_scan_job(job_id, profile, target or scanner.network_cidr)
        thread = threading.Thread(target=self._run, args=(job_id, profile, target), daemon=True)
        thread.start()
        return job_id

    def _run(self, job_id: str, profile: str, target: Optional[str]):
        try:
            datastore.update_scan_job(job_id, status="running", progress=1, message="Initializing scan")

            def progress(p: int, msg: str):
                datastore.update_scan_job(job_id, status="running", progress=p, message=msg)

            result = run_profile_scan(profile=profile, target_network=target, progress_callback=progress)
            datastore.update_scan_job(
                job_id,
                status="completed",
                progress=100,
                message="Completed",
                result=result,
            )
        except Exception as exc:
            datastore.update_scan_job(
                job_id,
                status="failed",
                progress=100,
                message="Failed",
                error=str(exc),
            )


class CourseworkJobManager:
    """Background runner for rubric-aligned module scripts (Module 1–7)."""

    def start(self, module: str, action: str, params: dict) -> str:
        job_id = str(uuid.uuid4())
        datastore.create_coursework_job(job_id, module, action, params or {})
        thread = threading.Thread(target=self._run, args=(job_id, module, action, params or {}), daemon=True)
        thread.start()
        return job_id

    def _run(self, job_id: str, module: str, action: str, params: dict):
        try:
            datastore.update_coursework_job(job_id, status="running", progress=1, message="Starting")
            if module == "pipeline" and action == "multichain":
                result, log_path = run_multichain_pipeline(job_id=job_id, params=params)
            else:
                result, log_path = run_coursework_action(module=module, action=action, params=params)
            datastore.update_coursework_job(
                job_id,
                status="completed",
                progress=100,
                message="Completed",
                log_path=log_path or "",
                result=result,
            )
        except Exception as exc:
            datastore.update_coursework_job(
                job_id,
                status="failed",
                progress=100,
                message="Failed",
                error=str(exc),
            )


class NipMetricsDaemon:
    """Continuous-ish time-window metrics + baselining + anomaly detection (NIP Phase 2/3).

    This is designed for lab use:
    - It derives per-window deltas from in-memory Connection objects.
    - It stores window rows in SQLite (nip_metrics) and maintains EWMA baselines (nip_baselines).
    - It raises alerts via analyzer._add_alert when behavior deviates strongly from baseline.

    It intentionally avoids packet-level logging volume; the goal is analyst-friendly signals.
    """

    def __init__(self, *, interval_seconds: int = 10, alpha: float = 0.2):
        self.interval_seconds = max(2, int(interval_seconds))
        self.alpha = max(0.01, min(float(alpha), 0.9))
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Per-flow last counters so we can compute deltas.
        self._last_flow: Dict[str, Tuple[int, int]] = {}
        self._last_dns_len: int = 0

        # In-memory EWMA baselines per IP.
        self._baseline: Dict[str, Dict[str, float]] = {}

        # Alert cooldown to avoid spam.
        self._last_alert_ts: Dict[Tuple[str, str], float] = {}
        self._last_tick_at: str = ""

    def configure(self, *, interval_seconds: Optional[int] = None, alpha: Optional[float] = None) -> None:
        """Update daemon parameters (safe to call while running)."""
        with self._lock:
            if interval_seconds is not None:
                self.interval_seconds = max(2, int(interval_seconds))
            if alpha is not None:
                self.alpha = max(0.01, min(float(alpha), 0.9))

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self.running = True
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()

    def stop(self) -> None:
        with self._lock:
            self.running = False
        try:
            if self.thread:
                self.thread.join(timeout=2)
        except Exception:
            pass

    def status(self) -> dict:
        with self._lock:
            return {
                "running": bool(self.running),
                "interval_seconds": int(self.interval_seconds),
                "alpha": float(self.alpha),
                "baseline_hosts": len(self._baseline),
                "last_tick_at": self._last_tick_at,
            }

    def _loop(self) -> None:
        while True:
            with self._lock:
                if not self.running:
                    return
                interval = int(self.interval_seconds)
            try:
                self._tick(window_seconds=interval)
            except Exception:
                pass
            time.sleep(max(0.5, interval))

    def _conn_key(self, c: Connection) -> str:
        return f"{c.src_ip}:{int(c.src_port)}-{c.dst_ip}:{int(c.dst_port)}-{c.protocol}"

    def _tick(self, *, window_seconds: int) -> None:
        now_iso = datetime.now().isoformat()
        now_epoch = time.time()

        # If we're not capturing, we still might have state but we should avoid generating noise.
        # We still update baselines slowly based on any deltas, but we don't emit anomalies unless capturing.
        capturing = bool(getattr(analyzer, "is_capturing", False))

        with analyzer.lock:
            conns = list(analyzer.connections.values())
            dns_all = list(analyzer.dns_queries)

        # DNS delta counts for this window.
        new_dns = dns_all[self._last_dns_len :] if self._last_dns_len <= len(dns_all) else []
        self._last_dns_len = len(dns_all)
        dns_by_ip = defaultdict(int)
        for q in new_dns:
            try:
                dns_by_ip[str(q.src_ip)] += 1
            except Exception:
                pass

        # Per-IP window metrics.
        per_ip = {}
        per_ip_dst_ips: Dict[str, set] = defaultdict(set)
        per_ip_dst_ports: Dict[str, set] = defaultdict(set)

        for c in conns:
            key = self._conn_key(c)
            prev_bytes, prev_pkts = self._last_flow.get(key, (0, 0))
            cur_bytes = int(getattr(c, "byte_count", 0) or 0)
            cur_pkts = int(getattr(c, "packet_count", 0) or 0)

            delta_b = cur_bytes - prev_bytes
            delta_p = cur_pkts - prev_pkts
            if delta_b < 0:
                delta_b = 0
            if delta_p < 0:
                delta_p = 0

            self._last_flow[key] = (cur_bytes, cur_pkts)
            if delta_b == 0 and delta_p == 0:
                continue

            src = str(getattr(c, "src_ip", "") or "")
            dst = str(getattr(c, "dst_ip", "") or "")
            dport = int(getattr(c, "dst_port", 0) or 0)

            if src:
                m = per_ip.setdefault(
                    src,
                    {
                        "bytes_out": 0,
                        "bytes_in": 0,
                        "packets_out": 0,
                        "packets_in": 0,
                    },
                )
                m["bytes_out"] += int(delta_b)
                m["packets_out"] += int(delta_p)
                if dst:
                    per_ip_dst_ips[src].add(dst)
                if dport > 0:
                    per_ip_dst_ports[src].add(dport)

            if dst:
                m = per_ip.setdefault(
                    dst,
                    {
                        "bytes_out": 0,
                        "bytes_in": 0,
                        "packets_out": 0,
                        "packets_in": 0,
                    },
                )
                m["bytes_in"] += int(delta_b)
                m["packets_in"] += int(delta_p)

        # Insert window rows + update baselines.
        for ip, m in per_ip.items():
            metric = {
                "timestamp": now_iso,
                "window_seconds": int(window_seconds),
                "ip": ip,
                "bytes_out": int(m.get("bytes_out") or 0),
                "bytes_in": int(m.get("bytes_in") or 0),
                "packets_out": int(m.get("packets_out") or 0),
                "packets_in": int(m.get("packets_in") or 0),
                "unique_dst_ips": len(per_ip_dst_ips.get(ip, set())),
                "unique_dst_ports": len(per_ip_dst_ports.get(ip, set())),
                "dns_queries": int(dns_by_ip.get(ip, 0)),
            }

            try:
                datastore.add_nip_metric(metric)
            except Exception:
                pass

            # Baseline EWMA.
            b = self._baseline.get(ip)
            if not b:
                b = {
                    "avg_bytes_out": float(metric["bytes_out"]),
                    "avg_bytes_in": float(metric["bytes_in"]),
                    "avg_unique_dst_ips": float(metric["unique_dst_ips"]),
                    "avg_unique_dst_ports": float(metric["unique_dst_ports"]),
                    "avg_dns_queries": float(metric["dns_queries"]),
                }
            else:
                a = float(self.alpha)
                b["avg_bytes_out"] = a * float(metric["bytes_out"]) + (1 - a) * float(b.get("avg_bytes_out", 0.0))
                b["avg_bytes_in"] = a * float(metric["bytes_in"]) + (1 - a) * float(b.get("avg_bytes_in", 0.0))
                b["avg_unique_dst_ips"] = a * float(metric["unique_dst_ips"]) + (1 - a) * float(b.get("avg_unique_dst_ips", 0.0))
                b["avg_unique_dst_ports"] = a * float(metric["unique_dst_ports"]) + (1 - a) * float(b.get("avg_unique_dst_ports", 0.0))
                b["avg_dns_queries"] = a * float(metric["dns_queries"]) + (1 - a) * float(b.get("avg_dns_queries", 0.0))
            self._baseline[ip] = b

            try:
                datastore.upsert_nip_baseline(
                    ip=ip,
                    baseline=b,
                    window_seconds=int(window_seconds),
                    method=f"ewma(alpha={self.alpha})",
                )
            except Exception:
                pass

            # Change detection: only emit anomalies when capture is active.
            if capturing:
                self._detect_anomaly(ip, metric, b, now_epoch)

        self._last_tick_at = now_iso

    def _detect_anomaly(self, ip: str, metric: dict, baseline: dict, now_epoch: float) -> None:
        # Cooldown per device to avoid spamming.
        cooldown_s = 60.0
        cooldown_key = (ip, "behavior_anomaly")
        last = float(self._last_alert_ts.get(cooldown_key, 0.0))
        if (now_epoch - last) < cooldown_s:
            return

        cur_bytes_out = float(metric.get("bytes_out") or 0.0)
        cur_unique_ports = float(metric.get("unique_dst_ports") or 0.0)
        cur_unique_dsts = float(metric.get("unique_dst_ips") or 0.0)
        cur_dns = float(metric.get("dns_queries") or 0.0)

        avg_bytes_out = max(0.0, float(baseline.get("avg_bytes_out") or 0.0))
        avg_unique_ports = max(0.0, float(baseline.get("avg_unique_dst_ports") or 0.0))
        avg_unique_dsts = max(0.0, float(baseline.get("avg_unique_dst_ips") or 0.0))
        avg_dns = max(0.0, float(baseline.get("avg_dns_queries") or 0.0))

        score = 0.0
        reasons = []

        # Volume spike.
        if avg_bytes_out > 0 and cur_bytes_out > max(200_000.0, avg_bytes_out * 6.0):
            score += 0.45
            reasons.append(f"bytes_out_spike cur={int(cur_bytes_out)} avg≈{int(avg_bytes_out)}")

        # Scanning-like: many unique ports to multiple destinations in one window.
        if cur_unique_ports >= 20 and (avg_unique_ports <= 1.0 or cur_unique_ports > avg_unique_ports * 6.0):
            score += 0.45
            reasons.append(f"unique_dst_ports_spike cur={int(cur_unique_ports)} avg≈{avg_unique_ports:.1f}")
        if cur_unique_dsts >= 10 and (avg_unique_dsts <= 1.0 or cur_unique_dsts > avg_unique_dsts * 6.0):
            score += 0.20
            reasons.append(f"unique_dst_ips_spike cur={int(cur_unique_dsts)} avg≈{avg_unique_dsts:.1f}")

        # DNS spike (intent signal).
        if cur_dns >= 30 and (avg_dns <= 1.0 or cur_dns > avg_dns * 8.0):
            score += 0.25
            reasons.append(f"dns_spike cur={int(cur_dns)} avg≈{avg_dns:.1f}")

        if score < 0.6:
            return

        severity = "medium" if score < 0.85 else "high"
        msg = f"Behavior anomaly on {ip}: score={score:.2f} ({', '.join(reasons)})"

        try:
            analyzer._add_alert(
                "behavior_anomaly",
                severity,
                msg,
                src_ip=ip,
                dst_ip="",
                details={
                    "metric": metric,
                    "baseline": baseline,
                    "reasons": reasons,
                    "score": score,
                },
            )
        except Exception:
            pass

        try:
            nip_bus.publish(
                event_type="anomaly.detected",
                source="nip:change_detector",
                entity=ip,
                summary=msg,
                data={"metric": metric, "baseline": baseline, "reasons": reasons, "score": score, "severity": severity},
            )
        except Exception:
            pass

        self._last_alert_ts[cooldown_key] = now_epoch


def _cw_is_root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def _cw_local_only_guard():
    """Refuse remote requests to coursework runners unless API key auth is enabled."""
    if API_KEY:
        return None  # already enforced by before_request
    if request.remote_addr in ("127.0.0.1", "::1"):
        return None
    return jsonify({"error": "Forbidden", "reason": "coursework_endpoints_local_only"}), 403


def _cw_parse_ports(value) -> List[int]:
    if value is None:
        return []
    if isinstance(value, list):
        out = []
        for v in value:
            try:
                p = int(v)
            except Exception:
                continue
            if 1 <= p <= 65535:
                out.append(p)
        return sorted(list(dict.fromkeys(out)))
    s = str(value)
    ports = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            p = int(part)
        except Exception:
            continue
        if 1 <= p <= 65535:
            ports.append(p)
    return sorted(list(dict.fromkeys(ports)))


def _cw_parse_hosts(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    s = str(value).strip()
    return [s] if s else []


CW_CORE_MODULES = tuple(f"mod{i}" for i in range(1, 8))
CW_EXT_MODULES = (
    "ipv6",
    "dhcp",
    "discovery",
    "icmp",
    "tls",
    "dns",
    "snmp",
    "ssh",
    "smb",
    "iot",
    "wifi",
    "analysis",
    "threat",
    "vlan",
)
CW_RUN_MODULES = set(CW_CORE_MODULES) | set(CW_EXT_MODULES)
CW_LOG_MODULES = set(CW_RUN_MODULES) | {"pipeline"}

# NIP ingestion helpers live here (technique -> inventory/events).

def _nip_find_technique(module: str, action: str):
    """Best-effort lookup of technique metadata from the NIP registry."""
    try:
        for t in nip_registry.values():
            if getattr(t, "module", None) == module and getattr(t, "action", None) == action:
                return t
    except Exception:
        pass
    return None


def _nip_upsert_device_min(*, ip: str, mac: str = "", vendor: str = "", hostname: str = "", os_guess: str = "", scan_profile: str = "") -> bool:
    """Upsert device into scanner.devices + datastore. Returns True if it was newly created in-memory."""
    now = datetime.now().isoformat()
    created = False

    if ip in scanner.devices:
        d = scanner.devices[ip]
        # Only fill fields when we have something better.
        if mac and (not d.mac or d.mac == "unknown"):
            d.mac = mac
        if vendor and not d.vendor:
            d.vendor = vendor
        if hostname and not d.hostname:
            d.hostname = hostname
        if os_guess and not d.os:
            d.os = os_guess
        d.last_seen = now
    else:
        created = True
        scanner.devices[ip] = Device(
            ip=ip,
            mac=mac or "unknown",
            hostname=hostname or "",
            vendor=vendor or "",
            os=os_guess or "",
            open_ports=[],
            services={},
            service_banners={},
            first_seen=now,
            last_seen=now,
            is_gateway=(ip == getattr(scanner, "gateway_ip", "")),
            is_local=(ip == getattr(scanner, "local_ip", "")),
        )

    try:
        datastore.upsert_device(scanner.devices[ip], scan_profile=(scan_profile or "coursework"))
    except Exception:
        pass

    return created


def _nip_ingest_coursework_result(*, module: str, action: str, params: dict, result: dict):
    """Convert coursework technique outputs into inventory/services/observations.

    This is a lightweight "graph population pipeline" for NIP: it takes the
    outputs of discrete techniques and pushes them into the persistent asset/
    service store so the GUI and story engine can fuse everything.
    """
    if not isinstance(result, dict):
        return

    src = f"{module}:{action}"

    # --------------------
    # Module 1: link-layer -> devices (IP/MAC)
    # --------------------
    if module == "mod1":
        rows = []
        if action == "active":
            rows = result.get("hosts") or []
        elif action == "passive":
            rows = result.get("ip_mac_table") or []
        elif action == "randomized":
            rows = ((result.get("scan_result") or {}).get("hosts") or [])

        for h in rows:
            if not isinstance(h, dict):
                continue
            ip = str(h.get("ip") or "").strip()
            mac = str(h.get("mac") or "").strip()
            if not ip:
                continue
            vendor = lookup_mac_vendor(mac) if mac else ""
            created = _nip_upsert_device_min(ip=ip, mac=mac, vendor=vendor, scan_profile=f"coursework_{module}_{action}")
            if created:
                nip_bus.publish(
                    event_type="device.discovered",
                    source=src,
                    entity=ip,
                    summary=f"Discovered device {ip}",
                    data={"ip": ip, "mac": mac, "vendor": vendor},
                )
        return

    # --------------------
    # Module 2: transport -> open ports/services + firewall inference
    # --------------------
    if module == "mod2":
        rows = result.get("results") or []
        for r in rows:
            if not isinstance(r, dict):
                continue
            ip = str(r.get("host") or "").strip()
            proto = str(r.get("proto") or "tcp").strip().lower()
            port = r.get("port")
            state = str(r.get("state") or "")
            if not ip or not isinstance(port, int):
                continue

            _nip_upsert_device_min(ip=ip, scan_profile=f"coursework_{module}_{action}")

            if state == "open":
                svc_name = SERVICE_NAMES.get(int(port)) or APP_PORTS.get(int(port)) or f"Port {int(port)}"
                try:
                    d = scanner.devices[ip]
                    if int(port) not in (d.open_ports or []):
                        d.open_ports.append(int(port))
                        d.open_ports = sorted(list(dict.fromkeys(d.open_ports)))
                    d.services[int(port)] = svc_name
                except Exception:
                    pass
                try:
                    datastore.upsert_service(ip, int(port), proto, svc_name, banner="")
                except Exception:
                    pass
                nip_bus.publish(
                    event_type="port.opened",
                    source=src,
                    entity=ip,
                    summary=f"Open {proto}:{int(port)} on {ip}",
                    data={"ip": ip, "port": int(port), "proto": proto, "service": svc_name},
                )

        if action == "ack" and isinstance(result.get("firewall_topology_map"), list):
            try:
                datastore.add_observation(
                    "firewall.inference",
                    "network",
                    "ACK scan firewall inference completed",
                    {"source": src, "map": result.get("firewall_topology_map")},
                )
            except Exception:
                pass
        return

    # --------------------
    # Module 5: app fingerprinting -> banners + HTTP/TLS intel
    # --------------------
    if module == "mod5":
        if action == "banner":
            host = str(result.get("host") or "").strip()
            if host:
                _nip_upsert_device_min(ip=host, scan_profile=f"coursework_{module}_{action}")
            for rr in (result.get("results") or []):
                if not isinstance(rr, dict):
                    continue
                port = rr.get("port")
                if not host or not isinstance(port, int):
                    continue
                banner = str(rr.get("banner") or "")
                intel = rr.get("intel") or {}
                service = ""
                if isinstance(intel, dict):
                    service = str(intel.get("service") or "")
                svc_name = service or SERVICE_NAMES.get(int(port)) or APP_PORTS.get(int(port)) or f"Port {int(port)}"

                try:
                    d = scanner.devices.get(host)
                    if d is not None:
                        d.services[int(port)] = svc_name
                        if banner:
                            d.service_banners[int(port)] = banner
                except Exception:
                    pass
                try:
                    datastore.upsert_service(host, int(port), "tcp", svc_name, banner=banner)
                except Exception:
                    pass
                if banner:
                    nip_bus.publish(
                        event_type="service.banner",
                        source=src,
                        entity=host,
                        summary=f"Banner on tcp:{int(port)} for {host}",
                        data={"ip": host, "port": int(port), "service": svc_name, "banner": banner[:200], "intel": intel},
                    )
            return

        if action in ("http", "tls", "tcpfp", "dns", "passive-dns"):
            ent = str(result.get("host") or result.get("domain") or "network")
            summ = f"{action} completed"
            try:
                datastore.add_observation(
                    f"mod5.{action}",
                    ent,
                    summ,
                    {"source": src, "technique": result.get("technique", ""), "result": result},
                )
            except Exception:
                pass
            nip_bus.publish(
                event_type=f"app.{action}.completed",
                source=src,
                entity=ent,
                summary=summ,
                data={"technique": result.get("technique", "")},
            )
            # Passive DNS: register querying local IPs as devices
            if action == "passive-dns":
                import ipaddress as _ipa
                seen_ips = set()
                for q in (result.get("queries") or []):
                    if not isinstance(q, dict):
                        continue
                    sip = str(q.get("src_ip") or "").strip()
                    if sip and sip not in seen_ips:
                        seen_ips.add(sip)
                        try:
                            addr = _ipa.ip_address(sip)
                            if addr.is_private and not addr.is_multicast and not addr.is_loopback:
                                _nip_upsert_device_min(ip=sip, scan_profile=f"coursework_{module}_{action}")
                        except Exception:
                            pass
            return

    # --------------------
    # Module 6/7: passive + IDS -> observations (raw detail in logs/artifacts)
    # --------------------
    if module in ("mod6", "mod7"):
        try:
            datastore.add_observation(
                f"{module}.{action}",
                "network",
                f"{module} {action} completed",
                {"source": src, "technique": result.get("technique", ""), "result": result},
            )
        except Exception:
            pass
        nip_bus.publish(
            event_type=f"{module}.{action}.completed",
            source=src,
            entity="network",
            summary=f"{module} {action} completed",
            data={"technique": result.get("technique", "")},
        )
        # Promiscuous capture: register observed LOCAL IPs + MACs as devices
        if module == "mod6" and action == "promisc":
            import ipaddress as _ipa
            analysis = result.get("analysis") or {}
            for ip_str in (analysis.get("ips") or []):
                if not isinstance(ip_str, str):
                    continue
                ip_str = ip_str.strip()
                if not ip_str:
                    continue
                try:
                    addr = _ipa.ip_address(ip_str)
                    if addr.is_private and not addr.is_multicast and not addr.is_loopback:
                        _nip_upsert_device_min(ip=ip_str, scan_profile=f"coursework_{module}_{action}")
                except Exception:
                    pass
            # Also register MAC addresses for IP-MAC pairs from top_talkers
            for talker in (analysis.get("top_talkers") or []):
                if isinstance(talker, dict):
                    ip = str(talker.get("ip") or "").strip()
                    if ip:
                        try:
                            addr = _ipa.ip_address(ip)
                            if addr.is_private and not addr.is_multicast and not addr.is_loopback:
                                _nip_upsert_device_min(ip=ip, scan_profile=f"coursework_{module}_{action}")
                        except Exception:
                            pass
        return

    # --------------------
    # Extended modules: persist observations + best-effort asset/service enrichment.
    # --------------------
    if module in CW_EXT_MODULES:
        ent = str(
            result.get("target")
            or result.get("host")
            or result.get("domain")
            or params.get("target")
            or params.get("host")
            or params.get("network")
            or "network"
        )

        # IPv6 host discovery
        if module == "ipv6":
            rows = result.get("hosts") or result.get("results") or []
            for h in rows:
                if not isinstance(h, dict):
                    continue
                ip = str(h.get("ip") or h.get("ipv6") or "").strip()
                if not ip:
                    continue
                mac = str(h.get("mac") or h.get("derived_mac") or "").strip()
                _nip_upsert_device_min(ip=ip, mac=mac, scan_profile=f"coursework_{module}_{action}")
                nip_bus.publish(
                    event_type="device.discovered",
                    source=src,
                    entity=ip,
                    summary=f"Discovered IPv6 device {ip}",
                    data={"ip": ip, "mac": mac},
                )

        # DHCP leases -> hostname/vendor enrichment
        if module == "dhcp":
            for l in (result.get("leases") or []):
                if not isinstance(l, dict):
                    continue
                ip = str(l.get("assigned_ip") or "").strip()
                if not ip or ip == "0.0.0.0":
                    continue
                mac = str(l.get("client_mac") or "").strip()
                hostname = str(l.get("hostname") or "").strip()
                vendor = str(l.get("vendor_class") or "").strip()
                _nip_upsert_device_min(ip=ip, mac=mac, hostname=hostname, vendor=vendor, scan_profile=f"coursework_{module}_{action}")

        # Discovery protocols -> device identity hints
        if module == "discovery":
            if action == "ssdp":
                for d in (result.get("devices") or []):
                    if not isinstance(d, dict):
                        continue
                    ip = str(d.get("ip") or "").strip()
                    if not ip:
                        continue
                    desc = d.get("description") or {}
                    vendor = str((desc or {}).get("manufacturer") or "").strip()
                    hostname = str((desc or {}).get("friendlyName") or "").strip()
                    _nip_upsert_device_min(ip=ip, vendor=vendor, hostname=hostname, scan_profile=f"coursework_{module}_{action}")
            if action == "nbns":
                # Handle flat IP list in "hosts" (primary format returned by NBNS)
                for h in (result.get("hosts") or []):
                    if isinstance(h, str) and h.strip():
                        _nip_upsert_device_min(ip=h.strip(), scan_profile=f"coursework_{module}_{action}")
                    elif isinstance(h, dict):
                        ip = str(h.get("ip") or "").strip()
                        if ip:
                            _nip_upsert_device_min(ip=ip, scan_profile=f"coursework_{module}_{action}")
                # Handle detailed results with name/mac info
                for d in (result.get("results") or []):
                    if not isinstance(d, dict):
                        continue
                    ip = str(d.get("ip") or "").strip()
                    if not ip:
                        continue
                    mac = str(d.get("mac") or "").strip()
                    names = d.get("names") or []
                    hostname = ""
                    if isinstance(names, list) and names:
                        hostname = str((names[0] or {}).get("name") or "").strip()
                    _nip_upsert_device_min(ip=ip, mac=mac, hostname=hostname, scan_profile=f"coursework_{module}_{action}")
            if action == "wsd":
                for d in (result.get("devices") or []):
                    if not isinstance(d, dict):
                        continue
                    ip = str(d.get("ip") or "").strip()
                    if not ip:
                        continue
                    os_guess = str(d.get("types") or "").strip()
                    _nip_upsert_device_min(ip=ip, os_guess=os_guess[:120], scan_profile=f"coursework_{module}_{action}")

        # mDNS / mDNS-passive -> device + service type enrichment
        if module == "discovery" and action in ("mdns", "mdns-passive"):
            for d in (result.get("devices") or result.get("hosts") or []):
                if not isinstance(d, dict):
                    continue
                ip = str(d.get("ip") or d.get("host") or "").strip()
                if not ip:
                    continue
                hostname = str(d.get("hostname") or d.get("name") or "").strip()
                _nip_upsert_device_min(ip=ip, hostname=hostname, scan_profile=f"coursework_{module}_{action}")

        # LLMNR passive -> device discovery from name resolution
        if module == "discovery" and action in ("llmnr-passive",):
            for h in (result.get("hosts") or result.get("responders") or []):
                if not isinstance(h, dict):
                    continue
                ip = str(h.get("ip") or "").strip()
                if not ip:
                    continue
                hostname = str(h.get("name") or h.get("hostname") or "").strip()
                _nip_upsert_device_min(ip=ip, hostname=hostname, scan_profile=f"coursework_{module}_{action}")

        # ICMP sweep -> alive host inventory
        if module == "icmp" and action == "echo-sweep":
            for h in (result.get("alive_hosts") or []):
                if not isinstance(h, dict):
                    continue
                ip = str(h.get("ip") or "").strip()
                if not ip:
                    continue
                _nip_upsert_device_min(ip=ip, scan_profile=f"coursework_{module}_{action}")

        # ICMP OS fingerprint -> OS guess enrichment
        if module == "icmp" and action == "icmp-os-fp":
            ip = str(result.get("target") or result.get("host") or "").strip()
            os_guess = str(result.get("os_guess") or result.get("best_guess") or "").strip()
            if ip and os_guess:
                _nip_upsert_device_min(ip=ip, os_guess=os_guess, scan_profile=f"coursework_{module}_{action}")

        # SNMP + SSH -> service enrichment
        if module == "snmp" and action == "walk":
            ip = str(result.get("target") or "").strip()
            if ip:
                sysi = result.get("system") or {}
                hostname = str((sysi or {}).get("sysName") or "")
                os_guess = str((sysi or {}).get("sysDescr") or "")
                _nip_upsert_device_min(ip=ip, hostname=hostname, os_guess=os_guess, scan_profile=f"coursework_{module}_{action}")
                try:
                    datastore.upsert_service(ip, 161, "udp", "SNMP", banner="")
                except Exception:
                    pass

        if module == "ssh":
            ip = str(result.get("target") or "").strip()
            if ip:
                _nip_upsert_device_min(ip=ip, scan_profile=f"coursework_{module}_{action}")
                try:
                    datastore.upsert_service(ip, int(result.get("port") or 22), "tcp", "SSH", banner="")
                except Exception:
                    pass

        if module == "smb":
            ip = str(result.get("target") or "").strip()
            if ip:
                hostname = str(result.get("hostname") or "")
                os_guess = str(result.get("os") or "")
                _nip_upsert_device_min(ip=ip, hostname=hostname, os_guess=os_guess, scan_profile=f"coursework_{module}_{action}")
                try:
                    datastore.upsert_service(ip, 445, "tcp", "SMB", banner="")
                except Exception:
                    pass

        # Mod3 TCP stack / IPID / TTL fingerprinting -> OS guess
        if module == "mod3":
            ip = str(result.get("target") or result.get("host") or params.get("target") or "").strip()
            os_guess = str(result.get("best_guess") or result.get("os_guess") or "").strip()
            if ip and os_guess:
                _nip_upsert_device_min(ip=ip, os_guess=os_guess, scan_profile=f"coursework_{module}_{action}")

        # Passive DNS -> store top domains as observations for the story engine
        if module == "mod5" and action == "passive-dns":
            for td in (result.get("top_domains") or []):
                dom = ""
                if isinstance(td, dict):
                    dom = str(td.get("domain") or td.get("name") or "")
                elif isinstance(td, (list, tuple)) and td:
                    dom = str(td[0])
                if dom:
                    try:
                        datastore.add_observation("dns.query", dom, f"DNS query: {dom}", {"source": src, "domain": dom})
                    except Exception:
                        pass

        # TLS JA3 -> extract SNI domains into observations for the story engine
        if module == "tls" and action in ("ja3", "ja3s"):
            import ipaddress as _ipa
            for fp in (result.get("fingerprints") or []):
                sni = str(fp.get("sni") or "").strip()
                src_ip = str(fp.get("src_ip") or "").strip()
                dst_ip = str(fp.get("dst_ip") or "").strip()
                if sni:
                    try:
                        datastore.add_observation(
                            "tls.sni", sni, f"TLS connection to {sni} from {src_ip}",
                            {"source": src, "sni": sni, "src_ip": src_ip, "dst_ip": dst_ip}
                        )
                    except Exception:
                        pass
                # Register source (local) device
                if src_ip:
                    try:
                        addr = _ipa.ip_address(src_ip)
                        if addr.is_private and not addr.is_multicast and not addr.is_loopback:
                            _nip_upsert_device_min(ip=src_ip, scan_profile=f"coursework_{module}_{action}")
                    except Exception:
                        pass
                # Register destination with SNI hostname
                if dst_ip:
                    _nip_upsert_device_min(ip=dst_ip, hostname=(sni or ""), scan_profile=f"coursework_{module}_{action}")

        if module == "iot":
            ip = str(result.get("target") or "").strip()
            if ip:
                _nip_upsert_device_min(ip=ip, scan_profile=f"coursework_{module}_{action}")
                if action == "mqtt-enum":
                    try:
                        datastore.upsert_service(ip, int(result.get("port") or 1883), "tcp", "MQTT", banner="")
                    except Exception:
                        pass
                if action == "coap-discover":
                    try:
                        datastore.upsert_service(ip, int(result.get("port") or 5683), "udp", "CoAP", banner="")
                    except Exception:
                        pass

        try:
            datastore.add_observation(
                f"{module}.{action}",
                ent,
                f"{module} {action} completed",
                {"source": src, "technique": result.get("technique", ""), "result": result},
            )
        except Exception:
            pass
        nip_bus.publish(
            event_type=f"{module}.{action}.completed",
            source=src,
            entity=ent,
            summary=f"{module} {action} completed",
            data={"technique": result.get("technique", "")},
        )
        return


def run_coursework_action(*, module: str, action: str, params: dict) -> Tuple[dict, str]:
    """Execute a rubric technique and write a JSON log under logs/mod*/.

    Returns (result, log_path).
    """
    from toolkit.utils import ensure_private_target, infer_local_ip, new_session_id, utc_now_iso, write_json_log

    module = str(module or "").strip()
    action = str(action or "").strip()
    params = params or {}

    if module not in CW_RUN_MODULES:
        raise ValueError(f"Invalid module: {module}")

    started_at = utc_now_iso()
    scanner_local_ip = getattr(scanner, "local_ip", None) or infer_local_ip()

    # Root/scapy requirements by registry metadata (fallback to legacy hard-coded rules).
    requires_root = False
    requires_scapy = False
    tmeta = _nip_find_technique(module, action)
    if tmeta is not None:
        requires_root = bool(getattr(tmeta, "requires_root", False))
        requires_scapy = bool(getattr(tmeta, "requires_scapy", False))
    else:
        if module in ("mod1", "mod3", "mod4", "mod6"):
            requires_root = True
            requires_scapy = True
        if module == "mod2" and action in ("syn", "fin", "xmas", "null", "udp", "ack"):
            requires_root = True
            requires_scapy = True
        if module == "mod5" and action in ("tcpfp", "passive-dns"):
            requires_root = True
            requires_scapy = True
        if module == "mod7" and action in ("arpwatch",):
            requires_root = True
            requires_scapy = True

    if requires_scapy and not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not available on the server; cannot run this technique.")
    if requires_root and not _cw_is_root():
        raise RuntimeError("This technique requires root privileges. Start the server with sudo.")

    # Execute.
    result: dict

    if module == "mod1":
        from mod1.link_layer_discovery import active_arp_enumeration, mac_randomization_session, passive_arp_observation

        network = str(params.get("network") or scanner.network_cidr)
        interface = params.get("interface")
        max_hosts = params.get("max_hosts")
        duration = int(params.get("duration") or 600)

        ensure_private_target(network)
        if action == "active":
            result = active_arp_enumeration(network=network, interface=interface, max_hosts=max_hosts)
        elif action == "passive":
            result = passive_arp_observation(interface=str(interface or conf.iface), duration=duration)
        elif action == "randomized":
            result = mac_randomization_session(network=network, interface=interface, max_hosts=max_hosts)
        else:
            raise ValueError(f"Invalid action for mod1: {action}")

    elif module == "mod2":
        from mod2.transport_scans import (
            ack_scan,
            tcp_connect_scan,
            tcp_flag_scan,
            tcp_syn_scan,
            udp_scan,
        )

        hosts = _cw_parse_hosts(params.get("hosts") or params.get("host"))
        ports = _cw_parse_ports(params.get("ports"))
        timeout = float(params.get("timeout") or 1.0)
        rate_delay = float(params.get("rate_delay") or 0.0)
        jitter_mode = str(params.get("jitter_mode") or "none")
        jitter_arg = float(params.get("jitter_arg") or 0.0)
        shuffle = bool(params.get("shuffle") or False)

        if not hosts:
            raise ValueError("mod2 requires host(s)")
        for h in hosts:
            ensure_private_target(h)
        if not ports:
            raise ValueError("mod2 requires ports")

        if action == "syn":
            result = tcp_syn_scan(hosts, ports, timeout=timeout, rate_delay=rate_delay, jitter_mode=jitter_mode, jitter_arg=jitter_arg, shuffle=shuffle)
        elif action == "connect":
            result = tcp_connect_scan(hosts, ports, timeout=timeout, rate_delay=rate_delay, jitter_mode=jitter_mode, jitter_arg=jitter_arg, shuffle=shuffle)
        elif action == "fin":
            result = tcp_flag_scan("tcp_fin_scan", "F", hosts, ports, timeout=timeout, rate_delay=rate_delay, jitter_mode=jitter_mode, jitter_arg=jitter_arg, shuffle=shuffle)
        elif action == "xmas":
            result = tcp_flag_scan("tcp_xmas_scan", "FPU", hosts, ports, timeout=timeout, rate_delay=rate_delay, jitter_mode=jitter_mode, jitter_arg=jitter_arg, shuffle=shuffle)
        elif action == "null":
            result = tcp_flag_scan("tcp_null_scan", "", hosts, ports, timeout=timeout, rate_delay=rate_delay, jitter_mode=jitter_mode, jitter_arg=jitter_arg, shuffle=shuffle)
        elif action == "udp":
            result = udp_scan(hosts, ports, timeout=timeout, rate_delay=rate_delay, jitter_mode=jitter_mode, jitter_arg=jitter_arg, shuffle=shuffle)
        elif action == "ack":
            result = ack_scan(hosts, ports, timeout=timeout, rate_delay=rate_delay, jitter_mode=jitter_mode, jitter_arg=jitter_arg, shuffle=shuffle)
        else:
            raise ValueError(f"Invalid action for mod2: {action}")

    elif module == "mod3":
        from mod3.ip_layer_techniques import (
            decoy_source_mixing,
            fragmentation_test,
            idle_scan,
            ipid_sequence_profile,
            ipid_sweep,
            ttl_path_inference,
        )

        lab_ok = bool(params.get("lab_ok") or False)
        target = params.get("target")
        zombie = params.get("zombie")

        if action == "frag":
            if not target:
                raise ValueError("mod3 frag requires target")
            ensure_private_target(str(target))
            result = fragmentation_test(
                str(target),
                int(params.get("dport") or 80),
                timeout=float(params.get("timeout") or 2.0),
                fragsize=int(params.get("fragsize") or 8),
                overlap=bool(params.get("overlap") or False),
            )
        elif action == "ttl":
            if not target:
                raise ValueError("mod3 ttl requires target")
            ensure_private_target(str(target))
            result = ttl_path_inference(
                str(target),
                max_hops=int(params.get("max_hops") or 20),
                timeout=float(params.get("timeout") or 1.0),
                method=str(params.get("method") or "icmp"),
                dport=int(params.get("dport") or 80),
            )
        elif action == "ipid":
            if not zombie:
                raise ValueError("mod3 ipid requires zombie")
            ensure_private_target(str(zombie))
            result = ipid_sequence_profile(
                str(zombie),
                probes=int(params.get("probes") or 20),
                interval=float(params.get("interval") or 0.2),
                timeout=float(params.get("timeout") or 1.0),
            )
        elif action == "ipid-sweep":
            hosts = _cw_parse_hosts(params.get("hosts") or params.get("host"))
            if not hosts:
                network = str(params.get("network") or scanner.network_cidr)
                ensure_private_target(network)
                from toolkit.utils import hosts_from_network

                max_hosts = int(params.get("max_hosts") or 64)
                hosts = hosts_from_network(network, max_hosts=max_hosts)
            for h in hosts:
                ensure_private_target(h)
            result = ipid_sweep(
                hosts,
                probes=int(params.get("probes") or 12),
                interval=float(params.get("interval") or 0.15),
                timeout=float(params.get("timeout") or 1.0),
            )
        elif action == "idle":
            if not lab_ok:
                raise ValueError("mod3 idle requires lab_ok acknowledgement")
            if not zombie or not target:
                raise ValueError("mod3 idle requires zombie and target")
            ensure_private_target(str(zombie))
            ensure_private_target(str(target))
            result = idle_scan(str(zombie), str(target), int(params.get("dport") or 80), timeout=float(params.get("timeout") or 1.0))
        elif action == "decoy":
            if not lab_ok:
                raise ValueError("mod3 decoy requires lab_ok acknowledgement")
            if not target:
                raise ValueError("mod3 decoy requires target")
            ensure_private_target(str(target))
            decoys = _cw_parse_hosts(params.get("decoys") or params.get("decoy"))
            for d in decoys:
                ensure_private_target(d)
            result = decoy_source_mixing(
                str(target),
                int(params.get("dport") or 80),
                decoys=decoys,
                real_probes=int(params.get("real_probes") or 5),
                timeout=float(params.get("timeout") or 1.0),
            )
        else:
            raise ValueError(f"Invalid action for mod3: {action}")

    elif module == "mod4":
        from mod4.timing_rate_control import fixed_rate_profiles, jitter_experiment, ordering_randomization

        hosts = _cw_parse_hosts(params.get("hosts") or params.get("host"))
        network = params.get("network")
        ports = _cw_parse_ports(params.get("ports") or "22,80,443")
        timeout = float(params.get("timeout") or 1.0)
        max_tuples = int(params.get("max_tuples") or 10)

        if not hosts:
            if not network:
                raise ValueError("mod4 requires host(s) or network")
            ensure_private_target(str(network))
            from toolkit.utils import hosts_from_network

            hosts = hosts_from_network(str(network), max_hosts=max(1, max_tuples))
        for h in hosts:
            ensure_private_target(h)
        if not ports:
            raise ValueError("mod4 requires ports")

        tuples = [(h, p) for h in hosts for p in ports][: max(1, max_tuples)]

        if action == "fixed":
            result = fixed_rate_profiles(tuples, timeout=timeout)
        elif action == "jitter":
            result = jitter_experiment(tuples, timeout=timeout, base_delay=float(params.get("base_delay") or 0.4))
        elif action == "order":
            result = ordering_randomization(tuples, timeout=timeout, delay=float(params.get("delay") or 0.4))
        else:
            raise ValueError(f"Invalid action for mod4: {action}")

    elif module == "mod5":
        from mod5.app_fingerprinting import (
            banner_grabbing,
            dns_enumeration,
            http_header_analysis,
            passive_dns_monitor,
            tcp_stack_fingerprint,
            tls_certificate_inspection,
        )

        if action == "banner":
            host = str(params.get("host") or "")
            ports = _cw_parse_ports(params.get("ports") or "21,22,25,80,443")
            if not host:
                raise ValueError("mod5 banner requires host")
            ensure_private_target(host)
            result = banner_grabbing(host, ports, timeout=float(params.get("timeout") or 2.0))
        elif action == "tls":
            host = str(params.get("host") or "")
            if not host:
                raise ValueError("mod5 tls requires host")
            ensure_private_target(host)
            result = tls_certificate_inspection(host, port=int(params.get("port") or 443), timeout=float(params.get("timeout") or 6.0))
        elif action == "http":
            host = str(params.get("host") or "")
            if not host:
                raise ValueError("mod5 http requires host")
            ensure_private_target(host)
            result = http_header_analysis(
                host,
                port=int(params.get("port") or 80),
                timeout=float(params.get("timeout") or 3.0),
                use_tls=bool(params.get("use_tls") or False),
            )
        elif action == "tcpfp":
            host = str(params.get("host") or "")
            if not host:
                raise ValueError("mod5 tcpfp requires host")
            ensure_private_target(host)
            result = tcp_stack_fingerprint(host, dport=int(params.get("dport") or 80), timeout=float(params.get("timeout") or 1.0))
        elif action == "dns":
            domain = str(params.get("domain") or "").strip()
            server = str(params.get("server") or "8.8.8.8").strip()
            if not domain:
                raise ValueError("mod5 dns requires domain")
            reverse_cidr = str(params.get("reverse_cidr") or params.get("reverseCidr") or "").strip()
            try:
                reverse_max = int(params.get("reverse_max") or params.get("reverseMax") or 256)
            except Exception:
                reverse_max = 256
            result = dns_enumeration(
                domain,
                server=server,
                reverse_cidr=(reverse_cidr or None),
                reverse_max=reverse_max,
            )
        elif action == "passive-dns":
            interface = str(params.get("interface") or conf.iface)
            result = passive_dns_monitor(interface, duration=int(params.get("duration") or 60))
        else:
            raise ValueError(f"Invalid action for mod5: {action}")

    elif module == "mod6":
        from mod6.passive_collection import ingest_pcap, netflow_collect, promisc_capture

        if action == "promisc":
            interface = str(params.get("interface") or conf.iface)
            result = promisc_capture(
                interface,
                duration=int(params.get("duration") or 60),
                bpf=str(params.get("bpf") or ""),
                pcap_out=str(params.get("pcap_out") or params.get("pcapOut") or ""),
            )
        elif action == "pcap":
            path = str(params.get("path") or "")
            if not path:
                raise ValueError("mod6 pcap requires path")
            result = ingest_pcap(path)
        elif action == "netflow":
            result = netflow_collect(
                str(params.get("listen_host") or "0.0.0.0"),
                int(params.get("listen_port") or 2055),
                duration=int(params.get("duration") or 60),
            )
        else:
            raise ValueError(f"Invalid action for mod6: {action}")

    elif module == "mod7":
        from mod7.arpwatch_like import arpwatch_monitor
        from mod7.detection_matrix import build_detection_matrix, PROJECT_ROOT as DM_ROOT
        from mod7.ids_offline import suricata_offline, zeek_offline
        from mod7.netflow_detect import netflow_detect

        if action == "arpwatch":
            interface = str(params.get("interface") or conf.iface)
            result = arpwatch_monitor(interface, duration=int(params.get("duration") or 300))
        elif action == "suricata-offline":
            pcap_path = str(params.get("pcap_path") or params.get("pcap") or params.get("path") or "").strip()
            if not pcap_path:
                raise ValueError("mod7 suricata-offline requires pcap_path")
            result = suricata_offline(
                pcap_path=pcap_path,
                rules_path=str(params.get("rules_path") or "") or None,
                config_path=str(params.get("config_path") or "") or None,
                timeout_seconds=int(params.get("timeout_seconds") or 120),
            )
        elif action == "zeek-offline":
            pcap_path = str(params.get("pcap_path") or params.get("pcap") or params.get("path") or "").strip()
            if not pcap_path:
                raise ValueError("mod7 zeek-offline requires pcap_path")
            result = zeek_offline(
                pcap_path=pcap_path,
                script_path=str(params.get("script_path") or "") or None,
                timeout_seconds=int(params.get("timeout_seconds") or 120),
            )
        elif action == "netflow-detect":
            result = netflow_detect(
                listen_host=str(params.get("listen_host") or "0.0.0.0"),
                listen_port=int(params.get("listen_port") or 2055),
                duration=int(params.get("duration") or 60),
                window_seconds=int(params.get("window_seconds") or 10),
                unique_port_threshold=int(params.get("unique_port_threshold") or 20),
                unique_dst_threshold=int(params.get("unique_dst_threshold") or 15),
                long_flow_ms=int(params.get("long_flow_ms") or 30000),
            )
        elif action == "detection-matrix":
            suri = params.get("suricata_eve")
            zeek = params.get("zeek_notice")
            out_json = DM_ROOT / "report" / "detection_matrix.json"
            out_md = DM_ROOT / "report" / "detection_matrix.md"
            result = build_detection_matrix(
                logs_dir=DM_ROOT / "logs",
                suricata_eve=(Path(str(suri)) if suri else None),
                zeek_notice=(Path(str(zeek)) if zeek else None),
                out_json=out_json,
                out_md=out_md,
            )
        else:
            raise ValueError(f"Invalid action for mod7: {action}")

    elif module == "ipv6":
        from ipv6.ipv6_discovery import (
            ipv6_neighbor_discovery,
            ipv6_passive_ndp,
            ipv6_router_advertisement_scan,
            ipv6_slaac_fingerprint,
        )

        if action == "nd-scan":
            result = ipv6_neighbor_discovery(
                interface=str(params.get("interface") or conf.iface),
                probes=int(params.get("probes") or 2),
                inter=float(params.get("inter") or 0.2),
                timeout=float(params.get("timeout") or 3.0),
            )
        elif action == "ra-scan":
            result = ipv6_router_advertisement_scan(
                interface=str(params.get("interface") or conf.iface),
                probes=int(params.get("probes") or 2),
                inter=float(params.get("inter") or 0.2),
                timeout=float(params.get("timeout") or 3.0),
            )
        elif action == "passive-ndp":
            result = ipv6_passive_ndp(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
            )
        elif action == "slaac-fp":
            addrs = params.get("addresses") or params.get("ipv6_addresses") or []
            if isinstance(addrs, str):
                addrs = [x.strip() for x in addrs.split(",") if x.strip()]
            if not isinstance(addrs, list):
                addrs = []
            if not addrs:
                # Best-effort from current assets inventory.
                addrs = [a.get("ip") for a in datastore.list_assets(limit=4000) if isinstance(a, dict) and ":" in str(a.get("ip") or "")]
            result = ipv6_slaac_fingerprint(addrs)
        else:
            raise ValueError(f"Invalid action for ipv6: {action}")

    elif module == "dhcp":
        from dhcp.dhcp_intel import dhcp_fingerprint, passive_dhcp_monitor, rogue_dhcp_server_detection

        if action == "passive-dhcp":
            result = passive_dhcp_monitor(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
            )
        elif action == "fingerprint":
            result = dhcp_fingerprint(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
            )
        elif action == "rogue-detect":
            result = rogue_dhcp_server_detection(
                interface=str(params.get("interface") or conf.iface),
                known_server_ip=str(params.get("known_server_ip") or params.get("knownServerIp") or ""),
                timeout=float(params.get("timeout") or 3.0),
            )
        else:
            raise ValueError(f"Invalid action for dhcp: {action}")

    elif module == "discovery":
        from discovery.multicast_discovery import (
            llmnr_passive_monitor,
            mdns_discovery,
            mdns_passive_monitor,
            nbns_node_status_query,
            ssdp_upnp_discovery,
            wsd_discovery,
        )

        if action == "mdns":
            result = mdns_discovery(
                interface=str(params.get("interface") or conf.iface),
                timeout=float(params.get("timeout") or 2.5),
            )
        elif action == "mdns-passive":
            result = mdns_passive_monitor(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
            )
        elif action == "ssdp":
            result = ssdp_upnp_discovery(
                interface=str(params.get("interface") or conf.iface),
                timeout=float(params.get("timeout") or 3.0),
                fetch_description=not bool(params.get("no_fetch") or params.get("noFetch") or False),
            )
        elif action == "nbns":
            hosts = _cw_parse_hosts(params.get("hosts") or params.get("host"))
            if not hosts:
                network = str(params.get("network") or scanner.network_cidr)
                ensure_private_target(network)
                from toolkit.utils import hosts_from_network

                hosts = hosts_from_network(network, max_hosts=int(params.get("max_hosts") or params.get("maxHosts") or 64))
            for h in hosts:
                ensure_private_target(h)
            result = nbns_node_status_query(hosts, timeout=float(params.get("timeout") or 1.2))
        elif action == "llmnr-passive":
            result = llmnr_passive_monitor(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
            )
        elif action == "wsd":
            result = wsd_discovery(
                interface=str(params.get("interface") or conf.iface),
                timeout=float(params.get("timeout") or 3.0),
            )
        else:
            raise ValueError(f"Invalid action for discovery: {action}")

    elif module == "icmp":
        from icmp.icmp_recon import icmp_address_mask_request, icmp_echo_sweep, icmp_os_fingerprint, icmp_timestamp_request

        if action == "echo-sweep":
            network = str(params.get("network") or scanner.network_cidr)
            ensure_private_target(network)
            result = icmp_echo_sweep(
                network=network,
                timeout=float(params.get("timeout") or 1.0),
                inter=float(params.get("inter") or 0.0),
                max_hosts=int(params.get("max_hosts") or params.get("maxHosts") or 512),
                shuffle=bool(params.get("shuffle") if params.get("shuffle") is not None else True),
            )
        elif action == "timestamp":
            target = str(params.get("target") or params.get("host") or "")
            if not target:
                raise ValueError("icmp timestamp requires target")
            ensure_private_target(target)
            result = icmp_timestamp_request(target, timeout=float(params.get("timeout") or 1.5))
        elif action == "address-mask":
            target = str(params.get("target") or params.get("host") or "")
            if not target:
                raise ValueError("icmp address-mask requires target")
            ensure_private_target(target)
            result = icmp_address_mask_request(target, timeout=float(params.get("timeout") or 1.5))
        elif action == "icmp-os-fp":
            target = str(params.get("target") or params.get("host") or "")
            if not target:
                raise ValueError("icmp icmp-os-fp requires target")
            ensure_private_target(target)
            result = icmp_os_fingerprint(target, timeout=float(params.get("timeout") or 1.0))
        else:
            raise ValueError(f"Invalid action for icmp: {action}")

    elif module == "tls":
        from tls.tls_fingerprints import encrypted_traffic_classification, ja3_passive_capture, ja3s_passive_capture

        ports = _cw_parse_ports(params.get("ports") or "443,8443,853")
        if action == "ja3":
            result = ja3_passive_capture(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
                ports=ports,
            )
        elif action == "ja3s":
            result = ja3s_passive_capture(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
                ports=ports,
            )
        elif action == "traffic-classify":
            result = encrypted_traffic_classification(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
            )
        else:
            raise ValueError(f"Invalid action for tls: {action}")

    elif module == "dns":
        from dns.dns_advanced import dns_dga_detection, dns_doh_dot_detection, dns_tunnel_detection

        if action == "tunnel-detect":
            result = dns_tunnel_detection(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
                entropy_threshold=float(params.get("entropy_threshold") or params.get("entropyThreshold") or 3.5),
                label_len_threshold=int(params.get("label_len_threshold") or params.get("labelLenThreshold") or 30),
            )
        elif action == "doh-detect":
            extra = params.get("extra_snis") or params.get("extraSnis") or []
            if isinstance(extra, str):
                extra = [x.strip() for x in extra.split(",") if x.strip()]
            if not isinstance(extra, list):
                extra = []
            result = dns_doh_dot_detection(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
                extra_snis=extra,
            )
        elif action == "dga-detect":
            result = dns_dga_detection(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
                score_threshold=float(params.get("score_threshold") or params.get("scoreThreshold") or 0.7),
            )
        else:
            raise ValueError(f"Invalid action for dns: {action}")

    elif module == "snmp":
        from snmp.snmp_enum import snmp_walk

        if action == "walk":
            target = str(params.get("target") or params.get("host") or "")
            if not target:
                raise ValueError("snmp walk requires target")
            ensure_private_target(target)
            result = snmp_walk(
                target,
                community=str(params.get("community") or "public"),
                mode=str(params.get("mode") or "system"),
            )
        else:
            raise ValueError(f"Invalid action for snmp: {action}")

    elif module == "ssh":
        from ssh.ssh_analysis import ssh_algorithm_audit, ssh_host_key_fingerprint

        target = str(params.get("target") or params.get("host") or "")
        if not target:
            raise ValueError("ssh module requires target")
        ensure_private_target(target)
        if action == "host-key-fp":
            result = ssh_host_key_fingerprint(
                target,
                port=int(params.get("port") or 22),
                timeout_seconds=int(params.get("timeout_seconds") or params.get("timeoutSeconds") or 4),
            )
        elif action == "algo-audit":
            result = ssh_algorithm_audit(
                target,
                port=int(params.get("port") or 22),
                timeout_seconds=int(params.get("timeout_seconds") or params.get("timeoutSeconds") or 10),
            )
        else:
            raise ValueError(f"Invalid action for ssh: {action}")

    elif module == "smb":
        from smb.smb_enum import smb_enum_sessions, smb_enum_shares, smb_os_discovery

        target = str(params.get("target") or params.get("host") or "")
        if not target:
            raise ValueError("smb module requires target")
        ensure_private_target(target)
        if action == "enum-shares":
            result = smb_enum_shares(target)
        elif action == "enum-sessions":
            result = smb_enum_sessions(target)
        elif action == "os-discovery":
            result = smb_os_discovery(target)
        else:
            raise ValueError(f"Invalid action for smb: {action}")

    elif module == "iot":
        from iot.iot_enum import coap_discovery, mqtt_enum

        target = str(params.get("target") or params.get("host") or "")
        if not target:
            raise ValueError("iot module requires target")
        ensure_private_target(target)
        if action == "mqtt-enum":
            result = mqtt_enum(
                target,
                port=int(params.get("port") or 1883),
                duration=int(params.get("duration") or 8),
                subscribe_topic=str(params.get("subscribe_topic") or params.get("subscribeTopic") or "#"),
            )
        elif action == "coap-discover":
            result = coap_discovery(
                target,
                port=int(params.get("port") or 5683),
                timeout=float(params.get("timeout") or 2.0),
            )
        else:
            raise ValueError(f"Invalid action for iot: {action}")

    elif module == "wifi":
        from wifi.wifi_scan import wifi_passive_scan

        if action == "passive-scan":
            result = wifi_passive_scan(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
            )
        else:
            raise ValueError(f"Invalid action for wifi: {action}")

    elif module == "vlan":
        from vlan.vlan_discovery import vlan_discovery

        if action == "discover":
            result = vlan_discovery(
                interface=str(params.get("interface") or conf.iface),
                duration=int(params.get("duration") or 60),
            )
        else:
            raise ValueError(f"Invalid action for vlan: {action}")

    elif module == "analysis":
        from analysis.analysis_engine import (
            community_detect_label_propagation,
            compute_baseline_from_metrics,
            compute_device_features,
            identity_resolve,
            reconstruct_attack_chain,
            risk_score_devices,
            score_anomaly,
        )

        if action == "compute-baseline":
            ip = str(params.get("ip") or params.get("device_id") or params.get("deviceId") or "").strip()
            if not ip:
                raise ValueError("analysis compute-baseline requires ip/device_id")
            ensure_private_target(ip)
            metrics = datastore.list_nip_metrics(ip=ip, limit=int(params.get("limit") or 240))
            result = compute_baseline_from_metrics(
                metrics,
                decay=float(params.get("decay") or 0.97),
                min_windows=int(params.get("min_windows") or params.get("minWindows") or 6),
            )
            result["ip"] = ip
        elif action == "anomaly-score":
            ip = str(params.get("ip") or params.get("device_id") or params.get("deviceId") or "").strip()
            if not ip:
                raise ValueError("analysis anomaly-score requires ip/device_id")
            ensure_private_target(ip)
            metrics = datastore.list_nip_metrics(ip=ip, limit=int(params.get("limit") or 240))
            if not metrics:
                raise ValueError("No metrics available for this ip; start capture/daemon first.")
            latest_metric = metrics[0]
            base_row = datastore.get_nip_baseline(ip) or {}
            base_obj = base_row.get("baseline") if isinstance(base_row, dict) else {}
            if not base_obj:
                base_obj = (compute_baseline_from_metrics(metrics).get("baseline") or {})
            active_hours = compute_baseline_from_metrics(metrics).get("active_hours") or []
            result = score_anomaly(metric=latest_metric, baseline=base_obj, active_hours=active_hours)
            result["ip"] = ip
            result["metric"] = latest_metric
            result["baseline"] = base_obj
        elif action == "identity-resolve":
            new_ip = str(params.get("new_ip") or params.get("newIp") or params.get("ip") or "").strip()
            if not new_ip:
                raise ValueError("analysis identity-resolve requires new_ip/ip")
            ensure_private_target(new_ip)
            candidate_ips = _cw_parse_hosts(params.get("candidate_ips") or params.get("candidateIps") or params.get("candidates"))
            if not candidate_ips:
                candidate_ips = [
                    str(a.get("ip"))
                    for a in datastore.list_assets(limit=4000)
                    if isinstance(a, dict) and str(a.get("ip") or "") and str(a.get("ip")) != new_ip
                ][:100]
            for cip in candidate_ips:
                ensure_private_target(cip)
            flows = datastore.list_flows(limit=int(params.get("flows_limit") or params.get("flowsLimit") or 12000))
            with datastore.lock, datastore._connect() as conn:
                dns_rows = conn.execute(
                    "SELECT src_ip, domain, query_type, resolved_ip, timestamp FROM dns_queries ORDER BY id DESC LIMIT ?",
                    (int(params.get("dns_limit") or params.get("dnsLimit") or 12000),),
                ).fetchall()
            dns_queries = [
                {
                    "src_ip": r["src_ip"],
                    "domain": r["domain"],
                    "query_type": r["query_type"],
                    "resolved_ip": r["resolved_ip"],
                    "timestamp": r["timestamp"],
                }
                for r in dns_rows
            ]
            new_feat = compute_device_features(ip=new_ip, flows=flows, dns_queries=dns_queries, top_n=int(params.get("top_n") or params.get("topN") or 20))
            cands = []
            for cip in candidate_ips:
                cands.append(compute_device_features(ip=cip, flows=flows, dns_queries=dns_queries, top_n=int(params.get("top_n") or params.get("topN") or 20)))
            result = identity_resolve(new_features=new_feat, candidates=cands, threshold=float(params.get("threshold") or 0.85))
        elif action == "community-detect":
            flows = datastore.list_flows(limit=int(params.get("limit") or 15000))
            result = community_detect_label_propagation(flows, max_iter=int(params.get("max_iter") or params.get("maxIter") or 20))
        elif action == "risk-score":
            assets = datastore.list_assets(limit=int(params.get("assets_limit") or params.get("assetsLimit") or 4000))
            services = datastore.list_services(limit=int(params.get("services_limit") or params.get("servicesLimit") or 12000))
            flows = datastore.list_flows(limit=int(params.get("flows_limit") or params.get("flowsLimit") or 12000))
            with datastore.lock, datastore._connect() as conn:
                a_rows = conn.execute(
                    "SELECT alert_type, severity, message, src_ip, dst_ip, timestamp, details_json FROM alerts ORDER BY id DESC LIMIT ?",
                    (int(params.get("alerts_limit") or params.get("alertsLimit") or 2000),),
                ).fetchall()
            alerts = []
            for r in a_rows:
                try:
                    details = json.loads(r["details_json"] or "{}")
                except Exception:
                    details = {}
                alerts.append(
                    {
                        "alert_type": r["alert_type"],
                        "severity": r["severity"],
                        "message": r["message"],
                        "src_ip": r["src_ip"],
                        "dst_ip": r["dst_ip"],
                        "timestamp": r["timestamp"],
                        "details": details,
                    }
                )
            threat_matches = [a for a in alerts if str(a.get("alert_type") or "") == "threat_match"]
            result = risk_score_devices(assets=assets, services=services, flows=flows, alerts=alerts, threat_matches=threat_matches)
        elif action == "attack-chain":
            with datastore.lock, datastore._connect() as conn:
                a_rows = conn.execute(
                    "SELECT alert_type, severity, message, src_ip, dst_ip, timestamp, details_json FROM alerts ORDER BY id DESC LIMIT ?",
                    (int(params.get("alerts_limit") or params.get("alertsLimit") or 2000),),
                ).fetchall()
            alerts = []
            for r in a_rows:
                alerts.append(
                    {
                        "alert_type": r["alert_type"],
                        "severity": r["severity"],
                        "message": r["message"],
                        "src_ip": r["src_ip"],
                        "dst_ip": r["dst_ip"],
                        "timestamp": r["timestamp"],
                    }
                )
            observations = datastore.get_recent_observations(limit=int(params.get("observations_limit") or params.get("observationsLimit") or 2000))
            result = reconstruct_attack_chain(alerts, observations)
        elif action == "temporal-correlate":
            anchor_ts = str(params.get("ts") or params.get("anchor") or params.get("anchor_ts") or "").strip()
            entity = str(params.get("entity") or params.get("ip") or "").strip()
            if not anchor_ts:
                raise ValueError("analysis temporal-correlate requires ts/anchor")
            window = max(10, int(params.get("window_seconds") or params.get("windowSeconds") or 300))
            try:
                center = datetime.fromisoformat(anchor_ts)
            except Exception:
                raise ValueError("Invalid anchor timestamp; expected ISO-8601")
            start_ts = (center - timedelta(seconds=window)).isoformat()
            end_ts = (center + timedelta(seconds=window)).isoformat()
            obs = datastore.list_observations_range(start_ts=start_ts, end_ts=end_ts, like=entity, limit=int(params.get("limit") or 500))
            m = datastore.list_nip_metrics_range(ip=entity, start_ts=start_ts, end_ts=end_ts, limit=int(params.get("metrics_limit") or params.get("metricsLimit") or 500)) if entity else []
            result = {
                "technique": "analysis_temporal_correlation",
                "anchor_ts": anchor_ts,
                "window_seconds": window,
                "entity_filter": entity,
                "window": {"start": start_ts, "end": end_ts},
                "observations": obs,
                "metrics": m,
                "counts": {"observations": len(obs), "metrics": len(m)},
            }
        elif action == "graph-diff":
            t1 = str(params.get("t1") or "").strip()
            t2 = str(params.get("t2") or "").strip()
            if not t1 or not t2:
                raise ValueError("analysis graph-diff requires t1 and t2 ISO timestamps")
            a1 = datastore.list_assets(limit=int(params.get("assets_limit") or 4000), as_of=t1)
            a2 = datastore.list_assets(limit=int(params.get("assets_limit") or 4000), as_of=t2)
            s1 = datastore.list_services(limit=int(params.get("services_limit") or 12000), as_of=t1)
            s2 = datastore.list_services(limit=int(params.get("services_limit") or 12000), as_of=t2)
            f1 = datastore.list_flows(limit=int(params.get("flows_limit") or 12000), as_of=t1)
            f2 = datastore.list_flows(limit=int(params.get("flows_limit") or 12000), as_of=t2)

            aset1 = {str(x.get("ip")) for x in a1 if isinstance(x, dict) and x.get("ip")}
            aset2 = {str(x.get("ip")) for x in a2 if isinstance(x, dict) and x.get("ip")}
            sv1 = {f"{x.get('ip')}:{x.get('port')}/{x.get('protocol')}" for x in s1 if isinstance(x, dict)}
            sv2 = {f"{x.get('ip')}:{x.get('port')}/{x.get('protocol')}" for x in s2 if isinstance(x, dict)}
            fl1 = {str(x.get("flow_key")) for x in f1 if isinstance(x, dict) and x.get("flow_key")}
            fl2 = {str(x.get("flow_key")) for x in f2 if isinstance(x, dict) and x.get("flow_key")}

            result = {
                "technique": "analysis_graph_diff",
                "t1": t1,
                "t2": t2,
                "new_nodes": sorted(list(aset2 - aset1)),
                "disappeared_nodes": sorted(list(aset1 - aset2)),
                "new_services": sorted(list(sv2 - sv1)),
                "disappeared_services": sorted(list(sv1 - sv2)),
                "new_edges": sorted(list(fl2 - fl1)),
                "disappeared_edges": sorted(list(fl1 - fl2)),
                "counts": {
                    "new_nodes": len(aset2 - aset1),
                    "disappeared_nodes": len(aset1 - aset2),
                    "new_services": len(sv2 - sv1),
                    "disappeared_services": len(sv1 - sv2),
                    "new_edges": len(fl2 - fl1),
                    "disappeared_edges": len(fl1 - fl2),
                },
            }
        else:
            raise ValueError(f"Invalid action for analysis: {action}")

    elif module == "threat":
        from threat.threat_lookup import cve_lookup, domain_reputation_check, feed_sync, ip_reputation_check

        # Shared indicator feed object used by ip/domain actions.
        feed_path = Path(str(params.get("feed_path") or params.get("feedPath") or NIP_THREAT_FEED_PATH))
        try:
            feed_obj = json.loads(feed_path.read_text(encoding="utf-8")) if feed_path.exists() else {}
        except Exception:
            feed_obj = {}
        indicators_obj = {"ips": [], "domains": []}
        if isinstance(feed_obj, dict):
            # support both {"ips":[],"domains":[]} and {"indicators":[{type,value}]}
            if isinstance(feed_obj.get("ips"), list):
                indicators_obj["ips"] = [str(x).strip() for x in (feed_obj.get("ips") or []) if str(x).strip()]
            if isinstance(feed_obj.get("domains"), list):
                indicators_obj["domains"] = [str(x).strip().lower().rstrip(".") for x in (feed_obj.get("domains") or []) if str(x).strip()]
            if isinstance(feed_obj.get("indicators"), list):
                for it in feed_obj.get("indicators") or []:
                    if not isinstance(it, dict):
                        continue
                    t = str(it.get("type") or "").lower().strip()
                    v = str(it.get("value") or "").strip()
                    if not t or not v:
                        continue
                    if t == "ip":
                        indicators_obj["ips"].append(v)
                    elif t == "domain":
                        indicators_obj["domains"].append(v.lower().rstrip("."))
        indicators_obj["ips"] = sorted(list(set(indicators_obj["ips"])))
        indicators_obj["domains"] = sorted(list(set(indicators_obj["domains"])))

        if action == "cve-lookup":
            product = str(params.get("product") or params.get("service") or "").strip()
            version = str(params.get("version") or "").strip()
            if not product:
                raise ValueError("threat cve-lookup requires product")
            result = cve_lookup(
                product=product,
                version=version,
                max_results=int(params.get("max_results") or params.get("maxResults") or 20),
                api_key=str(params.get("nvd_api_key") or params.get("nvdApiKey") or os.environ.get("NVD_API_KEY", "")),
            )
        elif action == "ip-reputation":
            ips = params.get("ips") or params.get("ip_list") or params.get("ipList") or []
            if isinstance(ips, str):
                ips = [x.strip() for x in ips.split(",") if x.strip()]
            if not isinstance(ips, list):
                ips = []
            if not ips:
                flows = datastore.list_flows(limit=int(params.get("limit_flows") or params.get("limitFlows") or 4000))
                ips = sorted(list({str(f.get("dst_ip") or "") for f in flows if isinstance(f, dict) and str(f.get("dst_ip") or "")}))
            result = ip_reputation_check(ips=ips, indicators=indicators_obj)
            result["feed_path"] = str(feed_path)
        elif action == "domain-reputation":
            domains = params.get("domains") or params.get("domain_list") or params.get("domainList") or []
            if isinstance(domains, str):
                domains = [x.strip() for x in domains.split(",") if x.strip()]
            if not isinstance(domains, list):
                domains = []
            if not domains:
                with datastore.lock, datastore._connect() as conn:
                    rows = conn.execute(
                        "SELECT domain FROM dns_queries ORDER BY id DESC LIMIT ?",
                        (int(params.get("limit_dns") or params.get("limitDns") or 3000),),
                    ).fetchall()
                domains = [str(r["domain"] or "").strip() for r in rows if str(r["domain"] or "").strip()]
            result = domain_reputation_check(domains=domains, indicators=indicators_obj, dga_threshold=float(params.get("dga_threshold") or params.get("dgaThreshold") or 0.75))
            result["feed_path"] = str(feed_path)
        elif action == "feed-sync":
            add_paths = params.get("feed_paths") or params.get("feedPaths") or []
            if isinstance(add_paths, str):
                add_paths = [x.strip() for x in add_paths.split(",") if x.strip()]
            if not isinstance(add_paths, list):
                add_paths = []
            add_paths_p = [Path(str(x)) for x in add_paths]
            flows = datastore.list_flows(limit=int(params.get("limit_flows") or 8000))
            retro_ips = sorted(
                list(
                    {
                        str(f.get("dst_ip") or "")
                        for f in flows
                        if isinstance(f, dict) and str(f.get("dst_ip") or "").strip()
                    }
                )
            )
            with datastore.lock, datastore._connect() as conn:
                rows = conn.execute(
                    "SELECT domain FROM dns_queries ORDER BY id DESC LIMIT ?",
                    (int(params.get("limit_dns") or 8000),),
                ).fetchall()
            retro_domains = [str(r["domain"] or "").strip().lower().rstrip(".") for r in rows if str(r["domain"] or "").strip()]
            result = feed_sync(
                base_feed_path=feed_path,
                additional_feed_paths=add_paths_p,
                retroactive_ips=retro_ips,
                retroactive_domains=retro_domains,
            )
        else:
            raise ValueError(f"Invalid action for threat: {action}")

    else:
        raise ValueError("Unknown module")

    finished_at = utc_now_iso()
    session_id = new_session_id(f"{module}-{action}")
    technique_meta = _nip_find_technique(module, action)
    nip_meta = {
        "technique_id": getattr(technique_meta, "id", f"{module}.{action}"),
        "name": getattr(technique_meta, "name", ""),
        "scope": getattr(technique_meta, "scope", ""),
        "module": module,
        "action": action,
        "requires_root": bool(getattr(technique_meta, "requires_root", False)),
        "requires_scapy": bool(getattr(technique_meta, "requires_scapy", False)),
        "lab_only": bool(getattr(technique_meta, "lab_only", False)),
        "consumes": list(getattr(technique_meta, "consumes", []) or []),
        "provides": list(getattr(technique_meta, "provides", []) or []),
        "tags": list(getattr(technique_meta, "tags", []) or []),
        "started_at": started_at,
        "finished_at": finished_at,
        "inputs": params,
        "raw_technique": (result or {}).get("technique") if isinstance(result, dict) else "",
    }

    # Best-effort: push technique output into inventory/services and emit fine-grained events.
    try:
        _nip_ingest_coursework_result(module=module, action=action, params=params, result=result)
    except Exception:
        pass

    log_path = write_json_log(
        module,
        session_id,
        {
            "started_at": started_at,
            "finished_at": finished_at,
            "scanner_local_ip": scanner_local_ip,
            "ui_invoked": True,
            "action": action,
            "params": params,
            "result": result,
            "nip": nip_meta,
        },
    )

    # Emit a completion event for orchestrator-style correlation.
    try:
        nip_bus.publish(
            event_type="technique.completed",
            source=f"{module}:{action}",
            entity=str(params.get("host") or params.get("target") or params.get("network") or params.get("domain") or module),
            summary=f"{module} {action} completed",
            data={"session_id": session_id, "log_path": str(log_path), "nip": nip_meta},
        )
    except Exception:
        pass

    return {"module": module, "action": action, "log_file": str(log_path), "result": result}, str(log_path)


def run_multichain_pipeline(*, job_id: str, params: dict) -> Tuple[dict, str]:
    """Run a multi-stage recon pipeline and synthesize a casefile + narrative story.

    This is designed for lab/coursework use: it enforces private targets and gates spoofing behind lab_ok.
    """
    from toolkit.utils import ensure_private_target, infer_local_ip, new_session_id, utc_now_iso, write_json_log

    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not available on the server; cannot run multichain.")
    if not _cw_is_root():
        raise RuntimeError("Multichain requires root privileges. Start the server with sudo.")

    params = params or {}
    profile = str(params.get("profile") or "standard").strip().lower()
    if profile not in ("quick", "standard", "deep"):
        profile = "standard"

    network = str(params.get("network") or params.get("network_cidr") or scanner.network_cidr)
    interface = str(params.get("interface") or params.get("iface") or conf.iface)
    target_ip = str(params.get("target_ip") or params.get("targetIp") or "").strip()
    zombie_ip = str(params.get("zombie_ip") or params.get("zombieIp") or "").strip()

    tcp_ports = params.get("tcp_ports") or params.get("tcpPorts") or "22,80,443"
    udp_ports = params.get("udp_ports") or params.get("udpPorts") or "53,123,161"
    banner_ports = params.get("banner_ports") or params.get("bannerPorts") or "21,22,25,80,443"
    domain = str(params.get("domain") or "").strip()
    dns_server = str(params.get("dns_server") or params.get("dnsServer") or "8.8.8.8").strip()
    max_hosts = int(params.get("max_hosts") or params.get("maxHosts") or 32)
    duration_short = int(params.get("duration_short") or params.get("durationShort") or 60)
    duration_long = int(params.get("duration_long") or params.get("durationLong") or 600)
    duration_arpwatch = int(params.get("duration_arpwatch") or params.get("durationArpwatch") or 120)

    dport = int(params.get("dport") or 80)
    http_port = int(params.get("http_port") or params.get("httpPort") or 80)
    tls_port = int(params.get("tls_port") or params.get("tlsPort") or 443)
    fragsize = int(params.get("fragsize") or 8)
    overlap = bool(params.get("overlap") if params.get("overlap") is not None else True)
    ttl_method = str(params.get("ttl_method") or params.get("ttlMethod") or "icmp")
    max_hops = int(params.get("max_hops") or params.get("maxHops") or 20)

    lab_ok = bool(params.get("lab_ok") or params.get("labOk") or False)
    decoys = params.get("decoys") or params.get("decoy") or []
    if isinstance(decoys, str):
        decoys = [d.strip() for d in decoys.split(",") if d.strip()]
    if not isinstance(decoys, list):
        decoys = []

    netflow_port = int(params.get("netflow_port") or params.get("netflowPort") or 2055)
    bpf = str(params.get("bpf") or "")
    pcap_path = str(params.get("pcap_path") or params.get("pcapPath") or "")

    suricata_eve = str(params.get("suricata_eve") or params.get("suricataEve") or "").strip()
    zeek_notice = str(params.get("zeek_notice") or params.get("zeekNotice") or "").strip()

    ensure_private_target(network)
    if target_ip:
        ensure_private_target(target_ip)
    if zombie_ip:
        ensure_private_target(zombie_ip)
    for d in decoys:
        ensure_private_target(str(d))

    started_at = utc_now_iso()
    scanner_local_ip = getattr(scanner, "local_ip", None) or infer_local_ip()
    gateway_ip = getattr(scanner, "gateway_ip", None) or ""

    state = {
        "pipeline": "multichain",
        "profile": profile,
        "started_at": started_at,
        "network": network,
        "interface": interface,
        "scanner_local_ip": scanner_local_ip,
        "gateway_ip": gateway_ip,
        "steps": [],
        "artifacts": {},
    }

    report_dir = Path(__file__).resolve().parent / "report"
    report_dir.mkdir(parents=True, exist_ok=True)

    def _update(progress: int, msg: str):
        datastore.update_coursework_job(job_id, status="running", progress=int(progress), message=msg, result=state)

    def _add_step(name: str, *, module: str, action: str, params_obj: dict, result_obj: dict | None, log_path: str | None):
        step = {
            "name": name,
            "module": module,
            "action": action,
            "params": params_obj,
            "log_path": log_path or "",
            "result_summary": result_obj.get("technique") if isinstance(result_obj, dict) else "",
            "completed_at": utc_now_iso(),
        }
        state["steps"].append(step)
        return step

    evidence_logs: List[str] = []

    # -----------------
    # Step 1: L2 discovery (active ARP)
    # -----------------
    _update(5, "Module 1: Active ARP enumeration")
    r_mod1, lp_mod1 = run_coursework_action(
        module="mod1",
        action="active",
        params={"network": network, "interface": interface, "max_hosts": max_hosts},
    )
    evidence_logs.append(lp_mod1)
    mod1_active_result = r_mod1.get("result", {})
    _add_step(
        "Active ARP Enumeration",
        module="mod1",
        action="active",
        params_obj={"network": network, "interface": interface, "max_hosts": max_hosts},
        result_obj=mod1_active_result,
        log_path=lp_mod1,
    )

    arp_hosts = []
    try:
        arp_hosts = r_mod1.get("result", {}).get("hosts", []) or []
    except Exception:
        arp_hosts = []

    discovered_ips = [h.get("ip") for h in arp_hosts if isinstance(h, dict) and h.get("ip")]
    discovered_ips = [ip for ip in discovered_ips if ip and ip not in {scanner_local_ip, gateway_ip}]
    discovered_ips = discovered_ips[: max(0, int(max_hosts))]

    # Choose a primary target for single-host techniques (TTL/frag/tcpfp/etc).
    primary_target = target_ip or (discovered_ips[0] if discovered_ips else "")

    if not discovered_ips:
        _update(100, "No hosts discovered by ARP; generating story.")
        state["artifacts"]["multichain_story_md"] = str(report_dir / "multichain_story.md")
        state["artifacts"]["multichain_story_json"] = str(report_dir / "multichain_story.json")
        story = {
            "generated_at": utc_now_iso(),
            "summary": "No hosts responded to active ARP in the specified network.",
            "network": network,
            "interface": interface,
            "steps": state["steps"],
            "evidence_logs": evidence_logs,
        }
        (report_dir / "multichain_story.json").write_text(json.dumps(story, indent=2), encoding="utf-8")
        (report_dir / "multichain_story.md").write_text(
            f"# Multi-Chain Story\n\n**Summary:** No hosts responded to active ARP in `{network}`.\n",
            encoding="utf-8",
        )
        session_id = new_session_id("pipeline-multichain")
        log_path = write_json_log("pipeline", session_id, {"started_at": started_at, "finished_at": utc_now_iso(), "result": story})
        return {"module": "pipeline", "action": "multichain", "log_file": str(log_path), "result": story}, str(log_path)

    mod1_passive_result = None
    mod1_randomized_result = None
    syn_result = None
    udp_result = None
    ack_result = None
    flag_scan_results: List[dict] = []
    passive_dns_result = None

    if profile in ("standard", "deep"):
        _update(10, f"Module 1: Passive ARP observation ({duration_short}s)")
        r_p, lp_p = run_coursework_action(
            module="mod1",
            action="passive",
            params={"interface": interface, "duration": duration_short},
        )
        evidence_logs.append(lp_p)
        _add_step(
            "Passive ARP Observation",
            module="mod1",
            action="passive",
            params_obj={"interface": interface, "duration": duration_short},
            result_obj=r_p.get("result", {}),
            log_path=lp_p,
        )
        mod1_passive_result = r_p.get("result", {})

    if profile == "deep":
        _update(14, "Module 1: MAC randomization session")
        r_r, lp_r = run_coursework_action(
            module="mod1",
            action="randomized",
            params={"network": network, "interface": interface, "max_hosts": max_hosts},
        )
        evidence_logs.append(lp_r)
        _add_step(
            "MAC Address Randomization",
            module="mod1",
            action="randomized",
            params_obj={"network": network, "interface": interface, "max_hosts": max_hosts},
            result_obj=r_r.get("result", {}),
            log_path=lp_r,
        )
        mod1_randomized_result = r_r.get("result", {})

    # -----------------
    # Step 2: Transport scans (SYN baseline; plus optional UDP/ACK and flag scans)
    # -----------------
    _update(18, f"Module 2: SYN scan ({len(discovered_ips)} host(s))")
    r_syn, lp_syn = run_coursework_action(
        module="mod2",
        action="syn",
        params={"hosts": discovered_ips, "ports": tcp_ports, "timeout": 1.0, "rate_delay": 0.0, "shuffle": True},
    )
    evidence_logs.append(lp_syn)
    _add_step("TCP SYN Scan", module="mod2", action="syn", params_obj={"hosts": discovered_ips, "ports": tcp_ports}, result_obj=r_syn.get("result", {}), log_path=lp_syn)
    syn_result = r_syn.get("result", {})

    open_ports_by_host: Dict[str, List[int]] = {}
    try:
        for pr in (r_syn.get("result", {}).get("results", []) or []):
            if not isinstance(pr, dict):
                continue
            if pr.get("state") != "open":
                continue
            hip = pr.get("host")
            p = pr.get("port")
            if hip and isinstance(p, int):
                open_ports_by_host.setdefault(hip, []).append(int(p))
    except Exception:
        open_ports_by_host = {}

    for hip, plist in open_ports_by_host.items():
        open_ports_by_host[hip] = sorted(list({int(x) for x in plist}))

    if profile in ("standard", "deep"):
        _update(28, "Module 2: UDP scan")
        r_udp, lp_udp = run_coursework_action(
            module="mod2",
            action="udp",
            params={"hosts": discovered_ips[: min(len(discovered_ips), 16)], "ports": udp_ports, "timeout": 1.0, "rate_delay": 0.0, "shuffle": True},
        )
        evidence_logs.append(lp_udp)
        _add_step("UDP Scan", module="mod2", action="udp", params_obj={"hosts": discovered_ips[: min(len(discovered_ips), 16)], "ports": udp_ports}, result_obj=r_udp.get("result", {}), log_path=lp_udp)
        udp_result = r_udp.get("result", {})

        _update(36, "Module 2: ACK scan (firewall inference)")
        r_ack, lp_ack = run_coursework_action(
            module="mod2",
            action="ack",
            params={"hosts": discovered_ips[: min(len(discovered_ips), 8)], "ports": tcp_ports, "timeout": 1.0, "rate_delay": 0.0, "shuffle": True},
        )
        evidence_logs.append(lp_ack)
        _add_step("TCP ACK Scan", module="mod2", action="ack", params_obj={"hosts": discovered_ips[: min(len(discovered_ips), 8)], "ports": tcp_ports}, result_obj=r_ack.get("result", {}), log_path=lp_ack)
        ack_result = r_ack.get("result", {})

    if profile == "deep" and primary_target:
        _update(42, "Module 2: FIN/XMAS/NULL flag scans (single target)")
        for action, label in (("fin", "TCP FIN"), ("xmas", "TCP XMAS"), ("null", "TCP NULL")):
            r_flag, lp_flag = run_coursework_action(
                module="mod2",
                action=action,
                params={"hosts": [primary_target], "ports": tcp_ports, "timeout": 1.0, "rate_delay": 0.0, "shuffle": False},
            )
            evidence_logs.append(lp_flag)
            _add_step(f"{label} Scan", module="mod2", action=action, params_obj={"host": primary_target, "ports": tcp_ports}, result_obj=r_flag.get("result", {}), log_path=lp_flag)
            flag_scan_results.append(r_flag.get("result", {}))

    # -----------------
    # Step 3: App fingerprinting on the most interesting hosts
    # -----------------
    _update(50, "Module 5: Selecting hosts for fingerprinting")
    # Rank by open-port count.
    ranked_hosts = sorted(discovered_ips, key=lambda ip: -len(open_ports_by_host.get(ip, [])))
    fp_limit = 6 if profile == "quick" else (12 if profile == "standard" else 20)
    fingerprint_hosts = ranked_hosts[: fp_limit]

    banner_ports_list = _cw_parse_ports(banner_ports)
    tcp_ports_list = _cw_parse_ports(tcp_ports)

    banner_results = []
    http_results = []
    tls_results = []

    for idx, hip in enumerate(fingerprint_hosts):
        _update(52 + int((idx / max(1, len(fingerprint_hosts))) * 18), f"Module 5: Fingerprinting {hip}")
        r_b, lp_b = run_coursework_action(module="mod5", action="banner", params={"host": hip, "ports": banner_ports_list, "timeout": 2.0})
        evidence_logs.append(lp_b)
        _add_step("Banner Grabbing", module="mod5", action="banner", params_obj={"host": hip, "ports": banner_ports_list}, result_obj=r_b.get("result", {}), log_path=lp_b)
        banner_results.append(r_b.get("result", {}))

        # HTTP header analysis based on open ports if we have them; otherwise best-effort on defaults.
        openp = set(open_ports_by_host.get(hip, []))
        if http_port in openp:
            r_h, lp_h = run_coursework_action(module="mod5", action="http", params={"host": hip, "port": http_port, "use_tls": False, "timeout": 3.0})
            evidence_logs.append(lp_h)
            _add_step("HTTP Header Analysis", module="mod5", action="http", params_obj={"host": hip, "port": http_port, "use_tls": False}, result_obj=r_h.get("result", {}), log_path=lp_h)
            http_results.append(r_h.get("result", {}))
        if tls_port in openp:
            r_t, lp_t = run_coursework_action(module="mod5", action="tls", params={"host": hip, "port": tls_port, "timeout": 6.0})
            evidence_logs.append(lp_t)
            _add_step("TLS Certificate Inspection", module="mod5", action="tls", params_obj={"host": hip, "port": tls_port}, result_obj=r_t.get("result", {}), log_path=lp_t)
            tls_results.append(r_t.get("result", {}))

            r_hs, lp_hs = run_coursework_action(module="mod5", action="http", params={"host": hip, "port": tls_port, "use_tls": True, "timeout": 4.0})
            evidence_logs.append(lp_hs)
            _add_step("HTTPS Header Analysis", module="mod5", action="http", params_obj={"host": hip, "port": tls_port, "use_tls": True}, result_obj=r_hs.get("result", {}), log_path=lp_hs)
            http_results.append(r_hs.get("result", {}))

    tcpfp_result = None
    if primary_target:
        _update(72, f"Module 5: TCP stack fingerprinting ({primary_target})")
        r_fp, lp_fp = run_coursework_action(module="mod5", action="tcpfp", params={"host": primary_target, "dport": dport, "timeout": 1.0})
        evidence_logs.append(lp_fp)
        _add_step("TCP Stack Fingerprinting", module="mod5", action="tcpfp", params_obj={"host": primary_target, "dport": dport}, result_obj=r_fp.get("result", {}), log_path=lp_fp)
        tcpfp_result = r_fp.get("result", {})

    dns_enum_result = None
    if domain:
        _update(74, f"Module 5: DNS enumeration ({domain})")
        r_dns, lp_dns = run_coursework_action(module="mod5", action="dns", params={"domain": domain, "server": dns_server})
        evidence_logs.append(lp_dns)
        _add_step("DNS Enumeration", module="mod5", action="dns", params_obj={"domain": domain, "server": dns_server}, result_obj=r_dns.get("result", {}), log_path=lp_dns)
        dns_enum_result = r_dns.get("result", {})

    if profile in ("standard", "deep"):
        _update(76, "Module 5: Passive DNS monitoring")
        r_pdns, lp_pdns = run_coursework_action(module="mod5", action="passive-dns", params={"interface": interface, "duration": duration_short})
        evidence_logs.append(lp_pdns)
        _add_step("Passive DNS Monitor", module="mod5", action="passive-dns", params_obj={"interface": interface, "duration": duration_short}, result_obj=r_pdns.get("result", {}), log_path=lp_pdns)
        passive_dns_result = r_pdns.get("result", {})

    # -----------------
    # Step 4: IP-layer techniques (single target)
    # -----------------
    ip_layer = {}
    if primary_target:
        _update(80, f"Module 3: TTL path inference ({primary_target})")
        r_ttl, lp_ttl = run_coursework_action(
            module="mod3",
            action="ttl",
            params={"target": primary_target, "max_hops": max_hops, "timeout": 1.0, "method": ttl_method, "dport": dport},
        )
        evidence_logs.append(lp_ttl)
        _add_step("TTL Path Inference", module="mod3", action="ttl", params_obj={"target": primary_target}, result_obj=r_ttl.get("result", {}), log_path=lp_ttl)
        ip_layer["ttl"] = r_ttl.get("result", {})

        _update(84, f"Module 3: Fragmentation test ({primary_target})")
        r_frag, lp_frag = run_coursework_action(
            module="mod3",
            action="frag",
            params={"target": primary_target, "dport": dport, "fragsize": fragsize, "timeout": 2.0, "overlap": overlap},
        )
        evidence_logs.append(lp_frag)
        _add_step("IP Fragmentation", module="mod3", action="frag", params_obj={"target": primary_target, "dport": dport}, result_obj=r_frag.get("result", {}), log_path=lp_frag)
        ip_layer["frag"] = r_frag.get("result", {})

    if profile == "deep":
        _update(88, "Module 3: IPID sweep (find idle-scan zombies)")
        r_sweep, lp_sweep = run_coursework_action(
            module="mod3",
            action="ipid-sweep",
            params={"network": network, "max_hosts": min(64, max_hosts), "probes": 12, "interval": 0.15, "timeout": 1.0},
        )
        evidence_logs.append(lp_sweep)
        _add_step("IPID Sweep", module="mod3", action="ipid-sweep", params_obj={"network": network}, result_obj=r_sweep.get("result", {}), log_path=lp_sweep)
        ip_layer["ipid_sweep"] = r_sweep.get("result", {})

        # Lab-only spoofing exercises
        if lab_ok and zombie_ip and primary_target:
            _update(90, "Module 3: Idle scan (lab_ok)")
            r_idle, lp_idle = run_coursework_action(
                module="mod3",
                action="idle",
                params={"lab_ok": True, "zombie": zombie_ip, "target": primary_target, "dport": dport, "timeout": 1.0},
            )
            evidence_logs.append(lp_idle)
            _add_step("Idle Scan", module="mod3", action="idle", params_obj={"zombie": zombie_ip, "target": primary_target, "dport": dport}, result_obj=r_idle.get("result", {}), log_path=lp_idle)
            ip_layer["idle"] = r_idle.get("result", {})

        if lab_ok and primary_target and decoys:
            _update(92, "Module 3: Decoy source mixing (lab_ok)")
            r_decoy, lp_decoy = run_coursework_action(
                module="mod3",
                action="decoy",
                params={"lab_ok": True, "target": primary_target, "dport": dport, "decoys": decoys, "real_probes": 5, "timeout": 1.0},
            )
            evidence_logs.append(lp_decoy)
            _add_step("Decoy Mixing", module="mod3", action="decoy", params_obj={"target": primary_target, "dport": dport, "decoys": decoys}, result_obj=r_decoy.get("result", {}), log_path=lp_decoy)
            ip_layer["decoy"] = r_decoy.get("result", {})

    # -----------------
    # Step 5: Passive collection + detection helpers (optional)
    # -----------------
    passive = {}
    if profile in ("standard", "deep"):
        _update(94, "Module 7: ARPwatch-style monitoring")
        r_aw, lp_aw = run_coursework_action(module="mod7", action="arpwatch", params={"interface": interface, "duration": duration_arpwatch})
        evidence_logs.append(lp_aw)
        _add_step("ARPwatch-Style Monitor", module="mod7", action="arpwatch", params_obj={"interface": interface, "duration": duration_arpwatch}, result_obj=r_aw.get("result", {}), log_path=lp_aw)
        passive["arpwatch"] = r_aw.get("result", {})

        _update(96, "Module 6: Promiscuous capture")
        r_prom, lp_prom = run_coursework_action(module="mod6", action="promisc", params={"interface": interface, "duration": duration_short, "bpf": bpf})
        evidence_logs.append(lp_prom)
        _add_step("Promiscuous Capture", module="mod6", action="promisc", params_obj={"interface": interface, "duration": duration_short}, result_obj=r_prom.get("result", {}), log_path=lp_prom)
        passive["promisc"] = r_prom.get("result", {})

    if profile == "deep":
        _update(97, "Module 6: NetFlow v5 collection (if exporter present)")
        r_nf, lp_nf = run_coursework_action(module="mod6", action="netflow", params={"listen_port": netflow_port, "duration": duration_short})
        evidence_logs.append(lp_nf)
        _add_step("NetFlow v5 Collection", module="mod6", action="netflow", params_obj={"listen_port": netflow_port, "duration": duration_short}, result_obj=r_nf.get("result", {}), log_path=lp_nf)
        passive["netflow_collect"] = r_nf.get("result", {})

        _update(98, "Module 7: NetFlow v5 detection (alerting)")
        r_nfd, lp_nfd = run_coursework_action(module="mod7", action="netflow-detect", params={"listen_port": netflow_port, "duration": duration_short})
        evidence_logs.append(lp_nfd)
        _add_step("NetFlow Detection", module="mod7", action="netflow-detect", params_obj={"listen_port": netflow_port, "duration": duration_short}, result_obj=r_nfd.get("result", {}), log_path=lp_nfd)
        passive["netflow_detect"] = r_nfd.get("result", {})

        # Detection matrix if the user provided paths.
        if suricata_eve or zeek_notice:
            _update(99, "Module 7: Detection matrix correlation")
            dm_params = {}
            if suricata_eve:
                dm_params["suricata_eve"] = suricata_eve
            if zeek_notice:
                dm_params["zeek_notice"] = zeek_notice
            r_dm, lp_dm = run_coursework_action(module="mod7", action="detection-matrix", params=dm_params)
            evidence_logs.append(lp_dm)
            _add_step("Detection Matrix", module="mod7", action="detection-matrix", params_obj=dm_params, result_obj=r_dm.get("result", {}), log_path=lp_dm)
            passive["detection_matrix"] = r_dm.get("result", {})

    # -----------------
    # Synthesis: casefile + narrative
    # -----------------
    _update(99, "Synthesizing casefile and narrative story")

    # Build normalized assets/services view.
    ip_to_mac = {}
    for h in arp_hosts:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip")
        mac = h.get("mac")
        if ip:
            ip_to_mac[ip] = mac or ""

    assets = []
    for ip in discovered_ips:
        mac = ip_to_mac.get(ip, "")
        vendor = lookup_mac_vendor(mac) if mac else ""
        assets.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "open_tcp_ports": open_ports_by_host.get(ip, []),
                "risk_ports": [p for p in open_ports_by_host.get(ip, []) if p in (21, 23, 445, 3389, 5900, 6379, 9200, 27017)],
            }
        )

    exposures = []
    risk_port_labels = {
        21: "FTP",
        23: "Telnet",
        445: "SMB",
        3389: "RDP",
        5900: "VNC",
        6379: "Redis",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }
    for a in assets:
        for p in a.get("risk_ports", []):
            exposures.append({"ip": a["ip"], "port": p, "service": risk_port_labels.get(p, str(p))})

    # Extract web posture highlights.
    web_findings = []
    for hr in http_results:
        if not isinstance(hr, dict):
            continue
        if hr.get("technique") != "http_header_analysis":
            continue
        f = hr.get("findings") or {}
        web_findings.append(
            {
                "host": hr.get("host"),
                "port": hr.get("port"),
                "use_tls": hr.get("use_tls"),
                "security_posture": hr.get("security_posture"),
                "server": f.get("server_software"),
                "framework": f.get("framework"),
                "internal_ip_leak_detected": (f.get("internal_ip_leak_detected") is True),
                "caching_layer_detected": (f.get("caching_layer") or {}).get("detected") is True,
            }
        )

    # Extract TLS intel highlights.
    tls_highlights = []
    for tr in tls_results:
        if not isinstance(tr, dict):
            continue
        chain = tr.get("chain") or []
        leaf = chain[0] if isinstance(chain, list) and chain else {}
        tls_highlights.append(
            {
                "host": tr.get("host"),
                "port": tr.get("port"),
                "leaf_subject": leaf.get("subject"),
                "leaf_issuer": leaf.get("issuer"),
                "leaf_sans": leaf.get("sans") or [],
                "leaf_not_after": leaf.get("not_after"),
                "leaf_sigalg": leaf.get("signature_algorithm"),
                "leaf_key_bits": leaf.get("public_key_bits"),
            }
        )

    # Correlate service intel per host across techniques (banner/http/tls/udp/ack).
    banner_by_host_port: Dict[str, Dict[int, Dict[str, object]]] = {}
    for br in banner_results:
        if not isinstance(br, dict):
            continue
        hip = br.get("host")
        if not hip:
            continue
        for rr in (br.get("results") or []):
            if not isinstance(rr, dict):
                continue
            p = rr.get("port")
            if not isinstance(p, int):
                continue
            banner_by_host_port.setdefault(hip, {})[int(p)] = {
                "banner": rr.get("banner") or "",
                "has_banner": bool(rr.get("has_banner")),
                "intel": rr.get("intel") or {},
            }

    http_by_host: Dict[str, List[dict]] = {}
    for hr in http_results:
        if not isinstance(hr, dict):
            continue
        hip = hr.get("host")
        if hip:
            http_by_host.setdefault(hip, []).append(hr)

    tls_by_host: Dict[str, dict] = {}
    for tr in tls_results:
        if not isinstance(tr, dict):
            continue
        hip = tr.get("host")
        if hip and hip not in tls_by_host:
            tls_by_host[hip] = tr

    udp_by_host_port: Dict[str, Dict[int, dict]] = {}
    if udp_result and isinstance(udp_result, dict):
        for ur in (udp_result.get("results") or []):
            if not isinstance(ur, dict):
                continue
            if ur.get("proto") != "udp":
                continue
            hip = ur.get("host")
            p = ur.get("port")
            if hip and isinstance(p, int):
                udp_by_host_port.setdefault(hip, {})[int(p)] = ur

    firewall_by_host: Dict[str, dict] = {}
    if ack_result and isinstance(ack_result, dict):
        for fr in (ack_result.get("firewall_topology_map") or []):
            if not isinstance(fr, dict):
                continue
            hip = fr.get("host")
            if hip:
                firewall_by_host[hip] = fr

    host_profiles = []
    for a in assets:
        hip = a.get("ip")
        if not hip:
            continue
        ports = open_ports_by_host.get(hip, [])
        services = []
        os_hints = []

        # Strong hints from ports.
        if any(p in ports for p in (445, 3389)):
            os_hints.append({"hint": "windows_likely", "confidence": 0.6, "evidence": "SMB/RDP open"})
        if 22 in ports and not any(p in ports for p in (445, 3389)):
            os_hints.append({"hint": "unix_like_likely", "confidence": 0.4, "evidence": "SSH open"})

        # Per-service intel.
        for p in ports:
            svc = {
                "port": int(p),
                "proto": "tcp",
                "risk_label": risk_port_labels.get(int(p), ""),
                "banner": "",
                "banner_intel": {},
            }
            bi = banner_by_host_port.get(hip, {}).get(int(p))
            if bi:
                svc["banner"] = bi.get("banner", "")
                svc["banner_intel"] = bi.get("intel") or {}
                os_hint = (svc["banner_intel"] or {}).get("os_hint")
                if os_hint:
                    os_hints.append({"hint": str(os_hint), "confidence": 0.35, "evidence": f"banner:{p}"})
            services.append(svc)

        # Web posture summary (worst posture wins).
        web = http_by_host.get(hip, [])
        posture_rank = {"weak": 0, "moderate": 1, "strong": 2, "unknown": 3}
        worst = None
        for hr in web:
            posture = str(hr.get("security_posture") or "unknown")
            if worst is None or posture_rank.get(posture, 3) < posture_rank.get(worst, 3):
                worst = posture

        # Firewall inference (ACK scan).
        fw = firewall_by_host.get(hip)

        # UDP scan outcomes (if we ran it).
        udp_obs = udp_by_host_port.get(hip, {})

        # TCP fingerprint only applies to the primary target.
        fp = tcpfp_result if (hip == primary_target) else None

        story_bits = []
        if ports:
            story_bits.append(f"open_tcp={','.join(str(p) for p in ports)}")
        if a.get("risk_ports"):
            story_bits.append(f"risk_ports={','.join(str(p) for p in a.get('risk_ports', []))}")
        if worst and worst != "unknown":
            story_bits.append(f"http_posture={worst}")
        if fp and isinstance(fp, dict) and fp.get("best_guess"):
            story_bits.append(f"tcpfp={fp.get('best_guess')}")
        if fw and isinstance(fw, dict):
            story_bits.append(f"ack_inference={fw.get('inference')}")

        host_profiles.append(
            {
                "ip": hip,
                "mac": a.get("mac", ""),
                "vendor": a.get("vendor", ""),
                "open_tcp_ports": ports,
                "risk_ports": a.get("risk_ports", []),
                "services": services,
                "web_posture_worst": worst or "unknown",
                "tls_leaf_subject": (tls_highlights and next((t.get("leaf_subject") for t in tls_highlights if t.get("host") == hip), None)) or None,
                "udp_ports": list(sorted(udp_obs.keys())),
                "udp_observations": udp_obs,
                "ack_firewall_inference": fw,
                "os_hints": os_hints[:10],
                "story": "; ".join(story_bits),
            }
        )

    summary = {
        "hosts_discovered": len(discovered_ips),
        "hosts_fingerprinted": len(fingerprint_hosts),
        "open_ports_total": sum(len(v) for v in open_ports_by_host.values()),
        "high_risk_exposures": len(exposures),
        "dns_domain_enumerated": bool(domain),
    }

    narrative_lines = []
    narrative_lines.append(f"Observed {summary['hosts_discovered']} host(s) via active ARP on `{network}`.")
    try:
        vlan = (mod1_active_result or {}).get("vlan_boundary_behavior") or {}
        if isinstance(vlan, dict) and vlan.get("interpretation"):
            narrative_lines.append(f"ARP/VLAN boundary heuristic: {vlan.get('interpretation')}.")
    except Exception:
        pass
    if exposures:
        narrative_lines.append(f"Identified {len(exposures)} high-risk service exposure(s) (e.g., SMB/RDP/FTP/Telnet).")
    if web_findings:
        weak = [w for w in web_findings if w.get("security_posture") == "weak"]
        if weak:
            narrative_lines.append(f"Web header posture: {len(weak)} endpoint(s) scored `weak` (missing multiple security headers).")
    if tls_highlights:
        narrative_lines.append(f"TLS intel collected from {len(tls_highlights)} endpoint(s) (subject/SAN/issuer/validity).")
    if tcpfp_result and isinstance(tcpfp_result, dict) and tcpfp_result.get("best_guess"):
        narrative_lines.append(f"TCP stack fingerprint best-guess: {tcpfp_result.get('best_guess')} (confidence={tcpfp_result.get('confidence')}).")
    if mod1_passive_result and isinstance(mod1_passive_result, dict):
        cov = mod1_passive_result.get("coverage") or {}
        if isinstance(cov, dict) and cov.get("hosts_seen_total") is not None:
            narrative_lines.append(
                f"Passive ARP saw {cov.get('hosts_seen_total')} host(s) total (within 60s: {cov.get('hosts_seen_within_1_min')})."
            )
    if ack_result and isinstance(ack_result, dict):
        fmap = ack_result.get("firewall_topology_map") or []
        if isinstance(fmap, list) and fmap:
            filtered_hosts = [x for x in fmap if isinstance(x, dict) and (x.get("filtered_ports") or 0) > 0]
            narrative_lines.append(
                f"ACK scan suggests stateful filtering on {len(filtered_hosts)} host(s) (RST received on others => unfiltered)."
            )
    if udp_result and isinstance(udp_result, dict):
        meas = (udp_result.get("icmp_rate_limiting_measurements") or {})
        if isinstance(meas, dict) and meas.get("suspected_rate_limiting") is True:
            narrative_lines.append("UDP scan shows signs of ICMP rate limiting (later ICMP unreachable rate dropped).")
    if domain:
        narrative_lines.append(f"DNS enumeration performed for domain `{domain}` (records + reverse DNS where possible).")

    # Optional compact "story panel" for UI dashboards.
    top_domains = []
    try:
        td = (passive_dns_result or {}).get("top_domains") or []
        for row in td[:10]:
            if isinstance(row, (list, tuple)) and len(row) >= 2:
                top_domains.append({"domain": str(row[0]), "count": int(row[1])})
    except Exception:
        top_domains = []

    summary_text_parts = [
        f"Discovered {summary['hosts_discovered']} host(s) on {network}.",
        f"Found {summary['open_ports_total']} open TCP port(s).",
    ]
    if exposures:
        summary_text_parts.append(f"{len(exposures)} high-risk exposure(s) detected.")
    if web_findings:
        weak = [w for w in web_findings if w.get("security_posture") == "weak"]
        if weak:
            summary_text_parts.append(f"{len(weak)} web endpoint(s) have weak security headers.")
    if top_domains:
        summary_text_parts.append(f"Top DNS domains observed: {', '.join(d['domain'] for d in top_domains[:3])}.")
    summary_text = " ".join(summary_text_parts)

    insights = []
    for ln in narrative_lines[:8]:
        insights.append(ln)
    if exposures:
        examples = ", ".join(f"{e['ip']}:{e['port']}" for e in exposures[:3])
        insights.append(f"Risk examples: {examples}.")
    if tcpfp_result and isinstance(tcpfp_result, dict) and tcpfp_result.get("best_guess"):
        insights.append(f"TCP fingerprint best-guess: {tcpfp_result.get('best_guess')} (confidence={tcpfp_result.get('confidence')}).")

    story_panel = {
        "summary": summary_text,
        "insights": insights[:12],
        "top_domains": top_domains,
        "exposed_services": exposures[:25],
    }

    casefile = {
        "generated_at": utc_now_iso(),
        "pipeline": {
            "profile": profile,
            "network": network,
            "interface": interface,
            "scanner_local_ip": scanner_local_ip,
            "gateway_ip": gateway_ip,
            "primary_target": primary_target,
            "lab_ok": lab_ok,
        },
        "summary": summary,
        "narrative": {
            "high_level": narrative_lines,
        },
        "story_panel": story_panel,
        "host_profiles": host_profiles,
        "link_layer": {
            "active_arp": mod1_active_result,
            "passive_arp": mod1_passive_result,
            "mac_randomization": mod1_randomized_result,
        },
        "transport": {
            "syn": syn_result,
            "udp": udp_result,
            "ack": ack_result,
            "flag_scans": flag_scan_results,
        },
        "app_fingerprinting": {
            "banner": banner_results,
            "http": http_results,
            "tls": tls_results,
        },
        "assets": assets,
        "exposures": exposures,
        "web_findings": web_findings,
        "tls_highlights": tls_highlights,
        "dns_enumeration": dns_enum_result,
        "tcp_fingerprint": tcpfp_result,
        "ip_layer": ip_layer,
        "passive": passive,
        "steps": state["steps"],
        "evidence_logs": evidence_logs,
    }

    md_lines = []
    md_lines.append("# Multi-Chain Network Story")
    md_lines.append("")
    md_lines.append(f"- Generated: `{casefile['generated_at']}`")
    md_lines.append(f"- Profile: `{profile}`")
    md_lines.append(f"- Network: `{network}`")
    md_lines.append(f"- Interface: `{interface}`")
    md_lines.append(f"- Local IP: `{scanner_local_ip}`")
    if gateway_ip:
        md_lines.append(f"- Gateway: `{gateway_ip}`")
    if primary_target:
        md_lines.append(f"- Primary Target: `{primary_target}`")
    md_lines.append("")
    md_lines.append("## Executive Summary")
    md_lines.append("")
    for ln in narrative_lines:
        md_lines.append(f"- {ln}")
    md_lines.append("")

    md_lines.append("## Asset Inventory")
    md_lines.append("")
    md_lines.append("| IP | MAC | Vendor | Open TCP Ports | Risk Ports |")
    md_lines.append("|---|---|---|---|---|")
    for a in assets:
        md_lines.append(
            f"| `{a['ip']}` | `{a.get('mac','')}` | {a.get('vendor','') or ''} | `{','.join(str(p) for p in a.get('open_tcp_ports', []))}` | `{','.join(str(p) for p in a.get('risk_ports', []))}` |"
        )
    md_lines.append("")

    if exposures:
        md_lines.append("## High-Risk Exposures")
        md_lines.append("")
        for ex in exposures[:200]:
            md_lines.append(f"- `{ex['ip']}:{ex['port']}` ({ex['service']})")
        md_lines.append("")

    if web_findings:
        md_lines.append("## Web Posture (HTTP Headers)")
        md_lines.append("")
        for w in web_findings[:50]:
            md_lines.append(
                f"- `{w.get('host')}:{w.get('port')}` tls={w.get('use_tls')} posture=`{w.get('security_posture')}` server=`{w.get('server')}` framework=`{w.get('framework')}` cache={w.get('caching_layer_detected')} leak={w.get('internal_ip_leak_detected')}"
            )
        md_lines.append("")

    if tls_highlights:
        md_lines.append("## TLS Certificate Intel")
        md_lines.append("")
        for t in tls_highlights[:30]:
            sans = t.get("leaf_sans") or []
            md_lines.append(f"- `{t.get('host')}:{t.get('port')}` subject=`{t.get('leaf_subject')}` issuer=`{t.get('leaf_issuer')}` not_after=`{t.get('leaf_not_after')}` key_bits=`{t.get('leaf_key_bits')}`")
            if sans:
                md_lines.append(f"  - SANs: {', '.join(str(x) for x in sans[:12])}")
        md_lines.append("")

    if dns_enum_result and isinstance(dns_enum_result, dict):
        md_lines.append("## DNS Enumeration")
        md_lines.append("")
        md_lines.append(f"- Domain: `{dns_enum_result.get('domain', domain)}`")
        md_lines.append(f"- Resolver: `{dns_enum_result.get('server', dns_server)}`")
        rec = dns_enum_result.get("records") or {}
        if isinstance(rec, dict):
            for k in ("A", "AAAA", "MX", "NS", "TXT", "SRV", "CNAME"):
                v = rec.get(k)
                if v:
                    md_lines.append(f"- {k}: {v}")
        md_lines.append("")

    md_lines.append("## Evidence (Logs)")
    md_lines.append("")
    for p in evidence_logs[-200:]:
        md_lines.append(f"- `{p}`")
    md_lines.append("")

    # Write artifacts
    story_json_path = report_dir / "multichain_story.json"
    story_md_path = report_dir / "multichain_story.md"
    casefile_path = report_dir / "multichain_casefile.json"
    story_json_path.write_text(json.dumps(casefile, indent=2), encoding="utf-8")
    casefile_path.write_text(json.dumps(casefile, indent=2), encoding="utf-8")
    story_md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    state["artifacts"]["multichain_story_json"] = str(story_json_path)
    state["artifacts"]["multichain_story_md"] = str(story_md_path)
    state["artifacts"]["multichain_casefile_json"] = str(casefile_path)

    finished_at = utc_now_iso()
    session_id = new_session_id("pipeline-multichain")
    log_path = write_json_log("pipeline", session_id, {"started_at": started_at, "finished_at": finished_at, "result": casefile})
    return {"module": "pipeline", "action": "multichain", "log_file": str(log_path), "result": casefile}, str(log_path)


# Global instances
DATA_DIR = Path(__file__).resolve().parent / "data"
datastore = DataStore(DATA_DIR / "netvis.db")
scanner = NetworkScanner()
analyzer = TrafficAnalyzer()
scan_jobs = ScanJobManager()
coursework_jobs = CourseworkJobManager()
nip_metrics_daemon = NipMetricsDaemon(interval_seconds=10, alpha=0.2)

# Persist NIP events into the observations timeline and optionally stream to UI.
def _nip_persist_event(ev):
    try:
        datastore.add_observation(
            ev.type,
            ev.entity or ev.source,
            ev.summary,
            {"source": ev.source, "event_id": ev.id, "ts": ev.ts, "data": ev.data},
        )
    except Exception:
        pass
    try:
        socketio.emit("nip_event", {"event": asdict(ev)})
    except Exception:
        pass


try:
    nip_bus.subscribe(_nip_persist_event)
except Exception:
    pass


# REST API Endpoints
@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    global mitm_active, mitm_last_seen
    # Check if MITM is still active (no data for 10 seconds = inactive)
    if mitm_last_seen and (datetime.now() - mitm_last_seen).total_seconds() > 10:
        mitm_active = False
    return jsonify({
        'scapy_available': SCAPY_AVAILABLE,
        'nmap_available': NMAP_AVAILABLE,
        'local_ip': scanner.local_ip,
        'gateway_ip': scanner.gateway_ip,
        'network': scanner.network_cidr,
        'capturing': analyzer.is_capturing,
        'mitm_active': mitm_active,
        'interfaces': get_if_list() if SCAPY_AVAILABLE else [],
        'scan_profiles': list(SCAN_PROFILES.keys()),
        'db_path': str(datastore.db_path),
        'api_key_enabled': bool(API_KEY),
    })


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a network scan"""
    data = request.json or {}
    scan_type = data.get('type', 'arp')
    target = data.get('target', scanner.network_cidr)
    profile = (data.get('profile') or 'standard').lower()
    
    if scan_type == 'nmap':
        devices = scanner.nmap_scan(target)
        return jsonify({
            'devices': [asdict(d) for d in devices.values()],
            'count': len(devices)
        })
    if scan_type == 'smart':
        results = run_profile_scan(profile=profile, target_network=target)
        return jsonify(results)
    else:
        devices = scanner.scan_network_arp()
        
    return jsonify({
        'devices': [asdict(d) for d in devices.values()],
        'count': len(devices)
    })


@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get all discovered devices"""
    return jsonify({
        'devices': [asdict(d) for d in scanner.devices.values()],
        'count': len(scanner.devices)
    })


@app.route('/api/device/<ip>', methods=['GET'])
def get_device(ip):
    """Get details for a specific device"""
    if ip in scanner.devices:
        return jsonify(asdict(scanner.devices[ip]))
    return jsonify({'error': 'Device not found'}), 404


@app.route('/api/device/<ip>/scan', methods=['POST'])
def scan_device_ports(ip):
    """Scan ports on a specific device"""
    data = request.json or {}
    ports = data.get('ports')
    banner_grab = bool(data.get('banner_grab', False))
    device = scanner.scan_ports(ip, ports, banner_grab=banner_grab)
    
    # Re-guess device type with port info
    if ip in scanner.devices:
        device = scanner.devices[ip]
        device_type = guess_device_type(device.hostname, device.vendor, device.open_ports)
        device.os = device_type
        datastore.upsert_device(device, scan_profile="device_deep_scan")
        for port in device.open_ports:
            datastore.upsert_service(
                ip,
                port,
                "tcp",
                device.services.get(port, f"Port {port}"),
                banner=device.service_banners.get(port, ""),
            )
        datastore.add_observation(
            "device_scan",
            ip,
            f"Deep scan completed for {ip} with {len(device.open_ports)} open ports",
            {"port_count": len(device.open_ports), "ports": device.open_ports},
        )
    
    return jsonify(asdict(device))


@app.route('/api/scan/enhanced', methods=['POST'])
def enhanced_scan():
    """Enhanced scan for VPN/mesh networks using ICMP + TCP probing"""
    import concurrent.futures
    
    data = request.json or {}
    target_network = data.get('network', scanner.network_cidr)
    quick = data.get('quick', True)
    
    results = {
        'alive_hosts': [],
        'scan_type': 'enhanced',
        'network': target_network
    }
    
    # Parse network
    if '/' in target_network:
        base_ip = target_network.split('/')[0]
    else:
        base_ip = target_network
    
    base_parts = base_ip.split('.')[:3]
    ips_to_scan = [f"{'.'.join(base_parts)}.{i}" for i in range(1, 255)]
    
    # Quick ICMP sweep
    def ping_host(ip):
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                # Parse TTL
                output = result.stdout.decode() if isinstance(result.stdout, bytes) else result.stdout
                ttl = 64
                if 'ttl=' in output.lower():
                    ttl = int(output.lower().split('ttl=')[1].split()[0])
                
                os_guess = 'Linux/Unix' if ttl <= 64 else ('Windows' if ttl <= 128 else 'Network Device')
                return {'ip': ip, 'alive': True, 'ttl': ttl, 'os_guess': os_guess}
        except:
            pass
        return None
    
    # Scan in parallel
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ips_to_scan}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)
    
    # For alive hosts, do quick port scan
    common_ports = [22, 80, 443, 445, 3389, 8080]
    
    def scan_ports_quick(host_info):
        ip = host_info['ip']
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        host_info['open_ports'] = open_ports
        
        # Try hostname resolution
        try:
            host_info['hostname'] = socket.gethostbyaddr(ip)[0]
        except:
            host_info['hostname'] = ''
        
        # Add to scanner devices
        now = datetime.now().isoformat()
        if ip not in scanner.devices:
            scanner.devices[ip] = Device(
                ip=ip,
                mac='',  # Unknown on VPN
                hostname=host_info['hostname'],
                vendor='',
                os=host_info['os_guess'].lower().replace('/', '_'),
                first_seen=now,
                last_seen=now,
                is_gateway=(ip == scanner.gateway_ip),
                is_local=(ip == scanner.local_ip),
                open_ports=open_ports,
                services={p: SERVICE_NAMES.get(p, f'Port {p}') for p in open_ports}
            )
        else:
            scanner.devices[ip].last_seen = now
            scanner.devices[ip].open_ports = open_ports
        
        return host_info
    
    # Scan ports on alive hosts
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results['alive_hosts'] = list(executor.map(scan_ports_quick, alive))
    
    return jsonify(results)


@app.route('/api/scan/smart', methods=['POST'])
def smart_scan():
    """Unified smart scan endpoint with depth profiles."""
    data = request.json or {}
    profile = (data.get('profile') or 'standard').lower()
    network = data.get('network')
    results = run_profile_scan(profile=profile, target_network=network)
    return jsonify(results)


@app.route('/api/scan/jobs', methods=['POST'])
def start_scan_job():
    """Start an asynchronous scan job."""
    data = request.json or {}
    profile = (data.get('profile') or 'standard').lower()
    target = data.get('network')
    if profile not in SCAN_PROFILES:
        return jsonify({'error': f'Invalid profile: {profile}'}), 400
    job_id = scan_jobs.start(profile, target)
    return jsonify({'job_id': job_id, 'status': 'queued', 'profile': profile, 'target': target or scanner.network_cidr}), 202


@app.route('/api/scan/jobs', methods=['GET'])
def list_scan_jobs():
    """List recent scan jobs."""
    try:
        limit = int(request.args.get('limit', 20))
    except Exception:
        limit = 20
    limit = max(1, min(200, limit))
    return jsonify({'jobs': datastore.list_scan_jobs(limit=limit)})


@app.route('/api/scan/jobs/<job_id>', methods=['GET'])
def get_scan_job(job_id):
    """Get scan job details."""
    job = datastore.get_scan_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(job)


def build_network_story_internal() -> dict:
    """Correlate active telemetry into analyst-friendly narrative insights."""
    with analyzer.lock:
        connections = list(analyzer.connections.values())
        dns_queries = list(analyzer.dns_queries)
        alerts = list(analyzer.alerts)

    total_devices = len(scanner.devices)
    total_connections = len(connections)
    total_bytes = sum(c.byte_count for c in connections)
    external_flows = sum(1 for c in connections if (not is_private_ip(c.src_ip) or not is_private_ip(c.dst_ip)))
    internal_flows = total_connections - external_flows

    ip_bytes = defaultdict(int)
    for c in connections:
        ip_bytes[c.src_ip] += c.byte_count
        ip_bytes[c.dst_ip] += c.byte_count
    top_talkers = sorted(ip_bytes.items(), key=lambda x: -x[1])[:8]

    domain_counts = defaultdict(int)
    for q in dns_queries:
        domain_counts[q.domain] += 1
    top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:8]

    risk_ports = {
        21: 'FTP',
        23: 'Telnet',
        445: 'SMB',
        3389: 'RDP',
        5900: 'VNC',
        6379: 'Redis',
        9200: 'Elasticsearch',
        27017: 'MongoDB',
    }
    exposed_services = []
    for d in scanner.devices.values():
        for p in d.open_ports:
            if p in risk_ports:
                exposed_services.append({
                    'ip': d.ip,
                    'hostname': d.hostname,
                    'port': p,
                    'service': risk_ports[p],
                })

    insights = []
    if external_flows > 0:
        insights.append(f"{external_flows} external-facing flows observed; prioritize reviewing destination reputation.")
    if top_talkers:
        lead_ip, lead_bytes = top_talkers[0]
        insights.append(f"Top talker {lead_ip} accounts for {format_bytes_for_story(lead_bytes)} of observed traffic.")
    if top_domains:
        lead_domain, lead_count = top_domains[0]
        insights.append(f"Most queried domain: {lead_domain} ({lead_count} lookups).")
    if exposed_services:
        insights.append(f"{len(exposed_services)} potentially high-risk service exposures detected across assets.")
    if alerts:
        sev_counts = defaultdict(int)
        for a in alerts:
            sev_counts[a.severity] += 1
        insights.append(
            "Active alerts by severity: " +
            ", ".join(f"{k}={v}" for k, v in sorted(sev_counts.items(), key=lambda kv: kv[0]))
        )
    if not insights:
        insights.append("No significant risk indicators detected in current telemetry window.")

    summary = (
        f"Observed {total_devices} devices, {total_connections} connections, and "
        f"{format_bytes_for_story(total_bytes)} of traffic. "
        f"Internal flows: {internal_flows}, external flows: {external_flows}."
    )

    return {
        'generated_at': datetime.now().isoformat(),
        'summary': summary,
        'insights': insights,
        'top_talkers': [{'ip': ip, 'bytes': bytes_count} for ip, bytes_count in top_talkers],
        'top_domains': [{'domain': d, 'count': c} for d, c in top_domains],
        'exposed_services': exposed_services[:30],
        'recent_alerts': [asdict(a) for a in alerts[-20:]],
        'timeline': datastore.get_recent_observations(limit=80),
    }


def format_bytes_for_story(value: int) -> str:
    """Readable byte formatter for narrative output."""
    if value <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    size = float(value)
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    return f"{size:.1f} {units[idx]}"


@app.route('/api/intel/story', methods=['GET'])
def get_network_story():
    """Return correlated story-style intelligence for the current network view."""
    return jsonify(build_network_story_internal())


@app.route('/api/intel/timeline', methods=['GET'])
def get_network_timeline():
    """Return persisted observation timeline."""
    limit = int(request.args.get('limit', 100))
    return jsonify({'timeline': datastore.get_recent_observations(limit=limit)})


# -----------------------------
# NIP APIs (Phase 0 substrate)
# -----------------------------

@app.route('/api/nip/techniques', methods=['GET'])
def nip_list_techniques():
    """List all registered techniques (self-describing primitives)."""
    return jsonify({"techniques": registry_as_list(nip_registry)})


@app.route('/api/nip/events', methods=['GET'])
def nip_list_events():
    """List recent in-memory bus events (best-effort, bounded buffer)."""
    limit = int(request.args.get("limit", 200))
    return jsonify({"events": nip_bus.list_events(limit=limit)})


@app.route('/api/nip/graph', methods=['GET'])
def nip_graph_snapshot():
    """Return a lightweight knowledge-graph snapshot from persisted assets/services/flows."""
    limit_assets = int(request.args.get("assets", 2000))
    limit_services = int(request.args.get("services", 5000))
    limit_flows = int(request.args.get("flows", 5000))

    as_of = str(request.args.get("as_of", "") or "").strip()

    assets = datastore.list_assets(limit=limit_assets, as_of=as_of)
    services = datastore.list_services(limit=limit_services, as_of=as_of)
    flows = datastore.list_flows(limit=limit_flows, as_of=as_of)

    nodes = []
    edges = []

    # Device nodes
    for a in assets:
        nodes.append(
            {
                "id": a["ip"],
                "type": "Device",
                **a,
            }
        )

    # Service nodes + edges
    for s in services:
        sid = f"svc:{s['ip']}:{s['protocol']}:{s['port']}"
        nodes.append(
            {
                "id": sid,
                "type": "Service",
                "ip": s["ip"],
                "port": s["port"],
                "protocol": s["protocol"],
                "service": s["service"],
                "banner": s["banner"],
                "first_seen": s["first_seen"],
                "last_seen": s["last_seen"],
            }
        )
        edges.append({"source": s["ip"], "target": sid, "type": "RUNS", "first_seen": s["first_seen"], "last_seen": s["last_seen"]})

    # Flow edges (Device -> Device)
    for f in flows:
        if not f.get("src_ip") or not f.get("dst_ip"):
            continue
        edges.append(
            {
                "source": f["src_ip"],
                "target": f["dst_ip"],
                "type": "CONNECTS",
                "protocol": f.get("protocol"),
                "application": f.get("application"),
                "src_port": f.get("src_port"),
                "dst_port": f.get("dst_port"),
                "packet_count": f.get("packet_count"),
                "byte_count": f.get("byte_count"),
                "first_seen": f.get("first_seen"),
                "last_seen": f.get("last_seen"),
            }
        )

    return jsonify(
        {
            "generated_at": datetime.now().isoformat(),
            "as_of": as_of or None,
            "nodes": nodes,
            "edges": edges,
            "counts": {"assets": len(assets), "services": len(services), "flows": len(flows)},
            "note": "This is a lightweight snapshot derived from SQLite tables; use /api/intel/timeline for temporal event history.",
        }
    )


@app.route('/api/nip/daemon/status', methods=['GET'])
def nip_daemon_status():
    """Return status for the NIP metrics/baselining daemon."""
    return jsonify({"daemon": nip_metrics_daemon.status()})


@app.route('/api/nip/daemon/start', methods=['POST'])
def nip_daemon_start():
    """Start the NIP metrics/baselining daemon (optional interval/alpha overrides)."""
    data = request.json or {}
    interval = data.get("interval_seconds", data.get("interval", None))
    alpha = data.get("alpha", None)
    try:
        nip_metrics_daemon.configure(interval_seconds=interval, alpha=alpha)
    except Exception:
        pass
    nip_metrics_daemon.start()
    try:
        datastore.add_observation("nip", "daemon", "NIP metrics daemon started", nip_metrics_daemon.status())
    except Exception:
        pass
    return jsonify({"daemon": nip_metrics_daemon.status()})


@app.route('/api/nip/daemon/stop', methods=['POST'])
def nip_daemon_stop():
    """Stop the NIP metrics/baselining daemon."""
    nip_metrics_daemon.stop()
    try:
        datastore.add_observation("nip", "daemon", "NIP metrics daemon stopped", nip_metrics_daemon.status())
    except Exception:
        pass
    return jsonify({"daemon": nip_metrics_daemon.status()})


@app.route('/api/nip/metrics', methods=['GET'])
def nip_list_metrics():
    """List recent per-window metrics rows (optionally filtered by IP)."""
    ip = str(request.args.get("ip", "") or "").strip()
    limit = int(request.args.get("limit", 400))
    return jsonify({"metrics": datastore.list_nip_metrics(ip=ip, limit=limit)})


@app.route('/api/nip/baselines', methods=['GET'])
def nip_list_baselines():
    """List baselines or return one baseline for a given IP."""
    ip = str(request.args.get("ip", "") or "").strip()
    limit = int(request.args.get("limit", 2000))
    if ip:
        return jsonify({"baseline": datastore.get_nip_baseline(ip)})
    return jsonify({"baselines": datastore.list_nip_baselines(limit=limit)})


@app.route('/api/nip/threat/check', methods=['GET'])
def nip_threat_check():
    """Check current telemetry against a local threat indicator file (starter for Phase 2.4)."""
    path = str(request.args.get("path", "") or "").strip()
    feed_path = Path(path or NIP_THREAT_FEED_PATH)

    limit_flows = int(request.args.get("flows", 5000))
    limit_dns = int(request.args.get("dns", 5000))
    max_alerts = int(request.args.get("max_alerts", 10))

    indicators = []
    try:
        if feed_path.exists():
            indicators_obj = json.loads(feed_path.read_text(encoding="utf-8"))
            if isinstance(indicators_obj, dict) and isinstance(indicators_obj.get("indicators"), list):
                indicators = indicators_obj.get("indicators") or []
    except Exception:
        indicators = []

    bad_ips = set()
    bad_domains = set()
    for ind in indicators:
        if not isinstance(ind, dict):
            continue
        itype = str(ind.get("type") or "").strip().lower()
        val = str(ind.get("value") or "").strip()
        if not itype or not val:
            continue
        if itype == "ip":
            bad_ips.add(val)
        elif itype == "domain":
            bad_domains.add(val.lower().rstrip("."))

    flows = datastore.list_flows(limit=max(1, int(limit_flows)))
    flow_matches = []
    for f in flows:
        src = str(f.get("src_ip") or "")
        dst = str(f.get("dst_ip") or "")
        if src in bad_ips or dst in bad_ips:
            flow_matches.append(
                {
                    "flow_key": f.get("flow_key"),
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": f.get("dst_port"),
                    "protocol": f.get("protocol"),
                    "application": f.get("application"),
                    "byte_count": f.get("byte_count"),
                    "first_seen": f.get("first_seen"),
                    "last_seen": f.get("last_seen"),
                    "indicator_ip": src if src in bad_ips else dst,
                }
            )

    with datastore.lock, datastore._connect() as conn:
        d_rows = conn.execute(
            "SELECT src_ip, domain, query_type, resolved_ip, timestamp FROM dns_queries ORDER BY id DESC LIMIT ?",
            (max(1, int(limit_dns)),),
        ).fetchall()

    dns_matches = []
    for r in d_rows:
        domain = (r["domain"] or "").lower().rstrip(".")
        resolved = str(r["resolved_ip"] or "").strip()
        hit_domain = ""
        if domain:
            if domain in bad_domains:
                hit_domain = domain
            else:
                for bd in bad_domains:
                    if bd and domain.endswith("." + bd):
                        hit_domain = bd
                        break
        if hit_domain or (resolved and resolved in bad_ips):
            dns_matches.append(
                {
                    "src_ip": r["src_ip"],
                    "domain": r["domain"],
                    "query_type": r["query_type"],
                    "resolved_ip": r["resolved_ip"],
                    "timestamp": r["timestamp"],
                    "indicator_domain": hit_domain or None,
                    "indicator_ip": resolved if resolved in bad_ips else None,
                }
            )

    total_matches = len(flow_matches) + len(dns_matches)

    if total_matches > 0:
        summary = f"Threat indicator matches: flows={len(flow_matches)} dns={len(dns_matches)} (feed={feed_path.name})"
        try:
            datastore.add_observation(
                "threat",
                "network",
                summary,
                {
                    "feed_path": str(feed_path),
                    "bad_ips": sorted(list(bad_ips))[:1000],
                    "bad_domains": sorted(list(bad_domains))[:1000],
                    "flow_matches": flow_matches[:50],
                    "dns_matches": dns_matches[:50],
                },
            )
        except Exception:
            pass

        # Emit a small number of alerts + bus events (avoid spam).
        emitted = 0
        for m in (flow_matches + dns_matches)[: max(0, int(max_alerts))]:
            if emitted >= max(0, int(max_alerts)):
                break
            ind = m.get("indicator_ip") or m.get("indicator_domain") or ""
            msg = f"Threat match: {ind}"
            try:
                analyzer._add_alert(
                    "threat_match",
                    "high",
                    msg,
                    src_ip=str(m.get("src_ip") or ""),
                    dst_ip=str(m.get("dst_ip") or ""),
                    details={"match": m, "feed_path": str(feed_path)},
                )
            except Exception:
                pass
            try:
                nip_bus.publish(
                    event_type="threat.match",
                    source="nip:threat_check",
                    entity=str(ind),
                    summary=msg,
                    data={"match": m, "feed_path": str(feed_path)},
                )
            except Exception:
                pass
            emitted += 1

    return jsonify(
        {
            "generated_at": datetime.now().isoformat(),
            "feed_path": str(feed_path),
            "indicators_loaded": {"ips": len(bad_ips), "domains": len(bad_domains)},
            "matches": {"flows": flow_matches, "dns": dns_matches},
            "counts": {"flow_matches": len(flow_matches), "dns_matches": len(dns_matches), "total": total_matches},
            "note": "This uses a local indicator file (no automatic downloads). Add indicators to samples/threat_indicators.json or set NIP_THREAT_FEED_PATH.",
        }
    )


@app.route('/api/nip/graph/diff', methods=['GET'])
def nip_graph_diff():
    """Return a simple 'what appeared between t1 and t2' diff (additions only)."""
    t1 = str(request.args.get("t1", request.args.get("from", "")) or "").strip()
    t2 = str(request.args.get("t2", request.args.get("to", "")) or "").strip()
    if not t1 or not t2:
        return jsonify({"error": "missing_t1_t2", "hint": "Provide ?t1=<ISO>&t2=<ISO> (or from/to)."}), 400

    limit_assets = int(request.args.get("assets", 2000))
    limit_services = int(request.args.get("services", 5000))
    limit_flows = int(request.args.get("flows", 5000))

    with datastore.lock, datastore._connect() as conn:
        a_rows = conn.execute(
            """
            SELECT ip, mac, hostname, vendor, os, is_gateway, is_local, first_seen, last_seen, last_scan_profile, metadata_json
            FROM assets
            WHERE first_seen IS NOT NULL AND first_seen != '' AND first_seen > ? AND first_seen <= ?
            ORDER BY first_seen ASC
            LIMIT ?
            """,
            (t1, t2, max(1, int(limit_assets))),
        ).fetchall()
        s_rows = conn.execute(
            """
            SELECT ip, port, protocol, service, banner, first_seen, last_seen
            FROM services
            WHERE first_seen IS NOT NULL AND first_seen != '' AND first_seen > ? AND first_seen <= ?
            ORDER BY first_seen ASC
            LIMIT ?
            """,
            (t1, t2, max(1, int(limit_services))),
        ).fetchall()
        f_rows = conn.execute(
            """
            SELECT flow_key, src_ip, dst_ip, src_port, dst_port, protocol, application, packet_count, byte_count, first_seen, last_seen, updated_at
            FROM flows
            WHERE first_seen IS NOT NULL AND first_seen != '' AND first_seen > ? AND first_seen <= ?
            ORDER BY first_seen ASC
            LIMIT ?
            """,
            (t1, t2, max(1, int(limit_flows))),
        ).fetchall()

    added_assets = []
    for r in a_rows:
        try:
            meta = json.loads(r["metadata_json"] or "{}")
        except Exception:
            meta = {}
        added_assets.append(
            {
                "ip": r["ip"],
                "mac": r["mac"] or "",
                "hostname": r["hostname"] or "",
                "vendor": r["vendor"] or "",
                "os": r["os"] or "",
                "is_gateway": bool(r["is_gateway"]),
                "is_local": bool(r["is_local"]),
                "first_seen": r["first_seen"] or "",
                "last_seen": r["last_seen"] or "",
                "last_scan_profile": r["last_scan_profile"] or "",
                "metadata": meta,
            }
        )

    added_services = [
        {
            "ip": r["ip"],
            "port": int(r["port"] or 0),
            "protocol": r["protocol"] or "tcp",
            "service": r["service"] or "",
            "banner": r["banner"] or "",
            "first_seen": r["first_seen"] or "",
            "last_seen": r["last_seen"] or "",
        }
        for r in s_rows
    ]
    added_flows = [
        {
            "flow_key": r["flow_key"],
            "src_ip": r["src_ip"],
            "dst_ip": r["dst_ip"],
            "src_port": int(r["src_port"] or 0),
            "dst_port": int(r["dst_port"] or 0),
            "protocol": r["protocol"] or "",
            "application": r["application"] or "",
            "packet_count": int(r["packet_count"] or 0),
            "byte_count": int(r["byte_count"] or 0),
            "first_seen": r["first_seen"] or "",
            "last_seen": r["last_seen"] or "",
            "updated_at": r["updated_at"] or "",
        }
        for r in f_rows
    ]

    return jsonify(
        {
            "generated_at": datetime.now().isoformat(),
            "t1": t1,
            "t2": t2,
            "added": {
                "assets": added_assets,
                "services": added_services,
                "flows": added_flows,
            },
            "counts": {
                "assets_added": len(added_assets),
                "services_added": len(added_services),
                "flows_added": len(added_flows),
            },
            "note": "This diff reports additions based on first_seen timestamps. Removals require explicit inactive marking (not yet implemented).",
        }
    )


@app.route('/api/nip/correlate', methods=['GET'])
def nip_correlate():
    """Return observations/metrics around an anchor timestamp (NIP Phase 3.4-style helper)."""
    anchor_ts = str(request.args.get("ts", "") or "").strip()
    entity = str(request.args.get("entity", "") or "").strip()
    ip = str(request.args.get("ip", "") or "").strip() or entity
    window_seconds = int(request.args.get("window_seconds", request.args.get("window", 300)) or 300)
    limit = int(request.args.get("limit", 200) or 200)
    metrics_limit = int(request.args.get("metrics_limit", 400) or 400)

    if not anchor_ts:
        anchor_dt = datetime.now()
        anchor_ts = anchor_dt.isoformat()
    else:
        try:
            anchor_dt = datetime.fromisoformat(anchor_ts.replace("Z", "+00:00"))
            # Normalize to naive local ISO strings for DB comparisons if tz-aware.
            if anchor_dt.tzinfo is not None:
                anchor_dt = anchor_dt.astimezone(tz=None).replace(tzinfo=None)
        except Exception:
            anchor_dt = datetime.now()
            anchor_ts = anchor_dt.isoformat()

    w = max(5, min(int(window_seconds), 3600 * 24))
    start_dt = anchor_dt - timedelta(seconds=w)
    end_dt = anchor_dt + timedelta(seconds=w)
    start_ts = start_dt.isoformat()
    end_ts = end_dt.isoformat()

    obs = datastore.list_observations_range(start_ts=start_ts, end_ts=end_ts, like=(entity or ip), limit=limit)

    metrics = []
    if ip:
        metrics = datastore.list_nip_metrics_range(ip=ip, start_ts=start_ts, end_ts=end_ts, limit=metrics_limit)

    return jsonify(
        {
            "generated_at": datetime.now().isoformat(),
            "anchor_ts": anchor_ts,
            "entity": entity,
            "ip": ip,
            "window_seconds": w,
            "start_ts": start_ts,
            "end_ts": end_ts,
            "observations": obs,
            "metrics": metrics,
            "note": "This is a best-effort correlator using ISO string windows; for rigorous UTC handling, normalize all stored timestamps to UTC.",
        }
    )


# ---------------------------------------------------------------------------
# NIP Phase 1.1 — Enhanced Graph (Subnet / DNSRecord / ThreatIndicator nodes)
# ---------------------------------------------------------------------------

@app.route('/api/nip/graph/full', methods=['GET'])
def nip_graph_full():
    """Full graph snapshot including Subnet, DNSRecord, Alert, ThreatIndicator nodes + all edge types."""
    limit_assets = int(request.args.get("assets", 2000))
    limit_services = int(request.args.get("services", 5000))
    limit_flows = int(request.args.get("flows", 5000))
    as_of = str(request.args.get("as_of", "") or "").strip()

    assets = datastore.list_assets(limit=limit_assets, as_of=as_of)
    services = datastore.list_services(limit=limit_services, as_of=as_of)
    flows = datastore.list_flows(limit=limit_flows, as_of=as_of)

    nodes = []
    edges = []
    seen_node_ids = set()

    # Device nodes
    for a in assets:
        nid = a["ip"]
        if nid not in seen_node_ids:
            seen_node_ids.add(nid)
            meta = {}
            try:
                meta = json.loads(a.get("metadata_json") or "{}")
            except Exception:
                pass
            nodes.append({"id": nid, "type": "Device", **a, "risk_score": meta.get("risk_score"), "behavioral_cluster": meta.get("community")})

    # Service nodes + RUNS edges
    for s in services:
        sid = f"svc:{s['ip']}:{s['protocol']}:{s['port']}"
        if sid not in seen_node_ids:
            seen_node_ids.add(sid)
            nodes.append({"id": sid, "type": "Service", "ip": s["ip"], "port": s["port"], "protocol": s["protocol"], "service": s["service"], "banner": s["banner"], "first_seen": s["first_seen"], "last_seen": s["last_seen"]})
        edges.append({"source": s["ip"], "target": sid, "type": "RUNS", "first_seen": s["first_seen"], "last_seen": s["last_seen"]})

    # Flow edges (CONNECTS_TO)
    for f in flows:
        if not f.get("src_ip") or not f.get("dst_ip"):
            continue
        edges.append({"source": f["src_ip"], "target": f["dst_ip"], "type": "CONNECTS_TO", "protocol": f.get("protocol"), "application": f.get("application"), "dst_port": f.get("dst_port"), "packet_count": f.get("packet_count"), "byte_count": f.get("byte_count"), "first_seen": f.get("first_seen"), "last_seen": f.get("last_seen")})

    # Subnet nodes + HOSTS edges
    with datastore.lock, datastore._connect() as conn:
        subnet_rows = conn.execute("SELECT cidr, gateway, vlan_id, device_count, first_seen, last_seen FROM subnets").fetchall()
        for sr in subnet_rows:
            sid = f"subnet:{sr['cidr']}"
            if sid not in seen_node_ids:
                seen_node_ids.add(sid)
                nodes.append({"id": sid, "type": "Subnet", "cidr": sr["cidr"], "gateway": sr["gateway"], "vlan_id": sr["vlan_id"], "device_count": sr["device_count"], "first_seen": sr["first_seen"], "last_seen": sr["last_seen"]})
            if sr["gateway"]:
                edges.append({"source": sr["gateway"], "target": sid, "type": "GATEWAY_FOR"})

    # Derive HOSTS edges (Device belongs to which Subnet)
    import ipaddress as _ipaddr
    subnet_nets = []
    for sr in subnet_rows:
        try:
            subnet_nets.append((sr["cidr"], _ipaddr.ip_network(sr["cidr"], strict=False)))
        except Exception:
            pass
    for a in assets:
        try:
            ip_obj = _ipaddr.ip_address(a["ip"])
            for cidr, net in subnet_nets:
                if ip_obj in net:
                    edges.append({"source": f"subnet:{cidr}", "target": a["ip"], "type": "HOSTS"})
                    break
        except Exception:
            pass

    # DNSRecord nodes + RESOLVES edges
    with datastore.lock, datastore._connect() as conn:
        dns_rows = conn.execute("SELECT id, domain, record_type, value, first_seen, last_seen, query_count FROM dns_records ORDER BY query_count DESC LIMIT 500").fetchall()
    for dr in dns_rows:
        did = f"dns:{dr['domain']}:{dr['record_type']}"
        if did not in seen_node_ids:
            seen_node_ids.add(did)
            nodes.append({"id": did, "type": "DNSRecord", "domain": dr["domain"], "record_type": dr["record_type"], "value": dr["value"], "first_seen": dr["first_seen"], "last_seen": dr["last_seen"], "query_count": dr["query_count"]})

    # Build RESOLVES edges from dns_queries table
    with datastore.lock, datastore._connect() as conn:
        dq_rows = conn.execute("SELECT DISTINCT src_ip, domain FROM dns_queries LIMIT 2000").fetchall()
    for dq in dq_rows:
        src_ip = str(dq["src_ip"] or "")
        domain = str(dq["domain"] or "")
        if src_ip and domain:
            did = f"dns:{domain}:A"
            edges.append({"source": src_ip, "target": did, "type": "RESOLVES"})

    # Alert nodes + TRIGGERED edges
    with datastore.lock, datastore._connect() as conn:
        alert_rows = conn.execute("SELECT id, alert_type, severity, message, src_ip, dst_ip, timestamp, details_json FROM alerts ORDER BY id DESC LIMIT 200").fetchall()
    for ar in alert_rows:
        aid = f"alert:{ar['id']}"
        if aid not in seen_node_ids:
            seen_node_ids.add(aid)
            nodes.append({"id": aid, "type": "Alert", "alert_type": ar["alert_type"], "severity": ar["severity"], "description": ar["message"], "timestamp": ar["timestamp"]})
        if ar["src_ip"]:
            edges.append({"source": ar["src_ip"], "target": aid, "type": "TRIGGERED"})

    # ThreatIndicator nodes + MATCHES edges
    with datastore.lock, datastore._connect() as conn:
        ti_rows = conn.execute("SELECT id, indicator_type, value, source, confidence, first_seen, last_seen FROM threat_indicators LIMIT 500").fetchall()
    for ti in ti_rows:
        tid = f"threat:{ti['indicator_type']}:{ti['value']}"
        if tid not in seen_node_ids:
            seen_node_ids.add(tid)
            nodes.append({"id": tid, "type": "ThreatIndicator", "indicator_type": ti["indicator_type"], "value": ti["value"], "source": ti["source"], "confidence": ti["confidence"], "first_seen": ti["first_seen"], "last_seen": ti["last_seen"]})

    return jsonify({"generated_at": datetime.now().isoformat(), "as_of": as_of or None, "nodes": nodes, "edges": edges, "counts": {"nodes": len(nodes), "edges": len(edges)}})


# ---------------------------------------------------------------------------
# NIP Phase 1.2 — Enhanced graph diff (with removals + property changes)
# ---------------------------------------------------------------------------

@app.route('/api/nip/graph/diff/full', methods=['GET'])
def nip_graph_diff_full():
    """Graph diff between t1 and t2 with additions AND removals."""
    t1 = str(request.args.get("t1", "") or "").strip()
    t2 = str(request.args.get("t2", "") or "").strip()
    if not t1 or not t2:
        return jsonify({"error": "missing_t1_t2"}), 400

    with datastore.lock, datastore._connect() as conn:
        added_assets = [dict(r) for r in conn.execute(
            "SELECT ip, mac, hostname, vendor, os, first_seen, last_seen FROM assets WHERE first_seen > ? AND first_seen <= ?", (t1, t2)).fetchall()]
        added_services = [dict(r) for r in conn.execute(
            "SELECT ip, port, protocol, service, banner, first_seen, last_seen FROM services WHERE first_seen > ? AND first_seen <= ?", (t1, t2)).fetchall()]
        # Removals: devices seen before t1 but NOT seen after t1
        removed_assets = [dict(r) for r in conn.execute(
            "SELECT ip, mac, hostname, vendor, os, first_seen, last_seen FROM assets WHERE last_seen <= ? AND first_seen <= ?", (t1, t1)).fetchall()]
        removed_services = [dict(r) for r in conn.execute(
            "SELECT ip, port, protocol, service, banner, first_seen, last_seen FROM services WHERE last_seen <= ? AND first_seen <= ?", (t1, t1)).fetchall()]
        # Property changes: devices that existed before t1 but were updated between t1 and t2
        changed_assets = [dict(r) for r in conn.execute(
            "SELECT ip, mac, hostname, vendor, os, first_seen, last_seen FROM assets WHERE first_seen <= ? AND last_seen > ? AND last_seen <= ?", (t1, t1, t2)).fetchall()]

    return jsonify({
        "generated_at": datetime.now().isoformat(),
        "t1": t1, "t2": t2,
        "added": {"assets": added_assets, "services": added_services},
        "removed": {"assets": removed_assets, "services": removed_services},
        "changed": {"assets": changed_assets},
        "counts": {
            "assets_added": len(added_assets), "services_added": len(added_services),
            "assets_removed": len(removed_assets), "services_removed": len(removed_services),
            "assets_changed": len(changed_assets),
        },
    })


# ---------------------------------------------------------------------------
# NIP Phase 2.5 — Log Ingestion
# ---------------------------------------------------------------------------

@app.route('/api/nip/logs/ingest', methods=['POST'])
def nip_log_ingest():
    """Ingest a log file (syslog/dhcp/auth/firewall) into the graph + event bus."""
    data = request.json or {}
    path = str(data.get("path", "") or "").strip()
    log_type = str(data.get("log_type", "auto") or "auto").strip()
    if not path:
        return jsonify({"error": "path_required"}), 400

    result = ingest_log_file(path, log_type=log_type)
    if not result.get("ok"):
        return jsonify(result), 400

    # Persist into log_events table + observations.
    events = result.get("events") or []
    persisted = 0
    with datastore.lock, datastore._connect() as conn:
        for ev in events[:10000]:
            try:
                conn.execute(
                    "INSERT INTO log_events (log_type, timestamp, source_file, entity, summary, payload_json) VALUES (?,?,?,?,?,?)",
                    (ev.get("type", ""), ev.get("timestamp", ""), path, ev.get("host") or ev.get("src_ip") or "", ev.get("message") or ev.get("hostname") or "", json.dumps(ev)),
                )
                persisted += 1
            except Exception:
                pass

    # Publish bus events for DHCP leases (device enrichment).
    for ev in events:
        if ev.get("type") == "dhcp_lease" and ev.get("ip"):
            _nip_upsert_device_min(ip=ev["ip"], mac=ev.get("mac", ""), hostname=ev.get("hostname", ""), scan_profile="log_dhcp")
            nip_bus.publish(event_type="device.dhcp_lease", source="log_ingest:dhcp", entity=ev["ip"],
                           summary=f"DHCP lease {ev['ip']} -> {ev.get('mac', '')} ({ev.get('hostname', '')})",
                           data=ev)
        elif ev.get("type") == "firewall" and ev.get("action", "").upper() in ("DROP", "REJECT", "BLOCK"):
            nip_bus.publish(event_type="firewall.block", source="log_ingest:firewall", entity=ev.get("src_ip", ""),
                           summary=f"Firewall {ev.get('action')} {ev.get('src_ip')}:{ev.get('src_port')} -> {ev.get('dst_ip')}:{ev.get('dst_port')}",
                           data=ev)
        elif ev.get("type") == "auth" and ev.get("auth_result") == "fail":
            nip_bus.publish(event_type="auth.failure", source="log_ingest:auth", entity=ev.get("src_ip", ""),
                           summary=f"Auth failure for {ev.get('user', '?')} from {ev.get('src_ip', '?')}",
                           data=ev)

    result["persisted"] = persisted
    return jsonify(result)


# ---------------------------------------------------------------------------
# NIP Phase 3.3 — Auto-correlation subscriber
# ---------------------------------------------------------------------------

def _nip_auto_correlate(ev):
    """Event bus subscriber: when anomaly.detected fires, auto-correlate and publish."""
    if ev.type != "anomaly.detected":
        return
    try:
        from analysis.analysis_engine import score_anomaly
        entity = ev.entity or ""
        if not entity:
            return
        anchor_ts = ev.ts or datetime.now().isoformat()
        try:
            anchor_dt = datetime.fromisoformat(str(anchor_ts).replace("Z", "+00:00"))
            if anchor_dt.tzinfo is not None:
                anchor_dt = anchor_dt.astimezone(tz=None).replace(tzinfo=None)
        except Exception:
            anchor_dt = datetime.now()
        w = 300
        start_ts = (anchor_dt - timedelta(seconds=w)).isoformat()
        end_ts = (anchor_dt + timedelta(seconds=w)).isoformat()
        obs = datastore.list_observations_range(start_ts=start_ts, end_ts=end_ts, like=entity, limit=50)
        if obs:
            nip_bus.publish(
                event_type="correlation.found",
                source="nip:auto_correlator",
                entity=entity,
                summary=f"Auto-correlated {len(obs)} events around anomaly on {entity}",
                data={"anchor_ts": anchor_ts, "entity": entity, "related_count": len(obs), "window_seconds": w},
            )
    except Exception:
        pass


try:
    nip_bus.subscribe(_nip_auto_correlate)
except Exception:
    pass


# ---------------------------------------------------------------------------
# NIP Phase 4 — Brain APIs
# ---------------------------------------------------------------------------

nip_brain_assessor = SituationAssessor()
nip_brain_selector = TechniqueSelector(nip_registry)
nip_brain_planner = StrategyPlanner()


@app.route('/api/nip/brain/assess', methods=['GET'])
def nip_brain_assess():
    """Run the Situation Assessor and return current network knowledge + gaps."""
    assets = datastore.list_assets(limit=5000)
    services = datastore.list_services(limit=10000)
    baselines = datastore.list_nip_baselines(limit=5000)
    alerts = datastore.list_alerts(limit=1000)
    situation = nip_brain_assessor.assess(assets=assets, services=services, baselines=baselines, alerts=alerts)
    return jsonify({"situation": asdict(situation)})


@app.route('/api/nip/brain/plan', methods=['GET', 'POST'])
def nip_brain_plan():
    """Run the full Brain pipeline: Assess -> Plan objectives -> Select techniques."""
    data = request.json if request.method == "POST" else {}
    stealth = float((data or {}).get("stealth", 0.5))

    assets = datastore.list_assets(limit=5000)
    services = datastore.list_services(limit=10000)
    baselines = datastore.list_nip_baselines(limit=5000)
    alerts = datastore.list_alerts(limit=1000)

    situation = nip_brain_assessor.assess(assets=assets, services=services, baselines=baselines, alerts=alerts)
    objectives = nip_brain_planner.plan(situation, required_stealth=stealth)

    planned = []
    for obj in objectives:
        target_device = None
        if obj.targets:
            for dk in situation.devices:
                if dk.ip in obj.targets:
                    target_device = dk
                    break
        techniques = nip_brain_selector.select(objective=obj.type, device=target_device, stealth=obj.stealth)
        planned.append({"objective": asdict(obj), "techniques": [asdict(t) for t in techniques]})

    # Persist the plan.
    try:
        with datastore.lock, datastore._connect() as conn:
            conn.execute(
                "INSERT INTO brain_plans (generated_at, situation_json, objectives_json, planned_techniques_json) VALUES (?,?,?,?)",
                (datetime.now().isoformat(), json.dumps(asdict(situation)), json.dumps([asdict(o) for o in objectives]), json.dumps(planned)),
            )
    except Exception:
        pass

    return jsonify({"situation_summary": {"total_devices": situation.total_devices, "coverage_pct": situation.overall_coverage_pct, "stale": len(situation.stale_devices), "unresolved_alerts": situation.unresolved_alerts, "gaps": situation.knowledge_gaps}, "plan": planned})


# ---------------------------------------------------------------------------
# NIP Phase 4 — Brain Execute (run a single technique via coursework jobs)
# ---------------------------------------------------------------------------

_TECHNIQUE_TO_ACTION = {
    # --- L2 discovery ---
    "mod1.active_arp": ("mod1", "active"),
    "mod1.passive_arp": ("mod1", "passive"),
    "mod1.mac_randomization": ("mod1", "randomized"),
    # --- Transport scanning ---
    "mod2.tcp_syn": ("mod2", "syn"),
    "mod2.tcp_connect": ("mod2", "connect"),
    "mod2.tcp_fin": ("mod2", "fin"),
    "mod2.tcp_xmas": ("mod2", "xmas"),
    "mod2.tcp_null": ("mod2", "null"),
    "mod2.udp_scan": ("mod2", "udp"),
    "mod2.tcp_ack": ("mod2", "ack"),
    # --- IP-layer ---
    "mod3.frag_scan": ("mod3", "frag"),
    "mod3.fragmentation": ("mod3", "frag"),
    "mod3.ttl_path": ("mod3", "ttl"),
    "mod3.ipid_profile": ("mod3", "ipid"),
    "mod3.ipid_sweep": ("mod3", "ipid-sweep"),
    "mod3.idle_scan": ("mod3", "idle"),
    "mod3.decoy_scan": ("mod3", "decoy"),
    "mod3.decoy_mixing": ("mod3", "decoy"),
    # --- Timing ---
    "mod4.fixed_rates": ("mod4", "fixed"),
    "mod4.jitter": ("mod4", "jitter"),
    "mod4.ordering": ("mod4", "order"),
    # --- Application fingerprinting ---
    "mod5.tcp_fingerprint": ("mod5", "tcpfp"),
    "mod5.banner": ("mod5", "banner"),
    "mod5.tls": ("mod5", "tls"),
    "mod5.tls_grab": ("mod5", "tls"),
    "mod5.http_headers": ("mod5", "http"),
    "mod5.dns_enum": ("mod5", "dns"),
    "mod5.dns_fingerprint": ("mod5", "dns"),
    "mod5.passive_dns": ("mod5", "passive-dns"),
    # --- Passive collection ---
    "mod6.promisc": ("mod6", "promisc"),
    "mod6.promisc_detect": ("mod6", "promisc"),
    "mod6.pcap_ingest": ("mod6", "pcap"),
    "mod6.netflow_collect": ("mod6", "netflow"),
    # --- Detection / IDS ---
    "mod7.arpwatch": ("mod7", "arpwatch"),
    "mod7.netflow_detect": ("mod7", "netflow-detect"),
    # --- Analysis ---
    "analysis.baseline_compute": ("analysis", "compute-baseline"),
    "analysis.anomaly_score": ("analysis", "anomaly-score"),
    "analysis.identity_resolve": ("analysis", "identity-resolve"),
    "analysis.identity_resolution": ("analysis", "identity-resolve"),
    "analysis.community_detect": ("analysis", "community-detect"),
    "analysis.community_detection": ("analysis", "community-detect"),
    "analysis.risk_score": ("analysis", "risk-score"),
    "analysis.attack_chain": ("analysis", "attack-chain"),
    "analysis.temporal_correlation": ("analysis", "temporal-correlate"),
    "analysis.graph_diff": ("analysis", "graph-diff"),
    # --- Threat intel ---
    "threat.cve_lookup": ("threat", "cve-lookup"),
    "threat.ip_reputation": ("threat", "ip-reputation"),
    "threat.domain_reputation": ("threat", "domain-reputation"),
    "threat.feed_sync": ("threat", "feed-sync"),
    # --- Discovery protocols ---
    "discovery.mdns_passive": ("discovery", "mdns-passive"),
    "discovery.mdns": ("discovery", "mdns"),
    "discovery.ssdp": ("discovery", "ssdp"),
    "discovery.ssdp_upnp": ("discovery", "ssdp"),
    "discovery.nbns": ("discovery", "nbns"),
    "discovery.llmnr": ("discovery", "llmnr-passive"),
    "discovery.wsd": ("discovery", "wsd"),
    # --- Protocol-specific ---
    "tls.ja3": ("tls", "ja3"),
    "tls.ja3_fingerprint": ("tls", "ja3"),
    "dns.tunnel_detect": ("dns", "tunnel-detect"),
    "dns.doh_detect": ("dns", "doh-detect"),
    "dns.dga_detect": ("dns", "dga-detect"),
    "dns.tunnel_detection": ("dns", "tunnel-detect"),
    "snmp.walk": ("snmp", "walk"),
    "ssh.host_key_fp": ("ssh", "host-key-fp"),
    "ssh.host_key_fingerprint": ("ssh", "host-key-fp"),
    "smb.enum_shares": ("smb", "enum-shares"),
    "smb.os_discovery": ("smb", "os-discovery"),
    # --- DHCP ---
    "dhcp.passive_monitor": ("dhcp", "passive-dhcp"),
    "dhcp.fingerprint": ("dhcp", "fingerprint"),
    "dhcp.rogue_detection": ("dhcp", "rogue-detect"),
    # --- IPv6 ---
    "ipv6.neighbor_discovery": ("ipv6", "nd-scan"),
    "ipv6.router_advertisement_scan": ("ipv6", "ra-scan"),
    "ipv6.passive_ndp": ("ipv6", "passive-ndp"),
    # --- ICMP ---
    "icmp.echo_sweep": ("icmp", "echo-sweep"),
    "icmp.os_fingerprint": ("icmp", "icmp-os-fp"),
}


@app.route('/api/nip/brain/execute', methods=['POST'])
def nip_brain_execute():
    """Execute a single Brain-planned technique. Maps technique_id to coursework module/action."""
    data = request.json or {}
    technique_id = str(data.get("technique_id", "")).strip()
    target = str(data.get("target", "")).strip()

    if not technique_id:
        return jsonify({"error": "technique_id required"}), 400

    mapping = _TECHNIQUE_TO_ACTION.get(technique_id)
    if not mapping:
        return jsonify({"error": f"Unknown technique: {technique_id}", "technique_id": technique_id}), 400

    module, action = mapping
    params = {}
    if target:
        params["target"] = target
        params["ip"] = target
        params["host"] = target
        params["hosts"] = target
        params["new_ip"] = target
    params["network"] = scanner.network_cidr
    # Default ports for port-scanning techniques
    params["ports"] = data.get("ports", "21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,8080,8443")
    # Short duration for passive/sniffing techniques so they don't block the loop
    params["duration"] = str(data.get("duration", 30))

    job_id = coursework_jobs.start(module, action, params)
    job = datastore.get_coursework_job(job_id) or {"job_id": job_id, "status": "queued"}
    return jsonify({"ok": True, "job_id": job_id, "technique_id": technique_id, "module": module, "action": action, "job": job}), 202


# ---------------------------------------------------------------------------
# NIP Phase 5 enhancements — persist risk scores + community into graph
# ---------------------------------------------------------------------------

@app.route('/api/nip/analysis/risk-persist', methods=['POST'])
def nip_risk_persist():
    """Run risk scoring and persist scores as device metadata."""
    from analysis.analysis_engine import risk_score_devices
    assets = datastore.list_assets(limit=5000)
    services = datastore.list_services(limit=10000)
    flows = datastore.list_flows(limit=10000)
    alerts = datastore.list_alerts(limit=1000)
    threat_matches = []
    with datastore.lock, datastore._connect() as conn:
        tm_rows = conn.execute("SELECT * FROM alerts WHERE alert_type='threat_match' ORDER BY id DESC LIMIT 500").fetchall()
        threat_matches = [dict(r) for r in tm_rows]

    result = risk_score_devices(assets=assets, services=services, flows=flows, alerts=alerts, threat_matches=threat_matches)
    # Persist risk_score into asset metadata.
    for dr in (result.get("device_risk") or []):
        ip = str(dr.get("ip", ""))
        score = dr.get("score", 0.0)
        if not ip:
            continue
        try:
            with datastore.lock, datastore._connect() as conn:
                row = conn.execute("SELECT metadata_json FROM assets WHERE ip=?", (ip,)).fetchone()
                meta = {}
                if row:
                    try:
                        meta = json.loads(row["metadata_json"] or "{}")
                    except Exception:
                        meta = {}
                meta["risk_score"] = score
                meta["risk_factors"] = dr.get("factors", {})
                meta["risk_recommendation"] = dr.get("recommendation", "")
                conn.execute("UPDATE assets SET metadata_json=? WHERE ip=?", (json.dumps(meta), ip))
        except Exception:
            pass
    return jsonify(result)


@app.route('/api/nip/analysis/community-persist', methods=['POST'])
def nip_community_persist():
    """Run community detection and persist cluster IDs into device metadata."""
    from analysis.analysis_engine import community_detect_label_propagation
    flows = datastore.list_flows(limit=20000)
    result = community_detect_label_propagation(flows)
    for cluster in (result.get("clusters") or []):
        cid = cluster.get("cluster_id", "")
        for ip in (cluster.get("members") or []):
            try:
                with datastore.lock, datastore._connect() as conn:
                    row = conn.execute("SELECT metadata_json FROM assets WHERE ip=?", (ip,)).fetchone()
                    meta = {}
                    if row:
                        try:
                            meta = json.loads(row["metadata_json"] or "{}")
                        except Exception:
                            meta = {}
                    meta["community"] = cid
                    conn.execute("UPDATE assets SET metadata_json=? WHERE ip=?", (json.dumps(meta), ip))
            except Exception:
                pass
    return jsonify(result)


# ---------------------------------------------------------------------------
# NIP Phase 6.3 — Natural Language Query (keyword-based)
# ---------------------------------------------------------------------------

@app.route('/api/nip/query', methods=['POST'])
def nip_nl_query():
    """Natural-language-style query endpoint (keyword-based graph query translator)."""
    data = request.json or {}
    q = str(data.get("query", data.get("q", "")) or "").strip().lower()
    if not q:
        return jsonify({"error": "query_required"}), 400

    results = []
    explanation = ""

    if any(kw in q for kw in ("most data", "top talker", "most traffic", "highest traffic")):
        explanation = "Querying top talkers by byte count."
        with datastore.lock, datastore._connect() as conn:
            rows = conn.execute(
                "SELECT src_ip, SUM(byte_count) as total_bytes FROM flows GROUP BY src_ip ORDER BY total_bytes DESC LIMIT 20"
            ).fetchall()
        results = [{"ip": r["src_ip"], "total_bytes": r["total_bytes"]} for r in rows]

    elif any(kw in q for kw in ("everything", "all activity", "what did")) and re.search(r"\d+\.\d+\.\d+\.\d+", q):
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", q)
        ip = ip_match.group(1) if ip_match else ""
        explanation = f"Querying all activity for {ip}."
        with datastore.lock, datastore._connect() as conn:
            flow_rows = conn.execute("SELECT * FROM flows WHERE src_ip=? OR dst_ip=? ORDER BY last_seen DESC LIMIT 200", (ip, ip)).fetchall()
            dns_rows = conn.execute("SELECT * FROM dns_queries WHERE src_ip=? ORDER BY timestamp DESC LIMIT 100", (ip,)).fetchall()
            alert_rows = conn.execute("SELECT * FROM alerts WHERE src_ip=? OR dst_ip=? ORDER BY timestamp DESC LIMIT 50", (ip, ip)).fetchall()
        results = {"flows": [dict(r) for r in flow_rows], "dns": [dict(r) for r in dns_rows], "alerts": [dict(r) for r in alert_rows]}

    elif any(kw in q for kw in ("malicious", "threat", "known bad", "malware", "c2")):
        explanation = "Querying threat indicator matches."
        with datastore.lock, datastore._connect() as conn:
            rows = conn.execute("SELECT * FROM alerts WHERE alert_type='threat_match' ORDER BY timestamp DESC LIMIT 50").fetchall()
        results = [dict(r) for r in rows]

    elif any(kw in q for kw in ("changed", "new device", "what changed", "diff")):
        explanation = "Querying recently added assets (last 24h)."
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        with datastore.lock, datastore._connect() as conn:
            rows = conn.execute("SELECT * FROM assets WHERE first_seen > ? ORDER BY first_seen DESC", (cutoff,)).fetchall()
        results = [dict(r) for r in rows]

    elif any(kw in q for kw in ("risk", "risky", "dangerous", "vulnerable")):
        explanation = "Querying devices with highest risk scores."
        with datastore.lock, datastore._connect() as conn:
            rows = conn.execute("SELECT ip, metadata_json FROM assets").fetchall()
        scored = []
        for r in rows:
            try:
                meta = json.loads(r["metadata_json"] or "{}")
                score = meta.get("risk_score")
                if score is not None:
                    scored.append({"ip": r["ip"], "risk_score": score, "recommendation": meta.get("risk_recommendation", "")})
            except Exception:
                pass
        scored.sort(key=lambda x: -x.get("risk_score", 0))
        results = scored[:20]

    elif any(kw in q for kw in ("dns", "domain", "query", "resolve")):
        explanation = "Querying top DNS domains."
        with datastore.lock, datastore._connect() as conn:
            rows = conn.execute("SELECT domain, COUNT(*) as cnt FROM dns_queries GROUP BY domain ORDER BY cnt DESC LIMIT 30").fetchall()
        results = [{"domain": r["domain"], "count": r["cnt"]} for r in rows]

    elif any(kw in q for kw in ("port", "service", "open")):
        explanation = "Querying open services."
        with datastore.lock, datastore._connect() as conn:
            rows = conn.execute("SELECT ip, port, protocol, service, banner FROM services ORDER BY port LIMIT 200").fetchall()
        results = [dict(r) for r in rows]

    else:
        explanation = "General search across observations."
        with datastore.lock, datastore._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM observations WHERE summary LIKE ? OR entity LIKE ? ORDER BY timestamp DESC LIMIT 50",
                (f"%{q}%", f"%{q}%"),
            ).fetchall()
        results = [dict(r) for r in rows]

    return jsonify({"query": q, "explanation": explanation, "results": results})


# ---------------------------------------------------------------------------
# NIP Phase 6.4 — Report Generation
# ---------------------------------------------------------------------------

@app.route('/api/nip/report/generate', methods=['POST'])
def nip_generate_report():
    """Generate an intelligence report covering current network state."""
    from analysis.analysis_engine import risk_score_devices, community_detect_label_propagation

    assets = datastore.list_assets(limit=5000)
    services = datastore.list_services(limit=10000)
    flows = datastore.list_flows(limit=10000)
    alerts = datastore.list_alerts(limit=1000)
    observations = datastore.get_recent_observations(limit=500)

    # Risk
    threat_matches = []
    with datastore.lock, datastore._connect() as conn:
        tm_rows = conn.execute("SELECT * FROM alerts WHERE alert_type='threat_match' ORDER BY id DESC LIMIT 500").fetchall()
        threat_matches = [dict(r) for r in tm_rows]
    risk_result = risk_score_devices(assets=assets, services=services, flows=flows, alerts=alerts, threat_matches=threat_matches)

    # Community
    community_result = community_detect_label_propagation(flows)

    # Brain situation
    baselines = datastore.list_nip_baselines(limit=5000)
    situation = nip_brain_assessor.assess(assets=assets, services=services, baselines=baselines, alerts=alerts)

    # Anomalies
    anomaly_alerts = [a for a in alerts if a.get("alert_type") == "behavior_anomaly"]
    threat_alerts = [a for a in alerts if a.get("alert_type") == "threat_match"]

    # Build report
    now = datetime.now()
    report = {
        "generated_at": now.isoformat(),
        "title": f"NIP Intelligence Report — {now.strftime('%Y-%m-%d %H:%M')}",
        "sections": {
            "network_overview": {
                "total_devices": len(assets),
                "total_services": len(services),
                "total_flows": len(flows),
                "knowledge_coverage_pct": situation.overall_coverage_pct,
                "stale_devices": len(situation.stale_devices),
            },
            "risk_summary": {
                "device_count": len(risk_result.get("device_risk", [])),
                "top_risk": (risk_result.get("device_risk") or [])[:5],
                "threat_alerts": len(threat_alerts),
                "anomaly_alerts": len(anomaly_alerts),
            },
            "traffic_summary": {
                "communities": len(community_result.get("clusters", [])),
                "top_communities": (community_result.get("clusters") or [])[:5],
            },
            "knowledge_gaps": situation.knowledge_gaps,
            "recommendations": [],
        },
    }

    # Generate recommendations.
    recs = report["sections"]["recommendations"]
    if situation.overall_coverage_pct < 50:
        recs.append("Run discovery scans to increase network coverage.")
    if situation.stale_devices:
        recs.append(f"Refresh {len(situation.stale_devices)} stale devices.")
    if situation.unresolved_alerts > 0:
        recs.append(f"Investigate {situation.unresolved_alerts} unresolved alerts.")
    gaps = situation.knowledge_gaps
    if gaps.get("has_os", 0) > len(assets) * 0.5:
        recs.append("Run OS fingerprinting on discovered devices.")
    if gaps.get("risk_assessed", 0) > 0:
        recs.append(f"Run risk assessment on {gaps.get('risk_assessed', 0)} unscored devices.")

    # Build markdown
    md_lines = [f"# {report['title']}", "", f"Generated: {report['generated_at']}", ""]
    md_lines += ["## Network Overview", ""]
    ov = report["sections"]["network_overview"]
    md_lines += [f"- Devices: {ov['total_devices']}", f"- Services: {ov['total_services']}", f"- Flows: {ov['total_flows']}", f"- Coverage: {ov['knowledge_coverage_pct']}%", f"- Stale: {ov['stale_devices']}", ""]
    md_lines += ["## Risk Summary", ""]
    rs = report["sections"]["risk_summary"]
    md_lines += [f"- Threat alerts: {rs['threat_alerts']}", f"- Anomaly alerts: {rs['anomaly_alerts']}", ""]
    if rs.get("top_risk"):
        md_lines += ["### Top Risk Devices", ""]
        for d in rs["top_risk"]:
            md_lines.append(f"- **{d.get('ip', '?')}**: score={d.get('score', 0):.2f} ({d.get('recommendation', '')})")
        md_lines.append("")
    md_lines += ["## Recommendations", ""]
    for r in recs:
        md_lines.append(f"- {r}")

    report["markdown"] = "\n".join(md_lines)

    # Save report.
    report_dir = Path(__file__).resolve().parent / "report"
    report_dir.mkdir(exist_ok=True)
    ts_slug = now.strftime("%Y%m%d_%H%M%S")
    (report_dir / f"nip_report_{ts_slug}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (report_dir / f"nip_report_{ts_slug}.md").write_text(report["markdown"], encoding="utf-8")

    return jsonify(report)


# ---------------------------------------------------------------------------
# NIP Phase 7.3 — Quality Metrics
# ---------------------------------------------------------------------------

@app.route('/api/nip/quality', methods=['GET'])
def nip_quality_metrics():
    """Compute and return intelligence quality metrics."""
    assets = datastore.list_assets(limit=5000)
    services = datastore.list_services(limit=10000)
    alerts = datastore.list_alerts(limit=1000)

    # Get risk scores from metadata.
    device_scores = []
    for a in assets:
        try:
            meta = json.loads(a.get("metadata_json") or "{}")
            score = meta.get("risk_score")
            if score is not None:
                device_scores.append({"ip": a["ip"], "score": score})
        except Exception:
            pass

    ground_truth_ips = None
    gt_param = str(request.args.get("ground_truth", "") or "").strip()
    if gt_param:
        ground_truth_ips = [ip.strip() for ip in gt_param.split(",") if ip.strip()]

    metrics = compute_quality_metrics(assets=assets, services=services, alerts=alerts, device_scores=device_scores, ground_truth_ips=ground_truth_ips)

    # Persist snapshot.
    try:
        with datastore.lock, datastore._connect() as conn:
            conn.execute("INSERT INTO quality_snapshots (generated_at, metrics_json) VALUES (?,?)", (datetime.now().isoformat(), json.dumps(metrics)))
    except Exception:
        pass

    return jsonify(metrics)


# ---------------------------------------------------------------------------
# NIP Phase 1.1 — Subnet + DNSRecord + ThreatIndicator population helpers
# ---------------------------------------------------------------------------

def _nip_populate_subnets():
    """Derive subnets from known assets and persist."""
    import ipaddress as _ipaddr
    assets = datastore.list_assets(limit=5000)
    subnet_counts = {}
    gw = getattr(scanner, "gateway_ip", "")
    cidr = getattr(scanner, "network_cidr", "")
    if cidr:
        try:
            net = _ipaddr.ip_network(cidr, strict=False)
            subnet_counts[str(net)] = {"gateway": gw, "count": 0}
        except Exception:
            pass
    for a in assets:
        try:
            ip = _ipaddr.ip_address(a["ip"])
            net24 = _ipaddr.ip_network(f"{a['ip']}/24", strict=False)
            key = str(net24)
            if key not in subnet_counts:
                subnet_counts[key] = {"gateway": "", "count": 0}
            subnet_counts[key]["count"] += 1
        except Exception:
            pass
    now = datetime.now().isoformat()
    with datastore.lock, datastore._connect() as conn:
        for cidr_str, info in subnet_counts.items():
            conn.execute(
                """INSERT INTO subnets (cidr, gateway, device_count, first_seen, last_seen)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(cidr) DO UPDATE SET device_count=excluded.device_count, last_seen=excluded.last_seen, gateway=COALESCE(NULLIF(excluded.gateway,''), subnets.gateway)""",
                (cidr_str, info["gateway"], info["count"], now, now),
            )


def _nip_populate_dns_records():
    """Derive DNSRecord nodes from dns_queries table."""
    now = datetime.now().isoformat()
    with datastore.lock, datastore._connect() as conn:
        rows = conn.execute(
            "SELECT domain, query_type, resolved_ip, COUNT(*) as cnt, MIN(timestamp) as fs, MAX(timestamp) as ls FROM dns_queries GROUP BY domain, query_type LIMIT 5000"
        ).fetchall()
        for r in rows:
            conn.execute(
                """INSERT INTO dns_records (domain, record_type, value, first_seen, last_seen, query_count)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT DO NOTHING""",
                (r["domain"], r["query_type"] or "A", r["resolved_ip"] or "", r["fs"] or now, r["ls"] or now, r["cnt"]),
            )


def _nip_populate_threat_indicators():
    """Populate ThreatIndicator nodes from the threat feed file."""
    feed_path = Path(NIP_THREAT_FEED_PATH)
    if not feed_path.exists():
        return
    try:
        data = json.loads(feed_path.read_text(encoding="utf-8"))
        indicators = data.get("indicators") or []
    except Exception:
        return
    now = datetime.now().isoformat()
    with datastore.lock, datastore._connect() as conn:
        for ind in indicators:
            if not isinstance(ind, dict):
                continue
            itype = str(ind.get("type") or "").strip()
            val = str(ind.get("value") or "").strip()
            src = str(ind.get("source") or "local_feed")
            conf = float(ind.get("confidence", 0.5))
            if not itype or not val:
                continue
            conn.execute(
                """INSERT INTO threat_indicators (indicator_type, value, source, confidence, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?)""",
                (itype, val, src, conf, now, now),
            )


@app.route('/api/nip/graph/populate', methods=['POST'])
def nip_graph_populate():
    """Populate extended graph nodes (subnets, DNS records, threat indicators) from current data."""
    _nip_populate_subnets()
    _nip_populate_dns_records()
    _nip_populate_threat_indicators()
    return jsonify({"ok": True, "message": "Graph population complete."})


def get_network_diagnosis_internal():
    """Internal function to get network diagnosis"""
    diagnosis = {
        'local_ip': scanner.local_ip,
        'gateway_ip': scanner.gateway_ip,
        'network': scanner.network_cidr,
        'vpn_detected': False,
        'can_arp_scan': True,
        'network_type': 'lan',
        'issues': []
    }
    
    # Check for VPN by IP range
    if scanner.local_ip:
        if scanner.local_ip.startswith('100.64.') or scanner.local_ip.startswith('100.100.'):
            diagnosis['vpn_detected'] = True
            diagnosis['can_arp_scan'] = False
            diagnosis['network_type'] = 'vpn_cgnat'
            diagnosis['issues'].append('CGNAT/VPN range detected (100.64.x.x)')
        elif scanner.local_ip.startswith('10.') and scanner.gateway_ip:
            # Check if gateway is on different subnet
            local_parts = scanner.local_ip.split('.')[:3]
            gateway_parts = scanner.gateway_ip.split('.')[:3]
            if local_parts != gateway_parts:
                diagnosis['can_arp_scan'] = False
                diagnosis['network_type'] = 'routed'
                diagnosis['issues'].append('Gateway on different subnet')
    
    # Check for tunnel interfaces
    try:
        result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        utun_count = result.stdout.count('utun')
        if utun_count > 2:
            diagnosis['vpn_detected'] = True
            diagnosis['issues'].append(f'{utun_count} tunnel interfaces detected')
    except:
        pass
    
    # Check for identical MACs (VPN indicator)
    mac_counts = {}
    for device in scanner.devices.values():
        if device.mac:
            mac_counts[device.mac] = mac_counts.get(device.mac, 0) + 1
    
    for mac, count in mac_counts.items():
        if count > 5:
            diagnosis['vpn_detected'] = True
            diagnosis['can_arp_scan'] = False
            if mac.upper().startswith('DE:AD'):
                diagnosis['network_type'] = 'vpn_mesh'
                diagnosis['issues'].append(f'Virtual MAC detected ({mac[:8]}...)')
            break
    
    return diagnosis


# Port to service name mapping
SERVICE_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
}


@app.route('/api/device/<ip>/enrich', methods=['POST'])
def enrich_device(ip):
    """Deep scan and enrich a specific device"""
    if ip not in scanner.devices:
        return jsonify({'error': 'Device not found'}), 404
    
    device = scanner.devices[ip]
    
    # Get MAC vendor
    if not device.vendor:
        device.vendor = lookup_mac_vendor(device.mac)
    
    # Try hostname resolution
    if not device.hostname:
        device.hostname = resolve_hostname_multi(ip)
    
    # Scan common ports
    scanner.scan_ports(ip, banner_grab=True)
    
    # Guess device type
    device.os = guess_device_type(device.hostname, device.vendor, device.open_ports)
    datastore.upsert_device(device, scan_profile="enrich")
    for port in device.open_ports:
        datastore.upsert_service(
            ip,
            port,
            "tcp",
            device.services.get(port, f"Port {port}"),
            banner=device.service_banners.get(port, ""),
        )
    
    return jsonify(asdict(device))


@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Start packet capture"""
    data = request.json or {}
    interface = data.get('interface')
    filter_str = data.get('filter', '')
    
    success = analyzer.start_capture(interface, filter_str)
    if success:
        datastore.add_observation(
            "capture",
            "local",
            "Packet capture started",
            {"interface": interface or "auto", "filter": filter_str},
        )
        # Start NIP metrics/baselining alongside capture (NIP Phase 3 substrate).
        try:
            nip_metrics_daemon.start()
        except Exception:
            pass
    return jsonify({'success': success, 'capturing': analyzer.is_capturing})


@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    analyzer.stop_capture()
    try:
        nip_metrics_daemon.stop()
    except Exception:
        pass
    datastore.add_observation("capture", "local", "Packet capture stopped", {})
    return jsonify({'success': True, 'capturing': analyzer.is_capturing})


@app.route('/api/connections', methods=['GET'])
def get_connections():
    """Get all captured connections"""
    return jsonify({
        'connections': analyzer.get_connections(),
        'count': len(analyzer.connections)
    })


@app.route('/api/traffic-matrix', methods=['GET'])
def get_traffic_matrix():
    """Get traffic matrix"""
    return jsonify(analyzer.get_traffic_matrix())


@app.route('/api/dns', methods=['GET'])
def get_dns_queries():
    """Get captured DNS queries"""
    with analyzer.lock:
        # Group by IP
        by_ip = {}
        for q in analyzer.dns_queries:
            if q.src_ip not in by_ip:
                by_ip[q.src_ip] = []
            by_ip[q.src_ip].append({
                'domain': q.domain,
                'type': q.query_type,
                'timestamp': q.timestamp
            })
        
        # Also get top domains
        domain_counts = {}
        for q in analyzer.dns_queries:
            domain_counts[q.domain] = domain_counts.get(q.domain, 0) + 1
        top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:20]
        
        return jsonify({
            'queries_by_ip': by_ip,
            'top_domains': top_domains,
            'total_queries': len(analyzer.dns_queries)
        })


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get security alerts"""
    with analyzer.lock:
        return jsonify({
            'alerts': [asdict(a) for a in analyzer.alerts],
            'count': len(analyzer.alerts)
        })


@app.route('/api/bandwidth/<ip>', methods=['GET'])
def get_bandwidth(ip):
    """Get bandwidth history for an IP"""
    with analyzer.lock:
        history = analyzer.bandwidth_history.get(ip, [])
        
        # Aggregate by second
        aggregated = {}
        for entry in history:
            ts = entry['timestamp'][:19]  # Truncate to second
            if ts not in aggregated:
                aggregated[ts] = 0
            aggregated[ts] += entry['bytes']
        
        # Convert to list sorted by time
        result = [{'timestamp': k, 'bytes': v} for k, v in sorted(aggregated.items())]
        
        return jsonify({
            'ip': ip,
            'history': result[-60:],  # Last 60 seconds
            'total_bytes': sum(e['bytes'] for e in history)
        })


@app.route('/api/stats', methods=['GET'])
def get_network_stats():
    """Get comprehensive network statistics"""
    with analyzer.lock:
        # Calculate stats
        total_bytes = sum(c.byte_count for c in analyzer.connections.values())
        total_packets = sum(c.packet_count for c in analyzer.connections.values())
        
        # Protocol breakdown
        protocols = {}
        for c in analyzer.connections.values():
            protocols[c.protocol] = protocols.get(c.protocol, 0) + c.byte_count
        
        # Application breakdown
        applications = {}
        for c in analyzer.connections.values():
            app = c.application or "Unknown"
            applications[app] = applications.get(app, 0) + c.byte_count
        
        # Top talkers (by bytes)
        ip_bytes = {}
        for c in analyzer.connections.values():
            ip_bytes[c.src_ip] = ip_bytes.get(c.src_ip, 0) + c.byte_count
            ip_bytes[c.dst_ip] = ip_bytes.get(c.dst_ip, 0) + c.byte_count
        top_talkers = sorted(ip_bytes.items(), key=lambda x: -x[1])[:10]
        
        # External vs internal traffic
        internal_bytes = 0
        external_bytes = 0
        for c in analyzer.connections.values():
            is_internal = (
                (c.src_ip.startswith('192.168.') or c.src_ip.startswith('10.')) and
                (c.dst_ip.startswith('192.168.') or c.dst_ip.startswith('10.'))
            )
            if is_internal:
                internal_bytes += c.byte_count
            else:
                external_bytes += c.byte_count
        
        # Enrich top talkers with IP info
        enriched_talkers = []
        for ip, bytes_count in top_talkers:
            info = lookup_ip_info(ip)
            # Check if it's a known device
            device = scanner.devices.get(ip)
            enriched_talkers.append({
                'ip': ip,
                'bytes': bytes_count,
                'hostname': device.hostname if device else '',
                'service': info.get('service', ''),
                'country': info.get('country', ''),
                'city': info.get('city', ''),
                'org': info.get('org', ''),
                'is_local': device is not None
            })

        risky_ports = {21, 23, 445, 3389, 5900, 6379, 9200, 27017}
        risky_exposures = 0
        for d in scanner.devices.values():
            risky_exposures += len([p for p in d.open_ports if p in risky_ports])
        
        return jsonify({
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'captured_packets_total': analyzer.total_packets,
            'captured_bytes_total': analyzer.total_bytes,
            'connection_count': len(analyzer.connections),
            'device_count': len(scanner.devices),
            'protocols': protocols,
            'applications': dict(sorted(applications.items(), key=lambda x: -x[1])[:15]),
            'top_talkers': enriched_talkers,
            'internal_traffic': internal_bytes,
            'external_traffic': external_bytes,
            'alert_count': len(analyzer.alerts),
            'dns_query_count': len(analyzer.dns_queries),
            'high_risk_service_exposures': risky_exposures,
        })


# WebSocket events for real-time updates
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('status', {
        'connected': True,
        'capturing': analyzer.is_capturing
    })


@socketio.on('subscribe_packets')
def handle_subscribe():
    """Subscribe to real-time packet updates"""
    def send_packets():
        while True:
            packets = analyzer.get_recent_packets()
            if packets:
                socketio.emit('packets', packets)
            time.sleep(0.5)
    
    thread = threading.Thread(target=send_packets, daemon=True)
    thread.start()


# Demo mode - generate sample data for testing without root
def generate_demo_data():
    """Generate demo network data for testing"""
    now = datetime.now().isoformat()
    
    demo_devices = [
        Device(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:01", hostname="router.local",
               vendor="Cisco", is_gateway=True, first_seen=now, last_seen=now,
               open_ports=[80, 443, 22], services={80: "HTTP", 443: "HTTPS", 22: "SSH"}),
        Device(ip="192.168.1.10", mac="AA:BB:CC:DD:EE:10", hostname="workstation-1",
               vendor="Dell", is_local=True, first_seen=now, last_seen=now,
               open_ports=[22, 3389], services={22: "SSH", 3389: "RDP"}),
        Device(ip="192.168.1.20", mac="AA:BB:CC:DD:EE:20", hostname="server-web",
               vendor="HP", first_seen=now, last_seen=now,
               open_ports=[80, 443, 22, 3306], services={80: "HTTP", 443: "HTTPS", 22: "SSH", 3306: "MySQL"}),
        Device(ip="192.168.1.30", mac="AA:BB:CC:DD:EE:30", hostname="nas-storage",
               vendor="Synology", first_seen=now, last_seen=now,
               open_ports=[22, 139, 445, 5000], services={22: "SSH", 139: "NetBIOS", 445: "SMB", 5000: "HTTP"}),
        Device(ip="192.168.1.40", mac="AA:BB:CC:DD:EE:40", hostname="printer-office",
               vendor="HP", first_seen=now, last_seen=now,
               open_ports=[80, 443, 9100], services={80: "HTTP", 443: "HTTPS", 9100: "RAW-Print"}),
        Device(ip="192.168.1.50", mac="AA:BB:CC:DD:EE:50", hostname="iot-camera",
               vendor="Hikvision", first_seen=now, last_seen=now,
               open_ports=[80, 554, 8000], services={80: "HTTP", 554: "RTSP", 8000: "SDK"}),
        Device(ip="192.168.1.60", mac="AA:BB:CC:DD:EE:60", hostname="smart-tv",
               vendor="Samsung", first_seen=now, last_seen=now,
               open_ports=[8001, 8002], services={8001: "WS-API", 8002: "HTTPS-API"}),
        Device(ip="192.168.1.100", mac="AA:BB:CC:DD:EE:A0", hostname="laptop-alice",
               vendor="Apple", first_seen=now, last_seen=now,
               open_ports=[], services={}),
        Device(ip="192.168.1.101", mac="AA:BB:CC:DD:EE:A1", hostname="phone-bob",
               vendor="Samsung", first_seen=now, last_seen=now,
               open_ports=[], services={}),
    ]
    
    for device in demo_devices:
        scanner.devices[device.ip] = device
        datastore.upsert_device(device, scan_profile="demo")
        for port in device.open_ports:
            datastore.upsert_service(device.ip, port, "tcp", device.services.get(port, f"Port {port}"))
    
    # Demo connections
    demo_connections = [
        Connection(src_ip="192.168.1.10", dst_ip="192.168.1.1", protocol="TCP",
                  src_port=52341, dst_port=443, packet_count=1500, byte_count=2500000, last_seen=now),
        Connection(src_ip="192.168.1.10", dst_ip="192.168.1.20", protocol="TCP",
                  src_port=52342, dst_port=80, packet_count=800, byte_count=450000, last_seen=now),
        Connection(src_ip="192.168.1.10", dst_ip="192.168.1.30", protocol="TCP",
                  src_port=52343, dst_port=445, packet_count=2000, byte_count=15000000, last_seen=now),
        Connection(src_ip="192.168.1.100", dst_ip="192.168.1.1", protocol="TCP",
                  src_port=52344, dst_port=443, packet_count=3000, byte_count=8000000, last_seen=now),
        Connection(src_ip="192.168.1.100", dst_ip="192.168.1.20", protocol="TCP",
                  src_port=52345, dst_port=443, packet_count=500, byte_count=120000, last_seen=now),
        Connection(src_ip="192.168.1.101", dst_ip="192.168.1.1", protocol="TCP",
                  src_port=52346, dst_port=443, packet_count=1200, byte_count=3500000, last_seen=now),
        Connection(src_ip="192.168.1.60", dst_ip="192.168.1.1", protocol="TCP",
                  src_port=52347, dst_port=443, packet_count=5000, byte_count=25000000, last_seen=now),
        Connection(src_ip="192.168.1.50", dst_ip="192.168.1.30", protocol="TCP",
                  src_port=52348, dst_port=445, packet_count=10000, byte_count=500000000, last_seen=now),
        Connection(src_ip="192.168.1.20", dst_ip="192.168.1.30", protocol="TCP",
                  src_port=52349, dst_port=3306, packet_count=400, byte_count=80000, last_seen=now),
        Connection(src_ip="192.168.1.40", dst_ip="192.168.1.10", protocol="TCP",
                  src_port=52350, dst_port=9100, packet_count=50, byte_count=250000, last_seen=now),
    ]
    
    for conn in demo_connections:
        key = f"{conn.src_ip}:{conn.src_port}-{conn.dst_ip}:{conn.dst_port}-{conn.protocol}"
        analyzer.connections[key] = conn
        datastore.upsert_flow(key, conn)


@app.route('/api/demo/load', methods=['POST'])
def load_demo_data():
    """Load demo data for testing"""
    generate_demo_data()
    return jsonify({
        'success': True,
        'devices': len(scanner.devices),
        'connections': len(analyzer.connections)
    })


@app.route('/api/clear', methods=['POST'])
def clear_data():
    """Clear all discovered devices and connections"""
    data = request.json or {}
    include_history = bool(data.get('include_history', False))
    include_assets = bool(data.get('include_assets', False))

    scanner.devices.clear()
    analyzer.connections.clear()
    analyzer.packet_buffer.clear()
    analyzer.dns_queries.clear()
    analyzer.alerts.clear()
    analyzer.bandwidth_history.clear()
    analyzer.total_packets = 0
    analyzer.total_bytes = 0
    analyzer._last_flow_persist.clear()

    if include_history:
        datastore.clear(include_assets=include_assets)

    return jsonify({
        'success': True,
        'message': 'All data cleared',
        'history_cleared': include_history,
        'assets_cleared': include_assets and include_history,
    })


@app.route('/api/capture/mode', methods=['POST'])
def set_capture_mode():
    """Set capture mode - normal or promiscuous with ARP spoofing"""
    data = request.json or {}
    mode = data.get('mode', 'normal')
    
    if mode == 'mitm':
        # WARNING: This enables ARP spoofing to see all network traffic
        # Only use on networks you own!
        return jsonify({
            'success': False,
            'message': 'MITM mode requires manual setup. Run: sudo python mitm_capture.py',
            'warning': 'Only use on networks you own and control!'
        })
    
    return jsonify({'success': True, 'mode': mode})


@app.route('/api/ip/<ip>', methods=['GET'])
def get_ip_info(ip):
    """Get detailed information about an IP address"""
    info = lookup_ip_info(ip)
    return jsonify(info)


@app.route('/api/ip/batch', methods=['POST'])
def get_ip_info_batch():
    """Get information about multiple IPs"""
    data = request.json or {}
    ips = data.get('ips', [])
    results = {}
    for ip in ips[:20]:  # Limit to 20 to avoid rate limiting
        results[ip] = lookup_ip_info(ip)
    return jsonify(results)


@app.route('/api/network/info', methods=['GET'])
def get_network_info():
    """Get detailed network information including capture limitations"""
    return jsonify({
        'local_ip': scanner.local_ip,
        'gateway_ip': scanner.gateway_ip,
        'network': scanner.network_cidr,
        'capture_limitations': {
            'message': 'On switched networks, you can only see traffic to/from this device',
            'visible_traffic': [
                'Traffic to/from this computer',
                'Broadcast traffic (ARP, DHCP)',
                'Multicast traffic (mDNS, SSDP, UPnP)'
            ],
            'invisible_traffic': [
                'Traffic between other devices',
                'Other devices internet traffic'
            ],
            'solutions': [
                'Enable port mirroring on router',
                'Use router built-in traffic monitoring',
                'Set up ARP spoofing (only on your own network)'
            ]
        }
    })


@app.route('/api/network/diagnose', methods=['GET'])
def diagnose_network():
    """Diagnose network configuration and provide detailed info"""
    import subprocess
    
    diagnosis = {
        'local_ip': scanner.local_ip,
        'gateway_ip': scanner.gateway_ip,
        'network': scanner.network_cidr,
        'network_type': 'unknown',
        'can_arp_scan': True,
        'issues': [],
        'recommendations': [],
        'interfaces': [],
        'public_ip': None,
        'dns_servers': [],
        'vpn_detected': False
    }
    
    # Check if on same subnet as gateway
    local_parts = scanner.local_ip.split('.') if scanner.local_ip else []
    gateway_parts = scanner.gateway_ip.split('.') if scanner.gateway_ip else []
    
    if len(local_parts) == 4 and len(gateway_parts) == 4:
        # Check /24 subnet match
        if local_parts[:3] != gateway_parts[:3]:
            diagnosis['can_arp_scan'] = False
            diagnosis['issues'].append(f"Gateway ({scanner.gateway_ip}) is on different subnet than you ({scanner.local_ip})")
            diagnosis['recommendations'].append("ARP scanning won't find devices across subnets")
    
    # Detect network type
    if scanner.local_ip:
        if scanner.local_ip.startswith('192.168.'):
            diagnosis['network_type'] = 'home'
        elif scanner.local_ip.startswith('10.'):
            diagnosis['network_type'] = 'vpn_or_enterprise'
            diagnosis['recommendations'].append("This looks like a VPN or enterprise network")
        elif scanner.local_ip.startswith('172.'):
            octets = int(scanner.local_ip.split('.')[1])
            if 16 <= octets <= 31:
                diagnosis['network_type'] = 'corporate'
    
    # Check for VPN interfaces
    try:
        result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        interfaces = result.stdout
        
        # Count active utun interfaces (VPN tunnels)
        utun_count = interfaces.count('utun')
        if utun_count > 2:  # More than default
            diagnosis['vpn_detected'] = True
            diagnosis['issues'].append(f"VPN detected ({utun_count} tunnel interfaces)")
    except:
        pass
    
    # Check for Tailscale-style network (100.64.x.x CGNAT range)
    try:
        if diagnosis['local_ip'] and diagnosis['local_ip'].startswith('100.64.'):
            diagnosis['vpn_detected'] = True
            diagnosis['network_type'] = 'tailscale'
            diagnosis['issues'].append("Tailscale/CGNAT network detected (100.64.x.x range)")
            diagnosis['recommendations'].append("This is a mesh VPN - device MACs are virtualized")
    except:
        pass
    
    # Check if devices have identical MACs (VPN indicator)
    try:
        mac_counts = {}
        for device in scanner.devices.values():
            if device.mac:
                mac_counts[device.mac] = mac_counts.get(device.mac, 0) + 1
        
        # If any MAC has >5 devices, likely VPN
        for mac, count in mac_counts.items():
            if count > 5:
                diagnosis['vpn_detected'] = True
                diagnosis['issues'].append(f"Multiple devices ({count}) share MAC {mac[:8]}... (virtual network)")
                if mac.upper().startswith('DE:AD'):
                    diagnosis['network_type'] = 'tailscale'
                    diagnosis['recommendations'].append("DE:AD MAC = Tailscale virtual interface")
                break
        
        # Get active network interfaces
        active_ifs = []
        for line in interfaces.split('\n'):
            if ': flags=' in line and 'RUNNING' in line:
                if_name = line.split(':')[0]
                if not if_name.startswith(('lo', 'gif', 'stf', 'utun', 'awdl', 'llw', 'bridge', 'ap')):
                    active_ifs.append(if_name)
        diagnosis['interfaces'] = active_ifs
    except:
        pass
    
    # Try to get public IP
    try:
        url = "https://api.ipify.org?format=json"
        req = urllib.request.Request(url, headers={'User-Agent': 'NetVis/1.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            diagnosis['public_ip'] = data.get('ip')
    except:
        pass
    
    # Try to get DNS servers
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns = line.split()[1]
                    diagnosis['dns_servers'].append(dns)
    except:
        pass
    
    # Try traceroute to gateway to check hops
    try:
        result = subprocess.run(['traceroute', '-n', '-m', '3', scanner.gateway_ip], 
                              capture_output=True, text=True, timeout=10)
        hops = result.stdout.count('\n') - 1
        if hops > 1:
            diagnosis['issues'].append(f"Gateway is {hops} hops away - may indicate VPN/NAT")
    except:
        pass
    
    # Summary and recommendations
    if diagnosis['network_type'] == 'vpn_or_enterprise':
        diagnosis['recommendations'].extend([
            "This is likely a VPN or enterprise network",
            "Device discovery may be limited due to network isolation",
            "Try disconnecting from VPN to scan your local network",
            "Traffic capture will still work for YOUR connections"
        ])
    
    if not diagnosis['can_arp_scan']:
        diagnosis['recommendations'].extend([
            "Cannot perform ARP scan across subnets",
            "The gateway appears to be routing traffic (not a simple switch)",
            "You can still capture YOUR traffic to analyze connections"
        ])
    
    return jsonify(diagnosis)


# ============== MITM INTEGRATION ENDPOINTS ==============
# These endpoints receive data from the mitm_capture.py script
# and merge it into the visualization

mitm_active = False
mitm_last_seen = None
mitm_process = None
mitm_started_by_gui = False

@app.route('/api/mitm/status', methods=['GET'])
def get_mitm_status():
    """Get MITM capture status"""
    global mitm_active, mitm_last_seen, mitm_process, mitm_started_by_gui
    
    # Check if process is still running
    if mitm_process is not None:
        poll = mitm_process.poll()
        if poll is not None:  # Process has ended
            mitm_process = None
            mitm_started_by_gui = False
    
    # Consider MITM inactive if no data for 10 seconds
    if mitm_last_seen and (datetime.now() - mitm_last_seen).total_seconds() > 10:
        mitm_active = False
    
    return jsonify({
        'active': mitm_active,
        'running': mitm_process is not None,
        'started_by_gui': mitm_started_by_gui,
        'last_seen': mitm_last_seen.isoformat() if mitm_last_seen else None
    })


@app.route('/api/mitm/start', methods=['POST'])
def start_mitm():
    """Start MITM capture script"""
    global mitm_process, mitm_started_by_gui, mitm_active
    
    if mitm_process is not None:
        return jsonify({'success': False, 'error': 'MITM already running'}), 400
    
    try:
        import os
        script_path = os.path.join(os.path.dirname(__file__), 'mitm_capture.py')
        python_path = os.path.join(os.path.dirname(__file__), 'venv', 'bin', 'python')
        
        # Check if script exists
        if not os.path.exists(script_path):
            return jsonify({'success': False, 'error': 'MITM script not found'}), 404
        
        # Start the MITM script with sudo (requires password-less sudo or already elevated)
        # We'll run it with --gui flag to enable GUI integration
        mitm_process = subprocess.Popen(
            ['sudo', '-n', python_path, script_path, '--gui', '--auto-confirm'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True  # Detach from parent
        )
        
        mitm_started_by_gui = True
        mitm_active = True
        
        return jsonify({
            'success': True, 
            'pid': mitm_process.pid,
            'message': 'MITM capture started'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/mitm/stop', methods=['POST'])
def stop_mitm():
    """Stop MITM capture script"""
    global mitm_process, mitm_started_by_gui, mitm_active
    
    if mitm_process is None:
        # Try to kill any running mitm_capture.py processes
        try:
            subprocess.run(['sudo', '-n', 'pkill', '-f', 'mitm_capture.py'], capture_output=True)
            mitm_active = False
            return jsonify({'success': True, 'message': 'Sent kill signal to MITM processes'})
        except:
            return jsonify({'success': False, 'error': 'No MITM process to stop'}), 400
    
    try:
        # Send SIGTERM to the process group
        import signal
        os.killpg(os.getpgid(mitm_process.pid), signal.SIGTERM)
        mitm_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        # Force kill if it doesn't stop
        os.killpg(os.getpgid(mitm_process.pid), signal.SIGKILL)
    except Exception as e:
        # Try sudo kill as fallback
        subprocess.run(['sudo', '-n', 'kill', str(mitm_process.pid)], capture_output=True)
    
    mitm_process = None
    mitm_started_by_gui = False
    mitm_active = False
    
    return jsonify({'success': True, 'message': 'MITM capture stopped'})


@app.route('/api/mitm/devices', methods=['POST'])
def receive_mitm_devices():
    """Receive discovered devices from MITM script and enrich them"""
    global mitm_active, mitm_last_seen
    data = request.json or {}
    devices = data.get('devices', [])
    
    mitm_active = True
    mitm_last_seen = datetime.now()
    
    added = 0
    # Add/update devices in scanner with enrichment
    for device in devices:
        ip = device.get('ip')
        mac = device.get('mac', '')
        if ip and ip not in scanner.devices:
            # Get vendor from MAC
            vendor = ''
            if mac:
                mac_prefix = mac.upper()[:8]
                vendor = MAC_VENDORS.get(mac_prefix, '')
                if not vendor:
                    # Try online lookup
                    vendor = get_mac_vendor_online(mac) or ''
            
            # Detect device type
            device_type = 'unknown'
            hostname = ''
            
            # Try to resolve hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            # Smart device type detection
            vendor_lower = vendor.lower()
            hostname_lower = hostname.lower()
            
            if 'apple' in vendor_lower or 'iphone' in hostname_lower or 'ipad' in hostname_lower or 'macbook' in hostname_lower:
                device_type = 'apple'
            elif 'samsung' in vendor_lower or 'galaxy' in hostname_lower:
                device_type = 'phone'
            elif 'ring' in vendor_lower or 'ring' in hostname_lower:
                device_type = 'camera'
            elif 'nest' in vendor_lower or 'google' in vendor_lower:
                device_type = 'iot'
            elif 'amazon' in vendor_lower or 'echo' in hostname_lower or 'alexa' in hostname_lower:
                device_type = 'iot'
            elif 'roku' in vendor_lower or 'firetv' in hostname_lower or 'chromecast' in hostname_lower:
                device_type = 'media'
            elif 'raspberry' in vendor_lower:
                device_type = 'server'
            elif ip == scanner.gateway_ip:
                device_type = 'router'
            
            scanner.devices[ip] = Device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                os=device_type,
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                is_gateway=(ip == scanner.gateway_ip),
                is_local=False,
                open_ports=[],
                services={}
            )
            datastore.upsert_device(scanner.devices[ip], scan_profile="mitm")
            datastore.add_observation(
                "mitm_discovery",
                ip,
                f"MITM discovered device {ip}",
                {"ip": ip, "mac": mac, "vendor": vendor, "device_type": device_type},
            )
            added += 1
        elif ip:
            scanner.devices[ip].last_seen = datetime.now().isoformat()
            datastore.upsert_device(scanner.devices[ip], scan_profile="mitm")
    
    # Emit device update
    socketio.emit('devices_update', {
        'devices': [asdict(d) for d in scanner.devices.values()],
        'count': len(scanner.devices)
    })
    
    return jsonify({'success': True, 'devices_added': added})


@app.route('/api/mitm/traffic', methods=['POST'])
def receive_mitm_traffic():
    """Receive traffic data from MITM script with enrichment"""
    global mitm_active, mitm_last_seen
    data = request.json or {}
    
    mitm_active = True
    mitm_last_seen = datetime.now()
    
    connections = data.get('connections', [])
    dns_queries = data.get('dns_queries', [])
    packets = data.get('packets', 0)
    bytes_total = data.get('bytes', 0)
    
    # Add connections to analyzer with enrichment
    with analyzer.lock:
        for conn in connections:
            src_ip = conn['src_ip']
            dst_ip = conn['dst_ip']
            dst_port = conn.get('dst_port', 0)
            
            # Identify service based on port and IP
            service = ''
            app_protocol = ''
            
            if dst_port == 443:
                app_protocol = 'HTTPS'
            elif dst_port == 80:
                app_protocol = 'HTTP'
            elif dst_port == 53:
                app_protocol = 'DNS'
            elif dst_port == 5353:
                app_protocol = 'mDNS'
            elif dst_port == 32100:
                app_protocol = 'Ring/IoT'
                service = 'Ring Camera'
            elif dst_port == 5062:
                app_protocol = 'Ring'
                service = 'Ring Camera'
            
            # Add external IPs as "cloud" devices for the graph
            for ip in [src_ip, dst_ip]:
                if ip not in scanner.devices and not is_private_ip(ip):
                    # Lookup IP info
                    ip_info = lookup_ip_info(ip)
                    service_name = ip_info.get('service', '')
                    
                    scanner.devices[ip] = Device(
                        ip=ip,
                        mac='',
                        hostname=ip_info.get('hostname', '') or service_name or ip,
                        vendor=service_name,
                        os='cloud',
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        is_gateway=False,
                        is_local=False,
                        open_ports=[],
                        services={'cloud': service_name, 'country': ip_info.get('country', ''), 'org': ip_info.get('org', '')}
                    )
                    datastore.upsert_device(scanner.devices[ip], scan_profile="mitm_cloud")
            
            key = f"{src_ip}:{conn.get('src_port', 0)}->{dst_ip}:{dst_port}"
            if key not in analyzer.connections:
                analyzer.connections[key] = Connection(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=conn.get('src_port', 0),
                    dst_port=dst_port,
                    protocol=conn.get('protocol', 'TCP'),
                    packet_count=conn.get('packets', 1),
                    byte_count=conn.get('bytes', 0),
                    first_seen=conn.get('first_seen', datetime.now().isoformat()),
                    last_seen=datetime.now().isoformat(),
                    services=[service] if service else [],
                    application=app_protocol or ''
                )
                datastore.add_observation(
                    "flow_new",
                    key,
                    f"New flow {src_ip}:{conn.get('src_port', 0)} -> {dst_ip}:{dst_port}",
                    {"protocol": conn.get('protocol', 'TCP'), "application": app_protocol or ''},
                )
            else:
                analyzer.connections[key].packet_count = conn.get('packets', 1)
                analyzer.connections[key].byte_count = conn.get('bytes', 0)
                analyzer.connections[key].last_seen = datetime.now().isoformat()

            datastore.upsert_flow(key, analyzer.connections[key])
        
        # Add DNS queries
        for dns in dns_queries:
            dns_query = DNSQuery(
                src_ip=dns['src_ip'],
                domain=dns['domain'],
                query_type=dns.get('type', 'A'),
                timestamp=datetime.now().isoformat()
            )
            analyzer.dns_queries.append(dns_query)
            datastore.add_dns_query(dns_query)
        
        # Update packet counts
        analyzer.total_packets = packets
        analyzer.total_bytes = bytes_total
    
    # Emit real-time updates via WebSocket
    socketio.emit('traffic_update', {
        'connections': len(analyzer.connections),
        'packets': analyzer.total_packets,
        'bytes': analyzer.total_bytes,
        'dns_queries': len(analyzer.dns_queries),
        'mitm_active': True
    })
    
    # Also emit device updates (includes cloud services now)
    socketio.emit('devices_update', {
        'devices': [asdict(d) for d in scanner.devices.values()],
        'count': len(scanner.devices)
    })
    
    return jsonify({'success': True, 'connections_updated': len(connections), 'devices': len(scanner.devices)})


# ============================================================================
# Coursework Helper Endpoints (NetVis toolkit)
# ============================================================================

@app.route('/api/coursework/status', methods=['GET'])
def coursework_status():
    """Summarize rubric module log presence for the Coursework UI."""
    base = Path(__file__).resolve().parent / "logs"
    report_dir = Path(__file__).resolve().parent / "report"

    logs_summary = {}
    ordered_modules = list(CW_CORE_MODULES) + [m for m in CW_EXT_MODULES]
    for mod in ordered_modules:
        mod_dir = base / mod
        files = []
        if mod_dir.exists():
            try:
                files = sorted(mod_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            except Exception:
                files = []

        latest = None
        if files:
            try:
                payload = json.loads(files[0].read_text(encoding="utf-8"))
                latest = {
                    "file": files[0].name,
                    "session_id": payload.get("session_id"),
                    "generated_at": payload.get("generated_at"),
                }
            except Exception:
                latest = {"file": files[0].name}

        logs_summary[mod] = {
            "count": len(files),
            "latest": latest,
        }

    report_artifacts = {}
    for name in (
        "FINAL_REPORT_TEMPLATE.md",
        "detection_matrix.json",
        "detection_matrix.md",
        "multichain_story.json",
        "multichain_story.md",
        "multichain_casefile.json",
    ):
        p = report_dir / name
        report_artifacts[name] = {"exists": p.exists()}
        if p.exists():
            try:
                report_artifacts[name]["modified_at"] = datetime.fromtimestamp(p.stat().st_mtime).isoformat()
            except Exception:
                pass

    return jsonify({
        "logs": logs_summary,
        "report": report_artifacts,
    })


def _cw_is_valid_module(mod: str) -> bool:
    return mod in CW_LOG_MODULES


@app.route('/api/coursework/logs/<module>', methods=['GET'])
def coursework_list_logs(module: str):
    """List JSON logs for a rubric module (for the Coursework UI)."""
    if not _cw_is_valid_module(module):
        return jsonify({"error": "invalid_module"}), 400

    try:
        limit = int(request.args.get("limit", "50"))
    except Exception:
        limit = 50
    limit = max(1, min(200, limit))

    base = Path(__file__).resolve().parent / "logs" / module
    if not base.exists():
        return jsonify({"module": module, "count": 0, "files": []})

    try:
        files = sorted(base.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        files = []

    out = []
    for p in files[:limit]:
        meta = {"file": p.name}
        try:
            st = p.stat()
            meta["modified_at"] = datetime.fromtimestamp(st.st_mtime).isoformat()
            meta["size_bytes"] = int(st.st_size)
        except Exception:
            pass

        # Best-effort extraction of a few useful fields without parsing the whole file in the UI.
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
            meta["session_id"] = payload.get("session_id")
            meta["generated_at"] = payload.get("generated_at")
            res = payload.get("result") or {}
            if isinstance(res, dict):
                meta["technique"] = res.get("technique")
        except Exception:
            pass

        out.append(meta)

    return jsonify({"module": module, "count": len(files), "files": out})


@app.route('/api/coursework/log/<module>/<filename>', methods=['GET'])
def coursework_get_log(module: str, filename: str):
    """Fetch a specific JSON log file (for the Coursework UI)."""
    if not _cw_is_valid_module(module):
        return jsonify({"error": "invalid_module"}), 400
    if not filename or "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"error": "invalid_filename"}), 400
    if not filename.endswith(".json"):
        return jsonify({"error": "only_json_allowed"}), 400

    base = (Path(__file__).resolve().parent / "logs" / module).resolve()
    path = (base / filename).resolve()
    try:
        path.relative_to(base)
    except Exception:
        return jsonify({"error": "path_not_allowed"}), 400

    if not path.exists():
        return jsonify({"error": "not_found"}), 404

    try:
        if path.stat().st_size > 5 * 1024 * 1024:
            return jsonify({"error": "file_too_large"}), 413
        payload = json.loads(path.read_text(encoding="utf-8"))
        return jsonify(payload)
    except Exception:
        return jsonify({"error": "failed_to_read"}), 500


@app.route('/api/coursework/report/<name>', methods=['GET'])
def coursework_get_report_artifact(name: str):
    """Fetch a report artifact (template or detection matrix) for viewing in the Coursework UI."""
    allowed = {
        "FINAL_REPORT_TEMPLATE.md",
        "detection_matrix.json",
        "detection_matrix.md",
        "multichain_story.json",
        "multichain_story.md",
        "multichain_casefile.json",
    }
    if name not in allowed:
        return jsonify({"error": "not_allowed"}), 400

    report_dir = (Path(__file__).resolve().parent / "report").resolve()
    path = (report_dir / name).resolve()
    try:
        path.relative_to(report_dir)
    except Exception:
        return jsonify({"error": "path_not_allowed"}), 400
    if not path.exists():
        return jsonify({"error": "not_found"}), 404

    try:
        text = path.read_text(encoding="utf-8")
        modified_at = datetime.fromtimestamp(path.stat().st_mtime).isoformat()
        if name.endswith(".json"):
            return jsonify({"name": name, "modified_at": modified_at, "json": json.loads(text)})
        return jsonify({"name": name, "modified_at": modified_at, "content": text})
    except Exception:
        return jsonify({"error": "failed_to_read"}), 500


@app.route('/api/coursework/jobs', methods=['POST'])
def coursework_start_job():
    guard = _cw_local_only_guard()
    if guard is not None:
        return guard

    data = request.json or {}
    module = str(data.get("module") or "").strip()
    action = str(data.get("action") or "").strip()
    params = data.get("params") or {}
    if not isinstance(params, dict):
        return jsonify({"error": "params_must_be_object"}), 400
    if not module or not action:
        return jsonify({"error": "module_and_action_required"}), 400

    job_id = coursework_jobs.start(module, action, params)
    job = datastore.get_coursework_job(job_id) or {"job_id": job_id, "status": "queued", "module": module, "action": action}
    return jsonify(job), 202


@app.route('/api/coursework/jobs', methods=['GET'])
def coursework_list_jobs():
    guard = _cw_local_only_guard()
    if guard is not None:
        return guard

    try:
        limit = int(request.args.get("limit", "20"))
    except Exception:
        limit = 20
    limit = max(1, min(200, limit))
    return jsonify({"jobs": datastore.list_coursework_jobs(limit=limit)})


@app.route('/api/coursework/jobs/<job_id>', methods=['GET'])
def coursework_get_job(job_id: str):
    guard = _cw_local_only_guard()
    if guard is not None:
        return guard

    job = datastore.get_coursework_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='NetVis - Network Visualization Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5001, help='Port to bind to')
    parser.add_argument('--demo', action='store_true', help='Load demo data on startup')
    args = parser.parse_args()
    
    if args.demo:
        generate_demo_data()
        print("Demo data loaded")
    
    print(f"Starting NetVis server on {args.host}:{args.port}")
    print(f"Local IP: {scanner.local_ip}")
    print(f"Gateway: {scanner.gateway_ip}")
    print(f"Network: {scanner.network_cidr}")
    print(f"Scapy available: {SCAPY_AVAILABLE}")
    print(f"Nmap available: {NMAP_AVAILABLE}")

    debug_enabled = str(os.environ.get("NETVIS_DEBUG", "")).strip().lower() in ("1", "true", "yes", "on")
    socketio.run(
        app,
        host=args.host,
        port=args.port,
        debug=debug_enabled,
        allow_unsafe_werkzeug=debug_enabled,
    )
