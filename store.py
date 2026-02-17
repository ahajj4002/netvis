"""
NetVis persistence layer.
SQLite-backed DataStore for assets, services, flows, alerts, observations, and jobs.
"""

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from models import Alert, Connection, Device, DNSQuery


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

                CREATE TABLE IF NOT EXISTS brain_plans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    generated_at TEXT,
                    situation_json TEXT,
                    objectives_json TEXT,
                    planned_techniques_json TEXT
                );

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

    def update_scan_job(
        self,
        job_id: str,
        *,
        status: Optional[str] = None,
        progress: Optional[int] = None,
        message: Optional[str] = None,
        result: Optional[dict] = None,
        error: Optional[str] = None,
    ):
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
        return [j for r in rows if (j := self.get_scan_job(r["job_id"]))]

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

    def update_coursework_job(
        self,
        job_id: str,
        *,
        status: Optional[str] = None,
        progress: Optional[int] = None,
        message: Optional[str] = None,
        log_path: Optional[str] = None,
        result: Optional[dict] = None,
        error: Optional[str] = None,
    ):
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
        return [j for r in rows if (j := self.get_coursework_job(r["job_id"]))]

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

    def list_observations_range(
        self,
        *,
        start_ts: str,
        end_ts: str,
        like: str = "",
        limit: int = 200,
    ) -> List[dict]:
        lim = max(1, int(limit))
        s0, s1 = str(start_ts or "").strip(), str(end_ts or "").strip()
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
                    ORDER BY id DESC LIMIT ?
                    """,
                    (s0, s1, pat, pat, pat, lim),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM observations
                    WHERE timestamp >= ? AND timestamp <= ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (s0, s1, lim),
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
                    ORDER BY last_seen DESC LIMIT ?
                    """,
                    (as_of_s, as_of_s, lim),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM assets ORDER BY last_seen DESC LIMIT ?", (lim,)).fetchall()
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
                    ORDER BY last_seen DESC LIMIT ?
                    """,
                    (as_of_s, as_of_s, lim),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM services ORDER BY last_seen DESC LIMIT ?", (lim,)).fetchall()
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
                    ORDER BY last_seen DESC LIMIT ?
                    """,
                    (as_of_s, as_of_s, lim),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM flows ORDER BY last_seen DESC LIMIT ?", (lim,)).fetchall()
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

    def add_nip_metric(self, metric: dict) -> None:
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
                rows = conn.execute("SELECT * FROM nip_metrics ORDER BY id DESC LIMIT ?", (lim,)).fetchall()
        return [
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
            for r in rows
        ]

    def list_nip_metrics_range(
        self,
        *,
        ip: str,
        start_ts: str,
        end_ts: str,
        limit: int = 500,
    ) -> List[dict]:
        lim = max(1, int(limit))
        ip_s, s0, s1 = str(ip or "").strip(), str(start_ts or "").strip(), str(end_ts or "").strip()
        if not ip_s or not s0 or not s1:
            return []
        with self.lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM nip_metrics
                WHERE ip=? AND timestamp >= ? AND timestamp <= ?
                ORDER BY id DESC LIMIT ?
                """,
                (ip_s, s0, s1, lim),
            ).fetchall()
        return [
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
            for r in rows
        ]

    def upsert_nip_baseline(
        self,
        *,
        ip: str,
        baseline: dict,
        window_seconds: int,
        method: str = "ewma",
    ) -> None:
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
            rows = conn.execute(
                "SELECT * FROM nip_baselines ORDER BY computed_at DESC LIMIT ?", (lim,)
            ).fetchall()
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
