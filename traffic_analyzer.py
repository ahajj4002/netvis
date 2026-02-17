"""
NetVis traffic analyzer.
Packet capture, connection tracking, DNS extraction, and anomaly detection.
"""

import time
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from typing import Dict, List, Optional, Set

from config import SCAPY_AVAILABLE
from constants import APP_PORTS, KNOWN_SERVICES
from models import Alert, Connection, DNSQuery


class TrafficAnalyzer:
    """Analyzes network traffic to identify communication patterns."""

    def __init__(self):
        self.connections: Dict[str, Connection] = {}
        self.capture_thread: Optional[object] = None
        self.is_capturing = False
        self.packet_buffer: List[dict] = []
        import threading
        self.lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self._last_flow_persist: Dict[str, float] = {}
        self._persist_interval_sec = 2.0
        self.dns_queries: List[DNSQuery] = []
        self.alerts: List[Alert] = []
        self.bandwidth_history: Dict[str, List[dict]] = {}
        self.known_devices: Set[str] = set()
        self.port_scan_tracker: Dict[str, Dict[str, set]] = {}
        self.datastore = None  # Injected by app after creation

    def start_capture(self, interface: Optional[str] = None, filter_str: str = ""):
        if not SCAPY_AVAILABLE:
            return False
        if self.is_capturing:
            return True
        import threading
        from scapy.all import sniff, IP, TCP, UDP, ICMP
        self.is_capturing = True
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, filter_str),
            daemon=True,
        )
        self.capture_thread.start()
        return True

    def stop_capture(self):
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)

    def _capture_loop(self, interface: Optional[str], filter_str: str):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.is_capturing,
            )
        except Exception:
            self.is_capturing = False

    def _process_packet(self, packet):
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            if IP not in packet:
                return
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "IP"
            src_port = dst_port = 0
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
            application = APP_PORTS.get(dst_port, APP_PORTS.get(src_port, ""))
            if dst_ip in KNOWN_SERVICES:
                application = KNOWN_SERVICES[dst_ip]
            elif src_ip in KNOWN_SERVICES:
                application = KNOWN_SERVICES[src_ip]
            if dst_port == 53 or src_port == 53:
                self._process_dns(packet, src_ip, dst_ip)
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
                        application=application,
                    )
                else:
                    conn = self.connections[conn_key]
                    conn.packet_count += 1
                    conn.byte_count += pkt_len
                    conn.last_seen = now
                    if not conn.application and application:
                        conn.application = application
                flow_obj = self.connections[conn_key]
                datastore = getattr(self, "datastore", None)
                last_persist = self._last_flow_persist.get(conn_key, 0)
                if datastore and (now_epoch - last_persist) >= self._persist_interval_sec:
                    datastore.upsert_flow(conn_key, flow_obj)
                    self._last_flow_persist[conn_key] = now_epoch
                for ip in [src_ip, dst_ip]:
                    if ip not in self.bandwidth_history:
                        self.bandwidth_history[ip] = []
                    self.bandwidth_history[ip].append({"timestamp": now, "bytes": pkt_len})
                    if len(self.bandwidth_history[ip]) > 1000:
                        self.bandwidth_history[ip] = self.bandwidth_history[ip][-500:]
                self._detect_port_scan(src_ip, dst_ip, dst_port)
                self._detect_new_device(src_ip)
                self._detect_new_device(dst_ip)
                self.packet_buffer.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "size": pkt_len,
                    "timestamp": now,
                    "application": application,
                })
                if len(self.packet_buffer) > 100:
                    self.packet_buffer = self.packet_buffer[-50:]
        except Exception:
            pass

    def _process_dns(self, packet, src_ip: str, dst_ip: str):
        try:
            from scapy.all import DNS
            if DNS not in packet:
                return
            dns = packet[DNS]
            now = datetime.now().isoformat()
            if dns.qd:
                qname = dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                qname = qname.rstrip(".")
                query_type = "A"
                querier = src_ip if dst_ip.endswith(".1") or dst_ip in ["8.8.8.8", "1.1.1.1"] else dst_ip
                with self.lock:
                    query = DNSQuery(
                        src_ip=querier,
                        domain=qname,
                        query_type=query_type,
                        timestamp=now,
                    )
                    self.dns_queries.append(query)
                    datastore = getattr(self, "datastore", None)
                    if datastore:
                        datastore.add_dns_query(query)
                    if len(self.dns_queries) > 500:
                        self.dns_queries = self.dns_queries[-250:]
        except Exception:
            pass

    def _detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int):
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = {}
        if dst_ip not in self.port_scan_tracker[src_ip]:
            self.port_scan_tracker[src_ip][dst_ip] = set()
        self.port_scan_tracker[src_ip][dst_ip].add(dst_port)
        if len(self.port_scan_tracker[src_ip][dst_ip]) > 20:
            self._add_alert(
                "port_scan",
                "high",
                f"Potential port scan detected: {src_ip} scanning {len(self.port_scan_tracker[src_ip][dst_ip])} ports on {dst_ip}",
                src_ip,
                dst_ip,
                {"ports_scanned": len(self.port_scan_tracker[src_ip][dst_ip])},
            )

    def _detect_new_device(self, ip: str):
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            if ip not in self.known_devices:
                self.known_devices.add(ip)
                datastore = getattr(self, "datastore", None)
                if datastore:
                    datastore.add_observation(
                        "discovery",
                        ip,
                        f"Observed new internal IP {ip}",
                        {"ip": ip},
                    )
                if len(self.known_devices) > 5:
                    self._add_alert("new_device", "medium", f"New device detected on network: {ip}", ip, "", {})

    def _add_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        src_ip: str = "",
        dst_ip: str = "",
        details: Optional[dict] = None,
    ):
        now = datetime.now().isoformat()
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            message=message,
            src_ip=src_ip,
            dst_ip=dst_ip,
            timestamp=now,
            details=details or {},
        )
        with self.lock:
            self.alerts.append(alert)
            datastore = getattr(self, "datastore", None)
            if datastore:
                datastore.add_alert(alert)
                datastore.add_observation(
                    "alert",
                    f"{alert.src_ip}->{alert.dst_ip}" if alert.dst_ip else (alert.src_ip or "network"),
                    alert.message,
                    {"alert_type": alert.alert_type, "severity": alert.severity, "details": alert.details},
                )
            if len(self.alerts) > 100:
                self.alerts = self.alerts[-50:]

    def get_connections(self) -> List[dict]:
        with self.lock:
            return [asdict(c) for c in self.connections.values()]

    def get_recent_packets(self) -> List[dict]:
        with self.lock:
            packets = self.packet_buffer.copy()
            self.packet_buffer.clear()
            return packets

    def get_traffic_matrix(self) -> Dict[str, Dict[str, int]]:
        matrix = defaultdict(lambda: defaultdict(int))
        with self.lock:
            for conn in self.connections.values():
                matrix[conn.src_ip][conn.dst_ip] += conn.byte_count
        return {k: dict(v) for k, v in matrix.items()}
