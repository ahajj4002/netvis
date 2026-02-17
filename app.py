#!/usr/bin/env python3
"""
NetVis - Network Visualization Platform
Entry point: wires refactored modules and runs the Flask app.
"""

from pathlib import Path
import os

# Build state from refactored modules
DATA_DIR = Path(__file__).resolve().parent / "data"
from store import DataStore
from net_scanner import NetworkScanner
from traffic_analyzer import TrafficAnalyzer
from services.scan_service import run_profile_scan
from services.jobs import ScanJobManager, CourseworkJobManager
from services.metrics_daemon import NipMetricsDaemon

datastore = DataStore(DATA_DIR / "netvis.db")
scanner = NetworkScanner()
analyzer = TrafficAnalyzer()
scanner.datastore = datastore
analyzer.datastore = datastore

# Import server (creates its own globals) then replace with our instances
import server

server.datastore = datastore
server.scanner = scanner
server.analyzer = analyzer
server.scan_jobs = ScanJobManager(
    datastore,
    scanner,
    lambda profile, target, progress_cb: run_profile_scan(
        scanner, datastore, profile, target, progress_cb
    ),
)
server.coursework_jobs = CourseworkJobManager(
    datastore,
    server.run_coursework_action,
    server.run_multichain_pipeline,
)
server.nip_metrics_daemon = NipMetricsDaemon(analyzer, datastore, server.nip_bus)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NetVis - Network Visualization Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5001, help="Port to bind to")
    parser.add_argument("--demo", action="store_true", help="Load demo data on startup")
    args = parser.parse_args()
    if args.demo:
        server.generate_demo_data()
        print("Demo data loaded")
    from config import NMAP_AVAILABLE, SCAPY_AVAILABLE
    print(f"Starting NetVis server on {args.host}:{args.port}")
    print(f"Local IP: {scanner.local_ip}")
    print(f"Gateway: {scanner.gateway_ip}")
    print(f"Network: {scanner.network_cidr}")
    print(f"Scapy available: {SCAPY_AVAILABLE}")
    print(f"Nmap available: {NMAP_AVAILABLE}")
    debug_enabled = str(os.environ.get("NETVIS_DEBUG", "")).strip().lower() in ("1", "true", "yes", "on")
    server.socketio.run(
        server.app,
        host=args.host,
        port=args.port,
        debug=debug_enabled,
        allow_unsafe_werkzeug=debug_enabled,
    )
