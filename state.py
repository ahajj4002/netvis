"""
NetVis shared state.
Global instances (datastore, scanner, analyzer, nip_bus, etc.) set by app at startup.
"""

# Set by app.py after creating instances
datastore = None
scanner = None
analyzer = None
nip_bus = None
nip_registry = None
scan_jobs = None
coursework_jobs = None
nip_metrics_daemon = None
socketio = None
DATA_DIR = None
NIP_THREAT_FEED_PATH = None
API_KEY = None
mitm_active = False
mitm_last_seen = None
mitm_process = None
mitm_started_by_gui = False
