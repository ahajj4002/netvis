from pathlib import Path
from types import SimpleNamespace
import threading

import pytest

import server
from store import DataStore


class ScanJobsStub:
    """Simple stub for scan job creation route tests."""

    def __init__(self, job_id: str = "job-test-123"):
        self.job_id = job_id
        self.calls = []

    def start(self, profile: str, target: str | None):
        self.calls.append((profile, target))
        return self.job_id


@pytest.fixture()
def isolated_store(tmp_path):
    """Fresh sqlite store per test."""
    return DataStore(Path(tmp_path) / "test_netvis.db")


@pytest.fixture()
def client_ctx(monkeypatch, isolated_store):
    """
    Flask test client with isolated backend globals.
    Prevents network side effects and uses a temp datastore.
    """
    scanner_stub = SimpleNamespace(
        local_ip="10.0.0.2",
        gateway_ip="10.0.0.1",
        network_cidr="10.0.0.0/24",
        devices={},
    )
    analyzer_stub = SimpleNamespace(
        is_capturing=False,
        lock=threading.Lock(),
        connections={},
        dns_queries=[],
        alerts=[],
    )
    scan_jobs_stub = ScanJobsStub()

    monkeypatch.setattr(server, "datastore", isolated_store)
    monkeypatch.setattr(server, "scanner", scanner_stub)
    monkeypatch.setattr(server, "analyzer", analyzer_stub)
    monkeypatch.setattr(server, "scan_jobs", scan_jobs_stub)
    monkeypatch.setattr(server, "SCAPY_AVAILABLE", False)
    monkeypatch.setattr(server, "NMAP_AVAILABLE", False)
    monkeypatch.setattr(server, "API_KEY", "", raising=False)
    monkeypatch.setattr(server, "mitm_active", False, raising=False)
    monkeypatch.setattr(server, "mitm_last_seen", None, raising=False)

    return {
        "client": server.app.test_client(),
        "store": isolated_store,
        "scanner": scanner_stub,
        "scan_jobs": scan_jobs_stub,
    }
