from models import Connection, Device


def test_status_endpoint_returns_expected_shape(client_ctx):
    client = client_ctx["client"]
    res = client.get("/api/status")
    assert res.status_code == 200

    data = res.get_json()
    assert data["local_ip"] == "10.0.0.2"
    assert data["gateway_ip"] == "10.0.0.1"
    assert data["network"] == "10.0.0.0/24"
    assert "scan_profiles" in data
    assert "db_path" in data
    assert "capturing" in data


def test_scan_job_create_accepts_valid_profile(client_ctx):
    client = client_ctx["client"]
    scan_jobs = client_ctx["scan_jobs"]

    res = client.post(
        "/api/scan/jobs",
        json={"profile": "standard", "network": "10.0.0.0/24"},
    )
    assert res.status_code == 202

    payload = res.get_json()
    assert payload["job_id"] == "job-test-123"
    assert payload["status"] == "queued"
    assert payload["profile"] == "standard"
    assert scan_jobs.calls == [("standard", "10.0.0.0/24")]


def test_scan_job_create_rejects_invalid_profile(client_ctx):
    client = client_ctx["client"]
    res = client.post("/api/scan/jobs", json={"profile": "not-a-profile"})
    assert res.status_code == 400
    assert "Invalid profile" in res.get_json()["error"]


def test_scan_jobs_list_endpoint_returns_created_jobs(client_ctx):
    client = client_ctx["client"]
    store = client_ctx["store"]

    store.create_scan_job("job-1", "quick", "10.0.0.0/24")
    store.create_scan_job("job-2", "standard", "10.0.0.0/24")

    res = client.get("/api/scan/jobs?limit=5")
    assert res.status_code == 200
    jobs = res.get_json()["jobs"]
    ids = {j["job_id"] for j in jobs}
    assert {"job-1", "job-2"}.issubset(ids)


def test_scan_job_detail_endpoint_returns_job(client_ctx):
    client = client_ctx["client"]
    store = client_ctx["store"]

    store.create_scan_job("job-detail", "deep", "10.0.0.0/24")
    store.update_scan_job(
        "job-detail",
        status="completed",
        progress=100,
        message="Done",
        result={"device_count": 3},
    )

    res = client.get("/api/scan/jobs/job-detail")
    assert res.status_code == 200
    data = res.get_json()
    assert data["job_id"] == "job-detail"
    assert data["status"] == "completed"
    assert data["result"]["device_count"] == 3


def test_scan_job_detail_endpoint_404_for_missing_job(client_ctx):
    client = client_ctx["client"]
    res = client.get("/api/scan/jobs/missing-job")
    assert res.status_code == 404
    assert res.get_json()["error"] == "Job not found"


def test_store_device_insert_and_read_roundtrip(isolated_store):
    store = isolated_store

    store.upsert_device(
        Device(
            ip="10.0.0.50",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="test-host",
            vendor="Acme",
            os="linux",
            is_local=True,
        ),
        scan_profile="standard",
        metadata={"source": "pytest"},
    )

    assets = store.list_assets()
    assert len(assets) == 1
    asset = assets[0]
    assert asset["ip"] == "10.0.0.50"
    assert asset["hostname"] == "test-host"
    assert asset["last_scan_profile"] == "standard"
    assert asset["metadata"]["source"] == "pytest"


def test_store_scan_job_lifecycle_roundtrip(isolated_store):
    store = isolated_store
    store.create_scan_job("scan-life", "quick", "10.0.0.0/24")
    store.update_scan_job(
        "scan-life",
        status="completed",
        progress=100,
        message="Completed",
        result={"ok": True},
    )

    job = store.get_scan_job("scan-life")
    assert job is not None
    assert job["status"] == "completed"
    assert job["progress"] == 100
    assert job["result"]["ok"] is True
    assert job["completed_at"]


def test_store_flow_insert_and_list_roundtrip(isolated_store):
    store = isolated_store
    store.upsert_flow(
        "flow-1",
        Connection(
            src_ip="10.0.0.10",
            dst_ip="1.1.1.1",
            protocol="TCP",
            src_port=51515,
            dst_port=443,
            packet_count=9,
            byte_count=4096,
            application="https",
        ),
    )

    flows = store.list_flows(limit=10)
    assert len(flows) == 1
    f = flows[0]
    assert f["flow_key"] == "flow-1"
    assert f["src_ip"] == "10.0.0.10"
    assert f["dst_port"] == 443
    assert f["application"] == "https"
