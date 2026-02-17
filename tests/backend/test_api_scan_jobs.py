def test_start_scan_job_queues_expected_profile_and_target(client_ctx):
    client = client_ctx["client"]
    scan_jobs = client_ctx["scan_jobs"]

    response = client.post("/api/scan/jobs", json={"profile": "quick", "network": "10.0.0.0/24"})
    assert response.status_code == 202

    payload = response.get_json()
    assert payload["job_id"] == "job-test-123"
    assert payload["status"] == "queued"
    assert payload["profile"] == "quick"
    assert payload["target"] == "10.0.0.0/24"
    assert scan_jobs.calls == [("quick", "10.0.0.0/24")]


def test_start_scan_job_rejects_invalid_profile(client_ctx):
    client = client_ctx["client"]

    response = client.post("/api/scan/jobs", json={"profile": "invalid-profile"})
    assert response.status_code == 400
    assert "Invalid profile" in response.get_json()["error"]


def test_list_scan_jobs_returns_recent_jobs(client_ctx):
    client = client_ctx["client"]
    store = client_ctx["store"]

    store.create_scan_job("job-1", "quick", "10.0.0.0/24")
    store.update_scan_job("job-1", status="running", progress=10, message="Started")

    response = client.get("/api/scan/jobs?limit=5")
    assert response.status_code == 200
    jobs = response.get_json()["jobs"]
    assert len(jobs) == 1
    assert jobs[0]["job_id"] == "job-1"
    assert jobs[0]["profile"] == "quick"
    assert jobs[0]["status"] == "running"


def test_list_scan_jobs_handles_bad_limit_input(client_ctx):
    client = client_ctx["client"]

    response = client.get("/api/scan/jobs?limit=not-a-number")
    assert response.status_code == 200
    assert isinstance(response.get_json()["jobs"], list)


def test_get_scan_job_returns_404_when_missing(client_ctx):
    client = client_ctx["client"]

    response = client.get("/api/scan/jobs/does-not-exist")
    assert response.status_code == 404
    assert response.get_json()["error"] == "Job not found"
