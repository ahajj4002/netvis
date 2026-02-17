def test_status_endpoint_returns_expected_shape(client_ctx):
    client = client_ctx["client"]

    response = client.get("/api/status")
    assert response.status_code == 200

    payload = response.get_json()
    assert payload["local_ip"] == "10.0.0.2"
    assert payload["gateway_ip"] == "10.0.0.1"
    assert payload["network"] == "10.0.0.0/24"
    assert payload["capturing"] is False
    assert payload["scapy_available"] is False
    assert payload["nmap_available"] is False
    assert payload["api_key_enabled"] is False
    assert isinstance(payload["scan_profiles"], list)
    assert "quick" in payload["scan_profiles"]
