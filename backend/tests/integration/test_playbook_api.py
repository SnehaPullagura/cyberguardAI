def test_create_and_list_playbooks_api(client, admin_headers):
    payload = {
        "name": "Integration Test Containment Playbook",
        "description": "Auto-generated test playbook",
        "enabled": True,
        "severity_threshold": "high",
        "risk_score_threshold": 80.0,
        "trigger_conditions": [{"field": "risk_score", "operator": "gte", "value": 80.0}],
        "action_sequence": ["create_incident", "quarantine_simulation"],
        "approval_required": False,
        "cooldown_seconds": 300,
        "timeout_seconds": 60,
    }

    # Create Playbook
    response = client.post("/api/v1/playbooks", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Integration Test Containment Playbook"
    pb_id = data["id"]

    # List Playbooks
    list_res = client.get("/api/v1/playbooks", headers=admin_headers)
    assert list_res.status_code == 200
    playbooks = list_res.json()
    assert any(p["id"] == pb_id for p in playbooks)

    # Test Playbook Simulation Endpoint
    test_res = client.post(f"/api/v1/playbooks/{pb_id}/test", headers=admin_headers)
    assert test_res.status_code == 200
    test_data = test_res.json()
    assert test_data["simulation_status"] == "success"
    assert test_data["mode"] == "simulation"
