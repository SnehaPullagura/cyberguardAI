import pytest
from fastapi.testclient import TestClient


def test_playbook_crud_api(client: TestClient, admin_token: str, auth_headers: dict):
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Create Playbook as Admin
    payload = {
        "name": "Integration Test Critical Anomaly Playbook",
        "description": "Auto-quarantine simulation for critical AI anomalies",
        "enabled": True,
        "response_mode": "dry_run",
        "severity_threshold": "high",
        "risk_score_threshold": 80.0,
        "trigger_conditions": [
            {"field": "risk_score", "operator": "gte", "value": 80.0},
            {"field": "severity", "operator": "eq", "value": "critical"},
        ],
        "action_sequence": [
            {"action_type": "quarantine_simulation", "action_config": {"target_host": "srv-prod-01"}, "risk_level": "high"},
            {"action_type": "notify_security_team", "action_config": {"channel": "soc-leads"}, "risk_level": "low"},
        ],
        "approval_required": True,
        "cooldown_seconds": 300,
        "timeout_seconds": 30,
        "failure_policy": "stop",
    }

    create_res = client.post("/api/v1/playbooks", json=payload, headers=admin_headers)
    assert create_res.status_code == 201
    created_pb = create_res.json()
    assert created_pb["name"] == payload["name"]
    pb_id = created_pb["id"]

    # 2. List Playbooks
    list_res = client.get("/api/v1/playbooks", headers=admin_headers)
    assert list_res.status_code == 200
    assert any(p["id"] == pb_id for p in list_res.json())

    # 3. Test Playbook Simulation Endpoint
    test_res = client.post(
        f"/api/v1/playbooks/{pb_id}/test",
        json={"mock_event": {"risk_score": 90.0, "severity": "critical"}},
        headers=admin_headers,
    )
    assert test_res.status_code == 200
    sim_data = test_res.json()
    assert sim_data["trigger_matched"] is True
    assert len(sim_data["simulated_actions"]) == 2

    # 4. Disable and Enable Playbook
    disable_res = client.post(f"/api/v1/playbooks/{pb_id}/disable", headers=admin_headers)
    assert disable_res.status_code == 200
    assert disable_res.json()["enabled"] is False

    enable_res = client.post(f"/api/v1/playbooks/{pb_id}/enable", headers=admin_headers)
    assert enable_res.status_code == 200
    assert enable_res.json()["enabled"] is True


def test_viewer_rbac_playbook_restriction(client: TestClient, auth_headers: dict):
    # Viewer cannot create playbook
    payload = {"name": "Unauthorized Playbook", "severity_threshold": "high", "risk_score_threshold": 50.0}
    create_res = client.post("/api/v1/playbooks", json=payload, headers=auth_headers)
    assert create_res.status_code == 403
