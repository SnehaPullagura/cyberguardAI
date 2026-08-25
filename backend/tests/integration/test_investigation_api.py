import uuid
import pytest
from fastapi.testclient import TestClient


def test_investigation_case_api_crud(client: TestClient, admin_headers: dict):
    # 1. Create Case
    payload = {
        "title": "Unauthorized Privilege Escalation Investigation",
        "description": "User svc_backup gained Domain Admin permissions.",
        "severity": "critical",
        "priority": "P1",
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "tags": ["domain_admin", "ad_security"],
    }
    create_res = client.post("/api/v1/investigations/cases", json=payload, headers=admin_headers)
    assert create_res.status_code == 201
    case_data = create_res.json()
    case_id = case_data["id"]
    assert case_data["title"] == payload["title"]
    assert case_data["priority"] == "P1"

    # 2. Get Case Details
    get_res = client.get(f"/api/v1/investigations/cases/{case_id}", headers=admin_headers)
    assert get_res.status_code == 200
    assert get_res.json()["case_id"] == case_data["case_id"]

    # 3. Update Status
    patch_res = client.patch(
        f"/api/v1/investigations/cases/{case_id}",
        json={"status": "investigating", "priority": "P2"},
        headers=admin_headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "investigating"
    assert patch_res.json()["priority"] == "P2"

    # 4. Attach Evidence
    evidence_payload = {
        "title": "Suspicious Kerberos Ticket Request Log",
        "evidence_type": "event",
        "data": {"account": "svc_backup", "ticket_options": "0x40810000"},
    }
    ev_res = client.post(
        f"/api/v1/investigations/cases/{case_id}/evidence",
        json=evidence_payload,
        headers=admin_headers,
    )
    assert ev_res.status_code == 201
    assert ev_res.json()["title"] == evidence_payload["title"]

    # 5. List Evidence
    list_ev_res = client.get(f"/api/v1/investigations/cases/{case_id}/evidence", headers=admin_headers)
    assert list_ev_res.status_code == 200
    assert len(list_ev_res.json()) >= 1

    # 6. Add Note
    note_res = client.post(
        f"/api/v1/investigations/cases/{case_id}/notes",
        json={"content": "Credential revocation issued for svc_backup."},
        headers=admin_headers,
    )
    assert note_res.status_code == 201
    assert "Credential revocation" in note_res.json()["content"]

    # 7. List Notes
    list_notes_res = client.get(f"/api/v1/investigations/cases/{case_id}/notes", headers=admin_headers)
    assert list_notes_res.status_code == 200
    assert len(list_notes_res.json()) >= 1

    # 8. Retrieve Timeline
    tl_res = client.get(f"/api/v1/investigations/cases/{case_id}/timeline", headers=admin_headers)
    assert tl_res.status_code == 200
    timeline = tl_res.json()
    assert len(timeline) >= 3

    # 9. Retrieve Graph
    gr_res = client.get(f"/api/v1/investigations/cases/{case_id}/graph", headers=admin_headers)
    assert gr_res.status_code == 200
    assert gr_res.json()["nodes_count"] >= 2


def test_global_search_and_saved_searches(client: TestClient, admin_headers: dict):
    # 1. Global Search
    search_res = client.get("/api/v1/investigations/search?q=admin", headers=admin_headers)
    assert search_res.status_code == 200
    res_data = search_res.json()
    assert "results" in res_data
    assert "cases" in res_data["results"]

    # 2. Create Saved Search
    saved_payload = {
        "name": "High Priority Unresolved Cases",
        "description": "Filter for P1 and P2 cases still in open or investigating status.",
        "target_entity": "cases",
        "filter_params": {"priorities": ["P1", "P2"], "status": ["open", "investigating"]},
    }
    create_saved_res = client.post(
        "/api/v1/investigations/saved-searches",
        json=saved_payload,
        headers=admin_headers,
    )
    assert create_saved_res.status_code == 201

    # 3. List Saved Searches
    list_saved_res = client.get("/api/v1/investigations/saved-searches", headers=admin_headers)
    assert list_saved_res.status_code == 200
    assert len(list_saved_res.json()) >= 1


def test_case_filters_api(client: TestClient, admin_headers: dict):
    # Create distinct cases
    client.post("/api/v1/investigations/cases", json={"title": "Filtered Case P1", "priority": "P1", "severity": "critical"}, headers=admin_headers)
    client.post("/api/v1/investigations/cases", json={"title": "Filtered Case P4", "priority": "P4", "severity": "low"}, headers=admin_headers)

    p1_res = client.get("/api/v1/investigations/cases?priority=P1", headers=admin_headers)
    assert p1_res.status_code == 200
    assert all(c["priority"] == "P1" for c in p1_res.json())

    crit_res = client.get("/api/v1/investigations/cases?severity=critical", headers=admin_headers)
    assert crit_res.status_code == 200
    assert all(c["severity"] == "critical" for c in crit_res.json())


def test_case_not_found_errors(client: TestClient, admin_headers: dict):
    res = client.get("/api/v1/investigations/cases/non-existent-case-id", headers=admin_headers)
    assert res.status_code == 404

    res_patch = client.patch("/api/v1/investigations/cases/non-existent-case-id", json={"title": "New"}, headers=admin_headers)
    assert res_patch.status_code == 404

    res_ev = client.post("/api/v1/investigations/cases/non-existent-case-id/evidence", json={"title": "Test", "evidence_type": "event"}, headers=admin_headers)
    assert res_ev.status_code == 404

    res_note = client.post("/api/v1/investigations/cases/non-existent-case-id/notes", json={"content": "Test"}, headers=admin_headers)
    assert res_note.status_code == 404


def test_case_assign_endpoint(client: TestClient, admin_headers: dict):
    # Create case
    c_res = client.post("/api/v1/investigations/cases", json={"title": "Assignment Endpoint Test Case"}, headers=admin_headers)
    case_id = c_res.json()["id"]

    # Assign to admin
    assign_res = client.post(
        f"/api/v1/investigations/cases/{case_id}/assign",
        json={"assignee_id": "non-existent-user-id"},
        headers=admin_headers,
    )
    assert assign_res.status_code == 400


def test_viewer_rbac_case_write_restriction(client: TestClient, viewer_headers: dict):
    # Viewer cannot create case
    payload = {"title": "Unauthorized Case Creation Attempt"}
    res = client.post("/api/v1/investigations/cases", json=payload, headers=viewer_headers)
    assert res.status_code == 403
