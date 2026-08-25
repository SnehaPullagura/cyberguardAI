import pytest
from fastapi.testclient import TestClient


def test_compliance_evaluation_api(client: TestClient, analyst_headers: dict):
    # 1. Get or evaluate SOC2
    res = client.get("/api/v1/reports/compliance/soc2", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["framework"] == "soc2"
    assert "overall_score" in data
    assert "summary_json" in data

    # 2. Trigger explicit evaluation
    eval_res = client.post("/api/v1/reports/compliance/iso27001/evaluate", headers=analyst_headers)
    assert eval_res.status_code == 200
    assert eval_res.json()["framework"] == "iso27001"

    # 3. Compliance History
    hist_res = client.get("/api/v1/reports/compliance-history?framework=soc2", headers=analyst_headers)
    assert hist_res.status_code == 200
    assert len(hist_res.json()) >= 1


def test_compliance_invalid_framework_400(client: TestClient, analyst_headers: dict):
    res = client.get("/api/v1/reports/compliance/unknown_framework", headers=analyst_headers)
    assert res.status_code == 400


def test_report_export_api_endpoints(client: TestClient, analyst_headers: dict):
    # 1. Export Incidents CSV
    csv_res = client.get("/api/v1/reports/export/csv?report_type=incidents", headers=analyst_headers)
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]

    # 2. Export Audit CSV
    audit_csv_res = client.get("/api/v1/reports/export/csv?report_type=audit", headers=analyst_headers)
    assert audit_csv_res.status_code == 200
    assert "text/csv" in audit_csv_res.headers["content-type"]

    # 3. Export Executive PDF
    pdf_res = client.get("/api/v1/reports/export/pdf?report_type=executive", headers=analyst_headers)
    assert pdf_res.status_code == 200
    assert "application/pdf" in pdf_res.headers["content-type"]

    # 4. Export Compliance PDF
    comp_pdf_res = client.get("/api/v1/reports/export/pdf?report_type=compliance&framework=nist_csf", headers=analyst_headers)
    assert comp_pdf_res.status_code == 200
    assert "application/pdf" in comp_pdf_res.headers["content-type"]


def test_legacy_backward_compatibility_endpoints(client: TestClient, analyst_headers: dict):
    csv_res = client.get("/api/v1/reports/incidents.csv", headers=analyst_headers)
    assert csv_res.status_code == 200

    pdf_res = client.get("/api/v1/reports/executive.pdf", headers=analyst_headers)
    assert pdf_res.status_code == 200


def test_report_schedule_crud_api(client: TestClient, admin_headers: dict):
    # 1. Create Schedule
    payload = {
        "name": "Daily Incident Digest",
        "report_type": "incidents",
        "frequency": "daily",
        "recipients": ["soc-lead@company.local"],
        "delivery_channel": "email",
    }
    create_res = client.post("/api/v1/reports/schedules", json=payload, headers=admin_headers)
    assert create_res.status_code == 201
    sched_id = create_res.json()["id"]

    # 2. List Schedules
    list_res = client.get("/api/v1/reports/schedules", headers=admin_headers)
    assert list_res.status_code == 200
    assert any(s["id"] == sched_id for s in list_res.json())

    # 3. Delete Schedule
    del_res = client.delete(f"/api/v1/reports/schedules/{sched_id}", headers=admin_headers)
    assert del_res.status_code == 204

    # 4. Delete missing schedule -> 404
    del_missing = client.delete("/api/v1/reports/schedules/missing-id", headers=admin_headers)
    assert del_missing.status_code == 404


def test_viewer_rbac_schedule_management_restriction(client: TestClient, viewer_headers: dict):
    # Viewer cannot create report schedule
    payload = {"name": "Viewer Schedule", "report_type": "incidents"}
    res = client.post("/api/v1/reports/schedules", json=payload, headers=viewer_headers)
    assert res.status_code == 403


def test_generate_report_metadata_api(client: TestClient, analyst_headers: dict):
    payload = {
        "report_type": "executive",
        "format": "pdf",
        "time_window_days": 14,
    }
    res = client.post("/api/v1/reports/generate", json=payload, headers=analyst_headers)
    assert res.status_code == 200
    assert "report_id" in res.json()
    assert res.json()["report_type"] == "executive"


def test_compliance_history_limit_parameter(client: TestClient, analyst_headers: dict):
    hist_res = client.get("/api/v1/reports/compliance-history?limit=5", headers=analyst_headers)
    assert hist_res.status_code == 200
    assert len(hist_res.json()) <= 5


def test_compliance_evaluation_by_viewer(client: TestClient, viewer_headers: dict):
    res = client.get("/api/v1/reports/compliance/soc2", headers=viewer_headers)
    assert res.status_code == 200
