from app.services.audit_service import audit_service
from app.models.audit import AuditLog


def test_audit_log_credential_redaction(db_session):
    sensitive_details = {
        "username": "target_user",
        "password": "SuperSecretPassword123!",
        "access_token": "secret.jwt.token",
        "nested": {"refresh_token": "refresh.secret.token"},
    }

    log_entry = audit_service.log_action(
        db=db_session,
        action="TEST_SECURITY_ACTION",
        resource="test",
        username="admin",
        details=sensitive_details,
    )

    assert log_entry.details["password"] == "[REDACTED]"
    assert log_entry.details["access_token"] == "[REDACTED]"
    assert log_entry.details["nested"]["refresh_token"] == "[REDACTED]"
    assert log_entry.details["username"] == "target_user"


def test_audit_logs_rbac_protection(client, admin_headers):
    response = client.get("/api/v1/audit", headers=admin_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
