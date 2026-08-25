import pytest
from app.models import User, Role
from app.security.auth import create_access_token
from app.security.password import get_password_hash


@pytest.fixture
def viewer_headers(db_session):
    role = db_session.query(Role).filter(Role.name == "viewer").first()
    if not role:
        role = Role(name="viewer", description="Viewer")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)

    user = db_session.query(User).filter(User.username == "viewer_user").first()
    if not user:
        user = User(
            username="viewer_user",
            email="viewer@cyberguard.ai",
            hashed_password=get_password_hash("Password123!"),
            role_id=role.id,
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    token = create_access_token(subject=user.id)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers(db_session):
    role = db_session.query(Role).filter(Role.name == "security_analyst").first()
    if not role:
        role = Role(name="security_analyst", description="Analyst")
        db_session.add(role)
        db_session.commit()
        db_session.refresh(role)

    user = db_session.query(User).filter(User.username == "analyst_user").first()
    if not user:
        user = User(
            username="analyst_user",
            email="analyst@cyberguard.ai",
            hashed_password=get_password_hash("Password123!"),
            role_id=role.id,
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    token = create_access_token(subject=user.id)
    return {"Authorization": f"Bearer {token}"}


def test_viewer_can_read_alerts(client, viewer_headers):
    response = client.get("/api/v1/alerts", headers=viewer_headers)
    assert response.status_code == 200


def test_viewer_cannot_update_alert_status(client, viewer_headers):
    response = client.patch(
        "/api/v1/alerts/dummy-id/status",
        json={"status": "resolved"},
        headers=viewer_headers,
    )
    assert response.status_code == 403
    assert "Permission denied" in response.json()["detail"]


def test_viewer_cannot_create_rule(client, viewer_headers):
    payload = {
        "rule_id": "RULE-TEST-001",
        "title": "Test Rule",
        "description": "Test",
        "severity": "high",
        "category": "process",
        "condition": {},
    }
    response = client.post("/api/v1/rules", json=payload, headers=viewer_headers)
    assert response.status_code == 403


def test_viewer_cannot_register_user(client, viewer_headers):
    payload = {
        "username": "newuser",
        "email": "newuser@test.com",
        "password": "Password123!",
    }
    response = client.post("/api/v1/auth/register", json=payload, headers=viewer_headers)
    assert response.status_code == 403


def test_analyst_cannot_register_user(client, analyst_headers):
    payload = {
        "username": "newuser2",
        "email": "newuser2@test.com",
        "password": "Password123!",
    }
    response = client.post("/api/v1/auth/register", json=payload, headers=analyst_headers)
    assert response.status_code == 403


def test_admin_can_register_user(client, admin_headers):
    payload = {
        "username": "newuser3",
        "email": "newuser3@test.com",
        "password": "Password123!",
    }
    response = client.post("/api/v1/auth/register", json=payload, headers=admin_headers)
    assert response.status_code == 201
    assert response.json()["username"] == "newuser3"
