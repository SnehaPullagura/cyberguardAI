import pytest
from app.models.user import User
from app.security.auth import create_access_token
from app.security.password import get_password_hash


def test_valid_login(client, db_session):
    user = User(
        username="secuser1",
        email="secuser1@cyberguard.ai",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "secuser1", "password": "Password123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_invalid_password_login(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


def test_missing_auth_header_access_rejected(client):
    response = client.get("/api/v1/alerts")
    assert response.status_code == 401


def test_invalid_jwt_token_rejected(client):
    response = client.get(
        "/api/v1/alerts", headers={"Authorization": "Bearer invalid.jwt.token"}
    )
    assert response.status_code == 401
