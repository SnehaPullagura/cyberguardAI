def test_security_headers_present(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "X-Correlation-ID" in response.headers


def test_correlation_id_propagation(client):
    custom_id = "test-correlation-uuid-12345"
    response = client.get("/", headers={"X-Correlation-ID": custom_id})
    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"] == custom_id


def test_login_rate_limiting(client):
    # Perform 11 login requests in quick succession
    responses = []
    for _ in range(11):
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "WrongPassword!"},
        )
        responses.append(resp)

    # 11th request must be rate limited with HTTP 429
    assert responses[-1].status_code == 429
    assert "Too many requests" in responses[-1].json()["detail"]
