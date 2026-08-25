def test_db_health_endpoint(client, admin_headers):
    response = client.get("/api/v1/health/db", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["database"] == "healthy"
    assert "metrics" in data
    assert "total_events" in data["metrics"]


def test_keyset_pagination_api_header(client, admin_headers):
    response = client.get("/api/v1/events?limit=2", headers=admin_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
