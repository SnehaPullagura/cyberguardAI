import pytest
from fastapi.testclient import TestClient


def test_health_live_probe(client: TestClient):
    res = client.get("/health/live")
    assert res.status_code == 200
    assert res.json()["status"] == "alive"


def test_api_v1_health_live_probe(client: TestClient):
    res = client.get("/api/v1/health/live")
    assert res.status_code == 200
    assert res.json()["status"] == "alive"


def test_health_ready_probe(client: TestClient):
    res = client.get("/health/ready")
    assert res.status_code == 200
    assert "ready" in res.text


def test_api_v1_health_ready_probe(client: TestClient):
    res = client.get("/api/v1/health/ready")
    assert res.status_code == 200
    assert "ready" in res.text


def test_prometheus_metrics_endpoint(client: TestClient):
    res = client.get("/metrics")
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]
    assert "cyberguard_" in res.text


def test_root_service_status(client: TestClient):
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["status"] == "online"


def test_unauthenticated_probes_accessibility(client: TestClient):
    # Probes MUST be publicly reachable without JWT for Kubernetes / load balancers
    res1 = client.get("/health/live")
    assert res1.status_code == 200
    res2 = client.get("/health/ready")
    assert res2.status_code == 200
    res3 = client.get("/metrics")
    assert res3.status_code == 200


def test_metrics_content_type_version(client: TestClient):
    res = client.get("/metrics")
    assert "version=0.0.4" in res.headers["content-type"]


def test_openapi_schema_endpoint(client: TestClient):
    res = client.get("/api/v1/openapi.json")
    assert res.status_code == 200
    assert "paths" in res.json()


def test_docs_endpoint(client: TestClient):
    res = client.get("/api/v1/docs")
    assert res.status_code == 200
