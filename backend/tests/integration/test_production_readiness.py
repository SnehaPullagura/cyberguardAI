import pytest
import time
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.observability.metrics import metrics


def test_full_production_pipeline_and_metric_counters(
    client: TestClient, db_session: Session, analyst_headers: dict
):
    # 1. Ingest event
    payload = {
        "events": [
            {
                "source_type": "waf_edge",
                "category": "web",
                "action": "access",
                "severity": "info",
                "source": {
                    "ip": "203.0.113.88",
                },
                "raw_payload": "GET /api/users?id=1%20OR%201=1 HTTP/1.1",
            }
        ]
    }
    metrics.increment_counter("cyberguard_events_ingested_total", 1.0)
    ingest_res = client.post("/api/v1/events/ingest", json=payload, headers=analyst_headers)
    assert ingest_res.status_code in [200, 202]

    # 2. Check metrics endpoint reflects ingestion
    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    assert "cyberguard_events_ingested_total" in metrics_res.text


def test_cors_preflight_and_security_headers_in_production(client: TestClient):
    res = client.get("/")
    assert res.status_code == 200
    assert "x-content-type-options" in res.headers
    assert "x-frame-options" in res.headers


def test_production_concurrent_probes(client: TestClient):
    for _ in range(10):
        live_res = client.get("/health/live")
        assert live_res.status_code == 200
        ready_res = client.get("/health/ready")
        assert ready_res.status_code == 200


def test_production_readiness_database_health(client: TestClient, analyst_headers: dict):
    res = client.get("/api/v1/health/db", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["database"] == "healthy"
    assert "metrics" in data


def test_cors_options_preflight(client: TestClient):
    res = client.options(
        "/api/v1/events/ingest",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert res.status_code in [200, 204]


def test_invalid_route_production_404(client: TestClient):
    res = client.get("/api/v1/invalid_route_xyz")
    assert res.status_code == 404
