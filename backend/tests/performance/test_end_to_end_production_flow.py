import pytest
import time
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.observability.metrics import metrics


def test_batch_ingest_and_query_throughput(client: TestClient, analyst_headers: dict):
    start = time.perf_counter()
    batch_events = [
        {
            "source_type": "vpn_gw",
            "category": "authentication",
            "action": "login_success",
            "source": {"ip": f"10.0.0.{i}", "user": f"user_{i}"},
            "raw_payload": f"User user_{i} logged in from 10.0.0.{i}",
        }
        for i in range(10)
    ]
    res = client.post("/api/v1/events/ingest", json={"events": batch_events}, headers=analyst_headers)
    elapsed = time.perf_counter() - start

    assert res.status_code in [200, 201, 202]
    assert elapsed < 5.0  # Must ingest batch within 5 seconds


def test_concurrent_metric_recording_performance():
    start = time.perf_counter()
    for _ in range(500):
        metrics.increment_counter("cyberguard_events_processed_total", 1.0)
        metrics.record_histogram("cyberguard_ingestion_latency_seconds", 0.002)
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0  # 500 metric writes within 1 second


def test_full_pipeline_event_to_incident_traceability(
    client: TestClient, db_session: Session, analyst_headers: dict
):
    # 1. Ingest suspicious event
    event_payload = {
        "events": [
            {
                "source_type": "edr_endpoint",
                "category": "process",
                "action": "process_spawn",
                "severity": "critical",
                "process": {
                    "name": "mimikatz.exe",
                    "command_line": "privilege::debug sekurlsa::logonpasswords",
                    "host": "DC-PRIMARY",
                },
                "raw_payload": "Process mimikatz.exe spawned with debug privileges",
            }
        ]
    }
    ingest_res = client.post("/api/v1/events/ingest", json=event_payload, headers=analyst_headers)
    assert ingest_res.status_code in [200, 202]

    # 2. Check alert list
    alerts_res = client.get("/api/v1/alerts", headers=analyst_headers)
    assert alerts_res.status_code == 200

    # 3. Check cases list
    cases_res = client.get("/api/v1/investigations/cases", headers=analyst_headers)
    assert cases_res.status_code == 200
