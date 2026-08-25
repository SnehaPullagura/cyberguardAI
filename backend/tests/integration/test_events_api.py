from app.queue.redis_queue import redis_queue
from app.schemas.event import SecurityEventCreate
from app.pipeline.processor import process_single_security_event


def test_bulk_event_ingestion_and_search(client, admin_headers, db_session):
    payload = {
        "events": [
            {
                "raw_payload": "Failed password for root from 198.51.100.42 port 443 ssh2",
                "source_type": "syslog",
                "category": "authentication",
                "action": "login_failed",
                "severity": "high",
            },
            {
                "raw_payload": "Accepted password for analyst from 10.0.0.15 port 22 ssh2",
                "source_type": "syslog",
                "category": "authentication",
                "action": "login_success",
                "severity": "info",
            },
        ]
    }

    ingest_resp = client.post("/api/v1/events/ingest", json=payload)
    assert ingest_resp.status_code == 202
    ingest_data = ingest_resp.json()
    assert ingest_data["total_received"] == 2
    assert ingest_data["total_ingested"] == 2

    # Process enqueued events from queue for search test
    while True:
        item = redis_queue.pop_event(timeout=0)
        if not item:
            break
        ev_schema = SecurityEventCreate.model_validate(item)
        process_single_security_event(db_session, ev_schema)

    # Query events via API
    search_resp = client.get("/api/v1/events", headers=admin_headers)
    assert search_resp.status_code == 200
    events = search_resp.json()
    assert len(events) >= 2


def test_dashboard_summary_api(client, admin_headers):
    response = client.get("/api/v1/dashboard/summary", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_events_processed" in data
    assert "open_alerts" in data
    assert "events_trend" in data
