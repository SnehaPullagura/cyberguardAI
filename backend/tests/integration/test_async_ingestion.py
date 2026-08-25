import uuid
import unittest.mock as mock
from app.schemas.event import SecurityEventCreate, EndpointSchema
from app.workers.event_worker import EventWorkerProcess
from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.queue.redis_queue import redis_queue


def test_async_ingest_api_202(client):
    payload = {
        "events": [
            {
                "raw_payload": "Failed password for root from 203.0.113.99 port 54321 ssh2",
                "source_type": "syslog",
                "category": "authentication",
                "action": "login_failed",
                "severity": "high",
            }
        ]
    }

    response = client.post("/api/v1/events/ingest", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["total_received"] == 1
    assert data["total_ingested"] == 1


def test_ingestion_health_endpoint(client):
    response = client.get("/api/v1/events/health")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "CyberGuard Ingestion Queue"
    assert "queue_health" in data


def test_worker_end_to_end_event_processing(db_session):
    event_id = str(uuid.uuid4())
    event_dict = {
        "event_id": event_id,
        "source_type": "syslog",
        "category": "authentication",
        "action": "login_failed",
        "severity": "high",
        "source": {"ip": "198.51.100.42", "user": "testadmin"},
        "raw_payload": "Failed password for testadmin from 198.51.100.42 port 22 ssh2",
        "retry_count": 0,
    }

    worker = EventWorkerProcess()
    success = worker.process_event_dict(event_dict, db=db_session)
    assert success is True

    # Verify event persisted to DB
    db_event = db_session.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
    assert db_event is not None
    assert db_event.source_ip == "198.51.100.42"

    # Verify Threat IoC match alert generated (since 198.51.100.42 is seeded IoC)
    alert = db_session.query(Alert).filter(Alert.source_entity == "198.51.100.42").first()
    assert alert is not None


def test_worker_failure_retry_and_dlq():
    """Verify processing failure triggers retry increment and DLQ routing on exhaustion."""
    worker = EventWorkerProcess()
    invalid_event_dict = {
        "event_id": f"invalid-{uuid.uuid4().hex[:6]}",
        "source_type": "syslog",
        "category": "authentication",
        "action": "login_failed",
        "severity": "invalid_severity_type_error",
        "retry_count": 0,
    }

    # First attempt (retry_count 0 -> 1)
    with mock.patch("time.sleep"):
        success = worker.process_event_dict(invalid_event_dict)
        assert success is False
        assert invalid_event_dict["retry_count"] == 1

    # Retry exhaustion attempt (retry_count 3 -> DLQ)
    exhausted_event_dict = {
        "event_id": f"exhausted-{uuid.uuid4().hex[:6]}",
        "source_type": "syslog",
        "category": "authentication",
        "action": "login_failed",
        "severity": "invalid_severity_type_error",
        "retry_count": 3,
    }

    with mock.patch.object(redis_queue, "push_dlq") as mock_dlq:
        success = worker.process_event_dict(exhausted_event_dict)
        assert success is False
        assert mock_dlq.called is True


def test_worker_graceful_shutdown():
    """Verify worker signal handler sets running flag to False."""
    worker = EventWorkerProcess()
    assert worker.running is True
    worker._handle_shutdown(15, None)
    assert worker.running is False
