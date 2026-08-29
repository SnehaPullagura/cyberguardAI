import uuid
from app.schemas.event import SecurityEventCreate, EndpointSchema
from app.queue.redis_queue import redis_queue


def test_queue_publish_and_pop():
    queue = redis_queue
    queue.reset_state()
    event_id = str(uuid.uuid4())
    event = SecurityEventCreate(
        event_id=event_id,
        source_type="syslog",
        category="authentication",
        action="login_failed",
        severity="high",
        source=EndpointSchema(ip="1.2.3.4", user="admin"),
    )

    enqueued_count, enqueued_ids = queue.publish_events([event])
    assert enqueued_count == 1
    assert event_id in enqueued_ids

    popped = queue.pop_event(timeout=1)
    assert popped is not None
    assert popped["event_id"] == event_id
    assert popped["action"] == "login_failed"
    assert popped["retry_count"] == 0


def test_queue_idempotency_duplicate_prevention():
    queue = redis_queue
    queue.reset_state()
    event_id = f"unique-id-{uuid.uuid4().hex}"

    # First attempt should not be duplicate
    assert queue.is_duplicate_and_mark(event_id) is False

    # Second attempt must be flagged as duplicate
    assert queue.is_duplicate_and_mark(event_id) is True

    # Publishing duplicate event must skip enqueuing
    event = SecurityEventCreate(
        event_id=event_id,
        source_type="syslog",
        category="system",
        action="test",
        severity="info",
    )
    count, ids = queue.publish_events([event])
    assert count == 0
    assert len(ids) == 0


def test_queue_dlq_routing():
    queue = redis_queue
    queue.reset_state()
    failed_event = {"event_id": "failed-123", "retry_count": 3, "action": "crash"}

    queue.push_dlq(failed_event, error_reason="Max retries exceeded")
    assert failed_event["dlq_reason"] == "Max retries exceeded"


def test_queue_health_check():
    queue = redis_queue
    health = queue.get_health()

    assert "status" in health
    assert "mode" in health
    assert "queue_length" in health
