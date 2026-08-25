import uuid
from datetime import datetime, timedelta
from app.models.event import SecurityEvent
from app.repositories.event_repository import event_repository


def test_save_event_and_deduplication(db_session):
    event_id = str(uuid.uuid4())
    event = SecurityEvent(
        event_id=event_id,
        timestamp=datetime.utcnow(),
        source_type="syslog",
        category="authentication",
        action="login_failed",
        severity="high",
    )

    persisted, is_new = event_repository.save_event(db_session, event)
    assert is_new is True
    assert persisted.event_id == event_id

    # Second attempt with same event_id must be deduplicated
    duplicate_event = SecurityEvent(
        event_id=event_id,
        timestamp=datetime.utcnow(),
        source_type="syslog",
        category="authentication",
        action="login_failed",
        severity="high",
    )
    dup_persisted, is_new_dup = event_repository.save_event(db_session, duplicate_event)
    assert is_new_dup is False
    assert dup_persisted.id == persisted.id


def test_keyset_pagination(db_session):
    now = datetime.utcnow()
    for i in range(10):
        ev = SecurityEvent(
            event_id=f"evt-keyset-{i}",
            timestamp=now - timedelta(minutes=i),
            source_type="syslog",
            category="network",
            action="connection",
            severity="info",
        )
        event_repository.save_event(db_session, ev)

    db_session.commit()

    page1, next_cursor = event_repository.search_events_keyset(db_session, limit=5)
    assert len(page1) == 5
    assert next_cursor is not None

    page2, next_cursor2 = event_repository.search_events_keyset(db_session, cursor=next_cursor, limit=5)
    assert len(page2) >= 1
    assert page1[0].event_id != page2[0].event_id


def test_retention_pruning(db_session):
    old_event = SecurityEvent(
        event_id=f"old-evt-{uuid.uuid4().hex[:6]}",
        timestamp=datetime.utcnow() - timedelta(days=100),
        source_type="syslog",
        category="system",
        action="test",
        severity="low",
    )
    event_repository.save_event(db_session, old_event)
    db_session.commit()

    deleted_count = event_repository.prune_expired_events(db_session, retention_days=90)
    assert deleted_count >= 1
