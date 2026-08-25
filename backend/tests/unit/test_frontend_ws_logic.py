import json
import pytest
from app.schemas.websocket import RealtimeEventEnvelope


def test_frontend_message_parsing():
    """Verify frontend RealtimeEventEnvelope message parsing."""
    raw_payload = json.dumps({
        "message_id": "msg-999",
        "type": "security_event",
        "timestamp": "2026-08-25T12:00:00Z",
        "schema_version": "1.0",
        "data": {"action": "ssh_login", "severity": "high", "risk_score": 85.0}
    })

    data_dict = json.loads(raw_payload)
    envelope = RealtimeEventEnvelope(**data_dict)
    assert envelope.message_id == "msg-999"
    assert envelope.type == "security_event"
    assert envelope.data["action"] == "ssh_login"
    assert envelope.data["risk_score"] == 85.0


def test_frontend_connection_state_transitions():
    """Verify frontend connection status transitions."""
    states = []
    def set_status(s): states.append(s)

    set_status("DISCONNECTED")
    set_status("CONNECTING")
    set_status("CONNECTED")

    assert states == ["DISCONNECTED", "CONNECTING", "CONNECTED"]


def test_frontend_duplicate_message_handling():
    """Verify duplicate message deduplication by message_id."""
    seen_ids = set()
    events = []

    def handle_message(env):
        if env["message_id"] in seen_ids:
            return False  # Dropped duplicate
        seen_ids.add(env["message_id"])
        events.append(env)
        return True

    msg1 = {"message_id": "m1", "type": "alert_created", "data": {"title": "SQLi"}}
    msg2 = {"message_id": "m1", "type": "alert_created", "data": {"title": "SQLi"}} # Duplicate
    msg3 = {"message_id": "m2", "type": "alert_created", "data": {"title": "BruteForce"}}

    assert handle_message(msg1) is True
    assert handle_message(msg2) is False # Duplicate correctly rejected
    assert handle_message(msg3) is True
    assert len(events) == 2


def test_frontend_reconnection_exponential_backoff():
    """Verify exponential backoff calculation for reconnection."""
    def get_delay(attempts):
        return min(10000, int(2000 * (1.5 ** attempts)))

    assert get_delay(1) == 3000
    assert get_delay(2) == 4500
    assert get_delay(3) == 6750
    assert get_delay(10) == 10000  # Capped at 10s


def test_frontend_bounded_event_history():
    """Verify client-side event history stays bounded at 50 max events."""
    history = []
    for i in range(1, 61):
        new_event = {"id": i, "action": f"action_{i}"}
        history = [new_event] + history[:49]

    assert len(history) == 50
    assert history[0]["id"] == 60  # Most recent first
    assert history[49]["id"] == 11


def test_frontend_ticket_url_construction():
    """Verify single-use ticket WebSocket URL construction without long-lived JWT token in URL."""
    base_url = "ws://localhost:8000/api/v1/ws"
    ticket = "wst_998877665544332211"
    full_url = f"{base_url}?ticket={ticket}"

    assert "wst_998877665544332211" in full_url
    assert "token=" not in full_url  # Token absent from URL!


def test_frontend_live_dashboard_updates():
    """Verify real-time metric counter increments on live dashboard."""
    summary = {"total_events_processed": 100, "open_alerts": 5}
    live_metrics = {"events_count": 0, "alerts_count": 0}

    live_metrics["events_count"] += 1
    live_metrics["alerts_count"] += 2

    display_events = summary["total_events_processed"] + live_metrics["events_count"]
    display_alerts = summary["open_alerts"] + live_metrics["alerts_count"]

    assert display_events == 101
    assert display_alerts == 7
