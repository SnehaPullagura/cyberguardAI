import pytest
from app.response.loop_guard import loop_guard


def test_loop_guard_recursion_depth():
    assert not loop_guard.is_loop_detected({}, current_depth=1)
    assert not loop_guard.is_loop_detected({}, current_depth=3)
    assert loop_guard.is_loop_detected({}, current_depth=4)


def test_loop_guard_provenance_detection():
    context_normal = {"event_details": {"action": "user_login"}}
    assert not loop_guard.is_loop_detected(context_normal)

    context_response_generated = {"event_details": {"response_generated": True}}
    assert loop_guard.is_loop_detected(context_response_generated)


def test_loop_guard_cooldown_locking():
    playbook_id = "PB-TEST-COOLDOWN"
    entity_key = "192.168.10.50"

    # First acquisition succeeds
    acquired = loop_guard.acquire_execution_lock(playbook_id, entity_key, cooldown_seconds=60)
    assert acquired is True

    # Immediate second acquisition fails due to active cooldown
    second_try = loop_guard.acquire_execution_lock(playbook_id, entity_key, cooldown_seconds=60)
    assert second_try is False

    # After releasing lock, it can be acquired again
    loop_guard.release_execution_lock(playbook_id, entity_key)
    third_try = loop_guard.acquire_execution_lock(playbook_id, entity_key, cooldown_seconds=60)
    assert third_try is True
    loop_guard.release_execution_lock(playbook_id, entity_key)
