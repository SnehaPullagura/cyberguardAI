import pytest
from app.response.action_registry import action_registry


def test_action_registry_allowlist():
    """Verify ActionRegistry allowlists valid actions and rejects unregistered types."""
    assert action_registry.is_allowlisted("create_incident") is True
    assert action_registry.is_allowlisted("quarantine_simulation") is True
    assert action_registry.is_allowlisted("account_lock_simulation") is True

    # Verify arbitrary command execution attempts are rejected
    assert action_registry.is_allowlisted("execute_shell_command") is False
    assert action_registry.is_allowlisted("run_subprocess") is False
    assert action_registry.is_allowlisted("eval_python_code") is False


def test_action_handler_simulation_mode(db_session):
    """Verify action handlers return simulated results in simulation mode."""
    act_meta = action_registry.get_action("quarantine_simulation")
    assert act_meta is not None

    status_res, meta_res, err_res = act_meta.handler(db_session, {"source_ip": "192.168.1.50"}, "simulation")
    assert status_res == "simulated"
    assert meta_res["action"] == "quarantine_simulation"
    assert meta_res["host_ip"] == "192.168.1.50"
    assert err_res is None
