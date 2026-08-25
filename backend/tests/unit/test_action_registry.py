import pytest
from app.response.action_registry import action_registry
from app.response.safety_validator import action_safety_validator
from app.response.enums import ResponseMode, RiskLevel
from app.security.rbac import Permission


def test_registered_allowlisted_actions():
    actions = action_registry.list_actions()
    action_types = [a["action_type"] for a in actions]
    
    assert "create_incident" in action_types
    assert "update_incident" in action_types
    assert "notify_security_team" in action_types
    assert "enrich_event" in action_types
    assert "quarantine_simulation" in action_types
    assert "account_lock_simulation" in action_types
    assert "network_block_simulation" in action_types


def test_unregistered_action_rejected():
    assert not action_registry.is_registered("arbitrary_bash_command")
    
    res = action_safety_validator.validate_action_safety(
        action_type="arbitrary_bash_command",
        action_config={"cmd": "rm -rf /"},
        requested_mode=ResponseMode.AUTHORIZED_EXECUTION,
    )
    assert not res.is_safe
    assert "NOT in the allowlisted Action Registry" in res.reason


def test_dangerous_config_keys_rejected():
    res = action_safety_validator.validate_action_safety(
        action_type="create_incident",
        action_config={"title": "Test", "command": "whoami"},
        requested_mode=ResponseMode.DRY_RUN,
    )
    assert not res.is_safe
    assert "Dangerous parameter" in res.reason


def test_high_risk_action_requires_approval():
    res = action_safety_validator.validate_action_safety(
        action_type="network_block_simulation",
        action_config={"target_ip": "192.0.2.1"},
        requested_mode=ResponseMode.AUTHORIZED_EXECUTION,
    )
    assert res.is_safe
    assert res.requires_approval
    assert res.enforced_mode == ResponseMode.APPROVAL_REQUIRED


def test_simulation_adapters_safe_output(db_session):
    # Test quarantine simulation
    q_def = action_registry.get("quarantine_simulation")
    res = q_def.execution_handler(
        db=db_session,
        config={"target_host": "test-workstation-9"},
        context={},
        mode=ResponseMode.SIMULATION,
    )
    assert res["success"] is True
    assert res["simulated"] is True
    assert res["target_host"] == "test-workstation-9"
    assert q_def.verification_handler(res, {}) is True

    # Test account lock simulation
    l_def = action_registry.get("account_lock_simulation")
    res_l = l_def.execution_handler(
        db=db_session,
        config={"target_user": "test_user_alice"},
        context={},
        mode=ResponseMode.SIMULATION,
    )
    assert res_l["success"] is True
    assert res_l["simulated"] is True
    assert res_l["target_user"] == "test_user_alice"
    assert l_def.verification_handler(res_l, {}) is True
