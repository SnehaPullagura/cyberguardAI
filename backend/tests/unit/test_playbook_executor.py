import pytest
import uuid
from datetime import datetime
from app.models.playbook import Playbook, PlaybookAction
from app.response.executor import playbook_executor
from app.response.enums import ResponseMode, ExecutionStatus


def test_playbook_executor_dry_run(db_session):
    playbook = Playbook(
        id=str(uuid.uuid4()),
        playbook_id="PB-UNIT-DRYRUN",
        name="Test Dry Run Playbook",
        enabled=True,
        response_mode="dry_run",
        severity_threshold="medium",
        risk_score_threshold=50.0,
        trigger_conditions=[{"field": "risk_score", "operator": "gte", "value": 50.0}],
        action_sequence=[
            {"action_type": "create_incident", "action_config": {"title": "Dry Run Incident"}},
            {"action_type": "notify_security_team", "action_config": {"channel": "test"}},
        ],
        cooldown_seconds=1,
    )
    db_session.add(playbook)
    db_session.commit()

    context = {
        "risk_score": 75.0,
        "severity": "high",
        "source_ip": "10.0.0.1",
        "alert_title": "Unit Test Alert",
    }

    execution = playbook_executor.execute_playbook(
        db=db_session,
        playbook=playbook,
        context=context,
    )

    assert execution is not None
    assert execution.status == ExecutionStatus.SIMULATED.value
    assert execution.mode == ResponseMode.DRY_RUN.value
    assert len(execution.action_executions) == 2
    assert execution.action_executions[0].verification_status == "verified"


def test_playbook_executor_approval_routing(db_session):
    playbook = Playbook(
        id=str(uuid.uuid4()),
        playbook_id="PB-UNIT-APPROVAL",
        name="Test Approval Playbook",
        enabled=True,
        response_mode="authorized_execution",
        severity_threshold="high",
        risk_score_threshold=80.0,
        trigger_conditions=[{"field": "risk_score", "operator": "gte", "value": 80.0}],
        action_sequence=[
            {"action_type": "network_block_simulation", "action_config": {"target_ip": "198.51.100.99"}, "risk_level": "critical"},
        ],
        approval_required=True,
        cooldown_seconds=1,
    )
    db_session.add(playbook)
    db_session.commit()

    context = {
        "risk_score": 90.0,
        "severity": "critical",
        "source_ip": "198.51.100.99",
        "alert_title": "Critical C2 Traffic",
    }

    execution = playbook_executor.execute_playbook(
        db=db_session,
        playbook=playbook,
        context=context,
    )

    assert execution is not None
    assert execution.status == ExecutionStatus.PENDING_APPROVAL.value
    assert len(execution.approval_requests) == 1
    assert execution.approval_requests[0].decision == "pending"
