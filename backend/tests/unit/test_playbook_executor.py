import uuid
import pytest
from app.models.playbook import Playbook
from app.response.executor import playbook_executor
from app.response.trigger_evaluator import trigger_evaluator


def test_trigger_evaluator_operators():
    """Verify safe structured condition evaluation without eval/exec."""
    context = {"risk_score": 85.0, "severity": "high", "category": "authentication"}

    cond_gte = {"field": "risk_score", "operator": "gte", "value": 80.0}
    assert trigger_evaluator.evaluate_condition(cond_gte, context) is True

    cond_eq = {"field": "category", "operator": "eq", "value": "authentication"}
    assert trigger_evaluator.evaluate_condition(cond_eq, context) is True

    cond_fail = {"field": "risk_score", "operator": "gte", "value": 95.0}
    assert trigger_evaluator.evaluate_condition(cond_fail, context) is False


def test_playbook_executor_dry_run_execution(db_session):
    """Verify playbook execution engine runs playbooks in simulation mode."""
    pb = Playbook(
        id=str(uuid.uuid4()),
        playbook_id=f"PB-TEST-{uuid.uuid4().hex[:6]}",
        name="Test Playbook",
        enabled=True,
        severity_threshold="high",
        risk_score_threshold=70.0,
        trigger_conditions=[{"field": "risk_score", "operator": "gte", "value": 70.0}],
        action_sequence=["create_incident", "notify_security_team"],
        approval_required=False,
    )
    db_session.add(pb)
    db_session.commit()

    context = {"risk_score": 85.0, "source_entity": "192.168.1.10"}
    executions = playbook_executor.evaluate_and_execute_playbooks(db_session, context)

    assert len(executions) >= 1
    exec_rec = executions[0]
    assert exec_rec.status == "simulated"
    assert exec_rec.mode == "simulation"
