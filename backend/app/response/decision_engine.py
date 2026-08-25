import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.playbook import Playbook
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.response_execution import ResponseExecution
from app.models.user import User
from app.response.enums import ResponseMode
from app.response.executor import playbook_executor
from app.response.trigger_evaluator import trigger_evaluator
from app.response.policy_engine import policy_engine
from app.response.safety_validator import action_safety_validator

logger = logging.getLogger(__name__)


class ResponseDecisionEngine:
    """Orchestrates playbook selection and response decision logic for incoming alerts and incidents."""

    def evaluate_for_alert(self, db: Session, alert: Alert, user: Optional[User] = None) -> List[ResponseExecution]:
        """Evaluates active playbooks against a newly created or updated Alert."""
        active_playbooks = db.query(Playbook).filter(Playbook.enabled == True).all()
        if not active_playbooks:
            return []

        context = {
            "alert_id": alert.id,
            "alert_code": alert.alert_id,
            "alert_title": alert.title,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "source_entity": alert.source_entity,
            "source_ip": alert.source_entity,
            "detection_source": alert.detection_source,
            "event_details": alert.event_details or {},
            "execution_depth": 1,
        }

        executions = []
        for pb in active_playbooks:
            try:
                exec_result = playbook_executor.execute_playbook(
                    db=db,
                    playbook=pb,
                    context=context,
                    user=user,
                )
                if exec_result:
                    executions.append(exec_result)
            except Exception as e:
                logger.exception(f"[DECISION ENGINE] Error executing playbook '{pb.name}': {e}")

        return executions

    def evaluate_for_incident(self, db: Session, incident: Incident, user: Optional[User] = None) -> List[ResponseExecution]:
        """Evaluates active playbooks against an Incident."""
        active_playbooks = db.query(Playbook).filter(Playbook.enabled == True).all()
        if not active_playbooks:
            return []

        context = {
            "incident_id": incident.id,
            "incident_code": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "status": incident.status,
            "execution_depth": 1,
        }

        executions = []
        for pb in active_playbooks:
            try:
                exec_result = playbook_executor.execute_playbook(
                    db=db,
                    playbook=pb,
                    context=context,
                    user=user,
                )
                if exec_result:
                    executions.append(exec_result)
            except Exception as e:
                logger.exception(f"[DECISION ENGINE] Error evaluating playbook '{pb.name}' on incident: {e}")

        return executions

    def simulate_playbook_test(self, db: Session, playbook: Playbook, test_context: Dict[str, Any]) -> Dict[str, Any]:
        """Executes a safe dry-run / simulation test for administrators to validate playbooks."""
        trigger_matched = trigger_evaluator.evaluate_all(playbook.trigger_conditions or [], test_context)
        policy_res = policy_engine.evaluate_playbook_policy(playbook, test_context)

        simulated_actions = []
        for action_item in playbook.action_sequence or []:
            action_type = action_item.get("action_type") if isinstance(action_item, dict) else str(action_item)
            action_cfg = action_item.get("action_config", {}) if isinstance(action_item, dict) else {}
            safety = action_safety_validator.validate_action_safety(
                action_type=action_type,
                action_config=action_cfg,
                requested_mode=ResponseMode.SIMULATION,
            )
            simulated_actions.append({
                "action_type": action_type,
                "is_safe": safety.is_safe,
                "requires_approval": safety.requires_approval,
                "enforced_mode": safety.enforced_mode.value if safety.enforced_mode else "simulation",
                "reason": safety.reason,
            })

        return {
            "playbook_id": playbook.playbook_id,
            "playbook_name": playbook.name,
            "trigger_matched": trigger_matched,
            "matched_conditions": playbook.trigger_conditions or [],
            "simulated_actions": simulated_actions,
            "policy_evaluation": {
                "allowed": policy_res.allowed,
                "reason": policy_res.reason,
                "requires_approval": policy_res.requires_approval,
                "mode": policy_res.mode.value,
            },
            "approval_required": playbook.approval_required or any(a["requires_approval"] for a in simulated_actions),
            "execution_mode": ResponseMode.DRY_RUN.value,
            "safety_summary": "All actions validated against safe allowlisted adapters with DRY_RUN default.",
        }


response_decision_engine = ResponseDecisionEngine()
