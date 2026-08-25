import uuid
import time
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.playbook import Playbook
from app.models.response_execution import ResponseExecution, ResponseActionExecution
from app.models.approval import ResponseApprovalRequest
from app.response.action_registry import action_registry
from app.response.trigger_evaluator import trigger_evaluator
from app.response.cooldown import cooldown_manager
from app.response.publisher import publish_response_event
from app.services.audit_service import audit_service

logger = logging.getLogger(__name__)


class PlaybookExecutor:
    """Centralized response execution engine handling playbook evaluation, approval gates, dry-run/simulation execution, and verification."""

    def evaluate_and_execute_playbooks(
        self,
        db: Session,
        context: Dict[str, Any],
        user_id: Optional[str] = None,
    ) -> List[ResponseExecution]:
        """Evaluate active playbooks against incoming alert/incident context and execute matching workflows."""
        executions = []
        enabled_playbooks = db.query(Playbook).filter(Playbook.enabled == True).all()

        for pb in enabled_playbooks:
            # 1. Evaluate Risk Thresholds
            risk_score = context.get("risk_score", 0.0)
            if risk_score < pb.risk_score_threshold:
                continue

            # 2. Evaluate Structured Trigger Conditions
            if not trigger_evaluator.evaluate_all_conditions(pb.trigger_conditions, context):
                continue

            # 3. Check Cooldown & Idempotency Lock
            entity_id = context.get("source_entity") or context.get("event_id") or "global"
            if not cooldown_manager.check_and_acquire_lock(pb.id, entity_id, pb.cooldown_seconds):
                logger.info(f"Playbook {pb.name} suppressed by active cooldown.")
                continue

            # 4. Check Risk Level and Approval Requirements
            requires_approval = pb.approval_required
            action_list = pb.action_sequence or ["create_incident", "notify_security_team"]

            for act_type in action_list:
                act_meta = action_registry.get_action(act_type)
                if act_meta and act_meta.risk_level in ["high", "critical"]:
                    requires_approval = True

            exec_id = f"exec-{uuid.uuid4().hex[:8]}"
            started_at = datetime.utcnow()

            if requires_approval:
                # Gate execution -> PENDING_APPROVAL
                execution = ResponseExecution(
                    id=str(uuid.uuid4()),
                    execution_id=exec_id,
                    playbook_id=pb.id,
                    alert_id=context.get("alert_id"),
                    incident_id=context.get("incident_id"),
                    status="pending_approval",
                    mode="approval_required",
                    started_at=started_at,
                    requested_by_id=user_id,
                    verification_status="pending",
                )
                db.add(execution)
                db.flush()

                approval_req = ResponseApprovalRequest(
                    id=str(uuid.uuid4()),
                    approval_id=f"appr-{uuid.uuid4().hex[:8]}",
                    execution_id=execution.id,
                    playbook_id=pb.id,
                    incident_id=context.get("incident_id"),
                    requested_by_id=user_id,
                    status="pending",
                    risk_level="high",
                    reason=f"Playbook '{pb.name}' requires authorization for high-impact actions.",
                    requested_at=started_at,
                )
                db.add(approval_req)
                db.commit()

                # Audit & WebSocket event
                audit_service.log_action(
                    db=db,
                    action="PLAYBOOK_APPROVAL_REQUESTED",
                    resource="playbooks",
                    user_id=user_id,
                    status="PENDING",
                    details={"playbook_id": pb.playbook_id, "name": pb.name},
                )
                publish_response_event("approval_requested", {
                    "execution_id": execution.execution_id,
                    "playbook_name": pb.name,
                    "approval_id": approval_req.approval_id,
                })
                executions.append(execution)
            else:
                # Immediate Dry-Run / Simulation Execution
                execution = self.execute_playbook_actions(
                    db=db,
                    playbook=pb,
                    context=context,
                    execution_id=exec_id,
                    mode="simulation",
                    requested_by_id=user_id,
                )
                executions.append(execution)

        return executions

    def execute_playbook_actions(
        self,
        db: Session,
        playbook: Playbook,
        context: Dict[str, Any],
        execution_id: str,
        mode: str = "simulation",
        requested_by_id: Optional[str] = None,
        approved_by_id: Optional[str] = None,
    ) -> ResponseExecution:
        """Execute allowlisted actions sequentially for a playbook."""
        start_time = time.time()
        started_at = datetime.utcnow()

        execution = ResponseExecution(
            id=str(uuid.uuid4()),
            execution_id=execution_id,
            playbook_id=playbook.id,
            alert_id=context.get("alert_id"),
            incident_id=context.get("incident_id"),
            status="running",
            mode=mode,
            started_at=started_at,
            requested_by_id=requested_by_id,
            approved_by_id=approved_by_id,
        )
        db.add(execution)
        db.flush()

        publish_response_event("response_started", {
            "execution_id": execution.execution_id,
            "playbook_name": playbook.name,
            "mode": mode,
        })

        action_sequence = playbook.action_sequence or ["create_incident", "notify_security_team"]
        all_passed = True

        for act_type in action_sequence:
            act_meta = action_registry.get_action(act_type)
            if not act_meta:
                logger.warning(f"Unregistered action type '{act_type}' skipped.")
                continue

            act_start = time.time()
            act_started_at = datetime.utcnow()

            # Execute allowlisted action handler
            status_res, meta_res, err_res = act_meta.handler(db, context, mode)
            act_duration = (time.time() - act_start) * 1000.0

            action_exec = ResponseActionExecution(
                id=str(uuid.uuid4()),
                execution_id=execution.id,
                action_type=act_type,
                status=status_res,
                risk_level=act_meta.risk_level,
                started_at=act_started_at,
                completed_at=datetime.utcnow(),
                duration_ms=act_duration,
                verification_status="verified" if status_res in ["success", "simulated"] else "failed",
                output=meta_res,
                error=err_res,
            )
            db.add(action_exec)

            if status_res == "failed":
                all_passed = False

        duration_ms = (time.time() - start_time) * 1000.0
        execution.completed_at = datetime.utcnow()
        execution.duration_ms = duration_ms
        execution.status = "simulated" if mode == "simulation" else "success" if all_passed else "failed"
        execution.verification_status = "verified" if all_passed else "failed"
        execution.result_metadata = {"actions_executed": len(action_sequence), "all_passed": all_passed}

        db.commit()

        audit_service.log_action(
            db=db,
            action="PLAYBOOK_EXECUTED",
            resource="playbooks",
            user_id=requested_by_id or approved_by_id,
            status="SUCCESS" if all_passed else "FAILED",
            details={"playbook_id": playbook.playbook_id, "mode": mode, "status": execution.status},
        )
        publish_response_event("response_completed", {
            "execution_id": execution.execution_id,
            "playbook_name": playbook.name,
            "status": execution.status,
        })

        return execution


playbook_executor = PlaybookExecutor()
