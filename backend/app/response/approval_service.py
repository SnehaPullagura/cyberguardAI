import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.approval import ResponseApproval
from app.models.response_execution import ResponseExecution
from app.models.user import User
from app.response.enums import ExecutionStatus, ApprovalDecision, ResponseMode
from app.response.policy_engine import policy_engine
from app.services.audit_service import audit_service
from app.schemas.websocket import RealtimeEventEnvelope
from app.websockets.pubsub import publish_realtime_event

logger = logging.getLogger(__name__)


class ApprovalService:
    """Manages the lifecycle of human-in-the-loop response approval requests."""

    APPROVAL_TTL_HOURS = 24

    def create_approval_request(
        self,
        db: Session,
        execution: ResponseExecution,
        action_type: str,
        risk_level: str,
        requested_by_id: Optional[str] = None,
    ) -> ResponseApproval:
        """Creates a pending approval request and notifies SOC analysts via WebSockets."""
        approval_id = f"APPR-{uuid.uuid4().hex[:8].upper()}"
        approval = ResponseApproval(
            id=str(uuid.uuid4()),
            approval_id=approval_id,
            execution_id=execution.id,
            incident_id=execution.incident_id,
            playbook_id=execution.playbook_id,
            action_type=action_type,
            risk_level=risk_level,
            requested_by_id=requested_by_id,
            requested_at=datetime.utcnow(),
            decision=ApprovalDecision.PENDING.value,
            expires_at=datetime.utcnow() + timedelta(hours=self.APPROVAL_TTL_HOURS),
        )
        db.add(approval)
        db.commit()
        db.refresh(approval)

        # Audit approval creation
        audit_service.log_action(
            db=db,
            action="RESPONSE_APPROVAL_REQUESTED",
            resource=f"approval/{approval.approval_id}",
            user_id=requested_by_id,
            username=execution.triggered_by,
            details={
                "approval_id": approval.approval_id,
                "execution_id": execution.execution_id,
                "action_type": action_type,
                "risk_level": risk_level,
            },
        )

        # Publish WebSocket event to analysts
        publish_realtime_event(
            RealtimeEventEnvelope(
                type="approval_requested",
                correlation_id=execution.correlation_id,
                data={
                    "approval_id": approval.approval_id,
                    "execution_id": execution.execution_id,
                    "incident_id": execution.incident_id,
                    "action_type": action_type,
                    "risk_level": risk_level,
                    "requested_at": approval.requested_at.isoformat(),
                    "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
                },
            )
        )

        return approval

    def approve_execution(
        self,
        db: Session,
        execution_id: str,
        approver: User,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Approves a pending execution after performing post-approval re-authorization checks."""
        execution = (
            db.query(ResponseExecution)
            .filter((ResponseExecution.id == execution_id) | (ResponseExecution.execution_id == execution_id))
            .first()
        )
        if not execution:
            raise ValueError(f"Response execution '{execution_id}' not found.")

        if execution.status != ExecutionStatus.PENDING_APPROVAL.value:
            raise ValueError(f"Execution is in status '{execution.status}', not pending approval.")

        # Post-Approval Re-Authorization Check
        valid, msg = policy_engine.re_validate_post_approval(db, execution, approver)
        if not valid:
            raise PermissionError(f"Post-approval authorization failed: {msg}")

        # Update approval records
        approval = (
            db.query(ResponseApproval)
            .filter(
                ResponseApproval.execution_id == execution.id,
                ResponseApproval.decision == ApprovalDecision.PENDING.value,
            )
            .first()
        )
        if approval:
            approval.decision = ApprovalDecision.APPROVED.value
            approval.decided_by_id = approver.id
            approval.decided_at = datetime.utcnow()
            approval.reason = reason or "Approved by security officer"

        execution.status = ExecutionStatus.APPROVED.value
        db.commit()
        db.refresh(execution)

        # Audit approval
        audit_service.log_action(
            db=db,
            action="RESPONSE_APPROVAL_GRANTED",
            resource=f"execution/{execution.execution_id}",
            user_id=approver.id,
            username=approver.username,
            details={
                "execution_id": execution.execution_id,
                "reason": reason,
                "approver": approver.username,
            },
        )

        # Publish WebSocket broadcast
        publish_realtime_event(
            RealtimeEventEnvelope(
                type="approval_approved",
                correlation_id=execution.correlation_id,
                data={
                    "execution_id": execution.execution_id,
                    "approved_by": approver.username,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
        )

        return {
            "success": True,
            "status": "approved",
            "execution_id": execution.execution_id,
            "message": "Execution approved and ready for dispatch.",
        }

    def reject_execution(
        self,
        db: Session,
        execution_id: str,
        approver: User,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Rejects and terminates a pending response execution."""
        from app.security.rbac import Permission, get_user_permissions
        approver_perms = get_user_permissions(approver)
        if Permission.PLAYBOOKS_APPROVE not in approver_perms:
            raise PermissionError("User lacks 'playbooks:approve' permission.")

        execution = (
            db.query(ResponseExecution)
            .filter((ResponseExecution.id == execution_id) | (ResponseExecution.execution_id == execution_id))
            .first()
        )
        if not execution:
            raise ValueError(f"Response execution '{execution_id}' not found.")

        # Update approval record
        approval = (
            db.query(ResponseApproval)
            .filter(
                ResponseApproval.execution_id == execution.id,
                ResponseApproval.decision == ApprovalDecision.PENDING.value,
            )
            .first()
        )
        if approval:
            approval.decision = ApprovalDecision.REJECTED.value
            approval.decided_by_id = approver.id
            approval.decided_at = datetime.utcnow()
            approval.reason = reason or "Rejected by security officer"

        execution.status = ExecutionStatus.REJECTED.value
        execution.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(execution)

        # Audit rejection
        audit_service.log_action(
            db=db,
            action="RESPONSE_APPROVAL_REJECTED",
            resource=f"execution/{execution.execution_id}",
            user_id=approver.id,
            username=approver.username,
            details={
                "execution_id": execution.execution_id,
                "reason": reason,
                "rejected_by": approver.username,
            },
        )

        # Publish WebSocket broadcast
        publish_realtime_event(
            RealtimeEventEnvelope(
                type="approval_rejected",
                correlation_id=execution.correlation_id,
                data={
                    "execution_id": execution.execution_id,
                    "rejected_by": approver.username,
                    "reason": reason,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
        )

        return {
            "success": True,
            "status": "rejected",
            "execution_id": execution.execution_id,
            "message": "Execution rejected and cancelled.",
        }


approval_service = ApprovalService()
