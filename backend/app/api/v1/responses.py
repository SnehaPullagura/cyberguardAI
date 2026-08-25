from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.response_execution import ResponseExecution
from app.models.approval import ResponseApprovalRequest
from app.models.playbook import Playbook
from app.models.user import User
from app.schemas.playbook import ResponseExecutionRead, ResponseApprovalDecision
from app.security.auth import get_current_user
from app.security.rbac import require_permission, Permission
from app.response.executor import playbook_executor
from app.services.audit_service import audit_service

router = APIRouter(prefix="/responses", tags=["Playbook Response Executions & Approvals"])


@router.get("", response_model=List[ResponseExecutionRead])
def list_response_executions(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RESPONSES_READ)),
):
    """List response execution audit records."""
    executions = db.query(ResponseExecution).order_by(ResponseExecution.started_at.desc()).limit(100).all()
    return executions


@router.get("/{execution_id}", response_model=ResponseExecutionRead)
def get_response_execution(
    execution_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RESPONSES_READ)),
):
    """Get response execution details by ID."""
    execution = db.query(ResponseExecution).filter((ResponseExecution.id == execution_id) | (ResponseExecution.execution_id == execution_id)).first()
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response execution record not found")
    return execution


@router.post("/{execution_id}/approve")
def approve_response_execution(
    execution_id: str,
    decision: ResponseApprovalDecision,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_APPROVE)),
):
    """Approve a pending high-impact response action execution."""
    execution = db.query(ResponseExecution).filter((ResponseExecution.id == execution_id) | (ResponseExecution.execution_id == execution_id)).first()
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response execution record not found")

    if execution.status != "pending_approval":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Execution status is '{execution.status}', cannot approve.")

    # Self-approval restriction check
    if execution.requested_by_id and execution.requested_by_id == current_user.id and not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Self-approval forbidden. Another authorized analyst must approve this request.")

    approval = db.query(ResponseApprovalRequest).filter(ResponseApprovalRequest.execution_id == execution.id, ResponseApprovalRequest.status == "pending").first()
    if approval:
        approval.status = "approved"
        approval.approved_by_id = current_user.id
        approval.reason = decision.reason or "Approved by authorized analyst"
        approval.decided_at = datetime.utcnow()

    playbook = db.query(Playbook).filter(Playbook.id == execution.playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Associated playbook not found")

    # Run execution with authorized mode
    executed_record = playbook_executor.execute_playbook_actions(
        db=db,
        playbook=playbook,
        context={"execution_id": execution.execution_id},
        execution_id=execution.execution_id,
        mode="simulation",
        approved_by_id=current_user.id,
    )

    audit_service.log_action(
        db=db,
        action="PLAYBOOK_APPROVAL_APPROVED",
        resource="playbooks",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"execution_id": execution.execution_id, "reason": decision.reason},
    )

    return {"status": "approved", "execution_id": execution.execution_id}


@router.post("/{execution_id}/reject")
def reject_response_execution(
    execution_id: str,
    decision: ResponseApprovalDecision,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_APPROVE)),
):
    """Reject a pending response action execution."""
    execution = db.query(ResponseExecution).filter((ResponseExecution.id == execution_id) | (ResponseExecution.execution_id == execution_id)).first()
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Response execution record not found")

    if execution.status != "pending_approval":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Execution status is '{execution.status}', cannot reject.")

    execution.status = "rejected"
    execution.completed_at = datetime.utcnow()
    execution.approval_reason = decision.reason or "Rejected by authorized analyst"

    approval = db.query(ResponseApprovalRequest).filter(ResponseApprovalRequest.execution_id == execution.id, ResponseApprovalRequest.status == "pending").first()
    if approval:
        approval.status = "rejected"
        approval.approved_by_id = current_user.id
        approval.reason = decision.reason
        approval.decided_at = datetime.utcnow()

    db.commit()

    audit_service.log_action(
        db=db,
        action="PLAYBOOK_APPROVAL_REJECTED",
        resource="playbooks",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"execution_id": execution.execution_id, "reason": decision.reason},
    )

    return {"status": "rejected", "execution_id": execution.execution_id}
