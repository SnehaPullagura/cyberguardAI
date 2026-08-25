from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.response_execution import ResponseExecution
from app.models.approval import ResponseApproval
from app.schemas.response import (
    ResponseExecutionResponse,
    ResponseApprovalResponse,
    ApprovalDecisionRequest,
)
from app.security.rbac import require_permission, Permission, get_current_user
from app.response.approval_service import approval_service

router = APIRouter(prefix="/responses", tags=["responses"])


@router.get("", response_model=List[ResponseExecutionResponse])
def list_responses(
    db: Session = Depends(get_db),
    status_filter: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_permission(Permission.RESPONSES_READ)),
):
    """List response execution history."""
    query = db.query(ResponseExecution)
    if status_filter:
        query = query.filter(ResponseExecution.status == status_filter)
    return query.order_by(ResponseExecution.started_at.desc()).limit(limit).all()


@router.get("/approvals", response_model=List[ResponseApprovalResponse])
def list_pending_approvals(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_READ)),
):
    """List pending response approval requests."""
    return (
        db.query(ResponseApproval)
        .filter(ResponseApproval.decision == "pending")
        .order_by(ResponseApproval.requested_at.desc())
        .all()
    )


@router.get("/{id}", response_model=ResponseExecutionResponse)
def get_response(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RESPONSES_READ)),
):
    """Get details of a specific response execution."""
    execution = (
        db.query(ResponseExecution)
        .filter((ResponseExecution.id == id) | (ResponseExecution.execution_id == id))
        .first()
    )
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response execution '{id}' not found.",
        )
    return execution


@router.post("/{id}/approve")
def approve_response(
    id: str,
    body: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_APPROVE)),
):
    """Approve a pending response execution after performing post-approval re-authorization."""
    try:
        res = approval_service.approve_execution(
            db=db,
            execution_id=id,
            approver=current_user,
            reason=body.reason,
        )
        return res
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/{id}/reject")
def reject_response(
    id: str,
    body: ApprovalDecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_APPROVE)),
):
    """Reject and cancel a pending response execution."""
    try:
        res = approval_service.reject_execution(
            db=db,
            execution_id=id,
            approver=current_user,
            reason=body.reason,
        )
        return res
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
