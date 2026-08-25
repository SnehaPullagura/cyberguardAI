import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.playbook import Playbook
from app.models.user import User
from app.schemas.playbook import PlaybookCreate, PlaybookRead
from app.security.auth import get_current_user
from app.security.rbac import require_permission, Permission
from app.response.executor import playbook_executor
from app.services.audit_service import audit_service

router = APIRouter(prefix="/playbooks", tags=["Automated Response Playbooks"])


@router.get("", response_model=List[PlaybookRead])
def list_playbooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_READ)),
):
    """List all registered response playbooks."""
    playbooks = db.query(Playbook).all()
    return playbooks


@router.post("", response_model=PlaybookRead, status_code=status.HTTP_201_CREATED)
def create_playbook(
    request_data: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_WRITE)),
):
    """Create a new automated response playbook."""
    pb_id = f"PB-{uuid.uuid4().hex[:8].upper()}"
    playbook = Playbook(
        id=str(uuid.uuid4()),
        playbook_id=pb_id,
        name=request_data.name,
        description=request_data.description,
        enabled=request_data.enabled,
        severity_threshold=request_data.severity_threshold,
        risk_score_threshold=request_data.risk_score_threshold,
        trigger_conditions=[c.dict() for c in request_data.trigger_conditions],
        action_sequence=request_data.action_sequence,
        approval_required=request_data.approval_required,
        cooldown_seconds=request_data.cooldown_seconds,
        timeout_seconds=request_data.timeout_seconds,
        retry_policy=request_data.retry_policy,
        created_by_id=current_user.id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)

    audit_service.log_action(
        db=db,
        action="PLAYBOOK_CREATED",
        resource="playbooks",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"playbook_id": playbook.playbook_id, "name": playbook.name},
    )
    return playbook


@router.get("/{playbook_id}", response_model=PlaybookRead)
def get_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_READ)),
):
    """Get playbook details by ID."""
    playbook = db.query(Playbook).filter((Playbook.id == playbook_id) | (Playbook.playbook_id == playbook_id)).first()
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    return playbook


@router.post("/{playbook_id}/enable", response_model=PlaybookRead)
def enable_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_WRITE)),
):
    """Enable a playbook."""
    playbook = db.query(Playbook).filter((Playbook.id == playbook_id) | (Playbook.playbook_id == playbook_id)).first()
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    playbook.enabled = True
    db.commit()
    db.refresh(playbook)
    return playbook


@router.post("/{playbook_id}/disable", response_model=PlaybookRead)
def disable_playbook(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_WRITE)),
):
    """Disable a playbook."""
    playbook = db.query(Playbook).filter((Playbook.id == playbook_id) | (Playbook.playbook_id == playbook_id)).first()
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    playbook.enabled = False
    db.commit()
    db.refresh(playbook)
    return playbook


@router.post("/{playbook_id}/test")
def test_playbook_simulation(
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_EXECUTE)),
):
    """Safe playbook testing endpoint running simulation adapters only."""
    playbook = db.query(Playbook).filter((Playbook.id == playbook_id) | (Playbook.playbook_id == playbook_id)).first()
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    mock_context = {
        "event_id": "test-sim-100",
        "action": "login_failed",
        "severity": "high",
        "risk_score": 90.0,
        "source_ip": "198.51.100.42",
        "source_user": "test_user",
    }

    execution = playbook_executor.execute_playbook_actions(
        db=db,
        playbook=playbook,
        context=mock_context,
        execution_id=f"sim-{uuid.uuid4().hex[:6]}",
        mode="simulation",
        requested_by_id=current_user.id,
    )
    return {
        "simulation_status": "success",
        "execution_id": execution.execution_id,
        "mode": execution.mode,
        "status": execution.status,
    }
