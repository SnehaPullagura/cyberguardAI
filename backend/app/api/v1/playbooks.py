import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.playbook import Playbook, PlaybookAction
from app.schemas.playbook import (
    PlaybookCreate,
    PlaybookUpdate,
    PlaybookResponse,
    PlaybookTestRequest,
    PlaybookTestResult,
)
from app.security.rbac import require_permission, Permission, get_current_user
from app.services.audit_service import audit_service
from app.response.decision_engine import response_decision_engine

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


@router.get("", response_model=List[PlaybookResponse])
def list_playbooks(
    db: Session = Depends(get_db),
    enabled_only: bool = False,
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_READ)),
):
    """List all defensive response playbooks."""
    query = db.query(Playbook)
    if enabled_only:
        query = query.filter(Playbook.enabled == True)
    return query.order_by(Playbook.created_at.desc()).all()


@router.post("", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
def create_playbook(
    playbook_in: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_WRITE)),
):
    """Create a new defensive response playbook with structured conditions."""
    playbook_id = f"PB-{uuid.uuid4().hex[:8].upper()}"
    actions_data = [a.dict() for a in playbook_in.action_sequence]
    triggers_data = [t.dict() for t in playbook_in.trigger_conditions]

    playbook = Playbook(
        id=str(uuid.uuid4()),
        playbook_id=playbook_id,
        name=playbook_in.name,
        description=playbook_in.description,
        enabled=playbook_in.enabled,
        response_mode=playbook_in.response_mode.value,
        severity_threshold=playbook_in.severity_threshold,
        risk_score_threshold=playbook_in.risk_score_threshold,
        trigger_conditions=triggers_data,
        action_sequence=actions_data,
        approval_required=playbook_in.approval_required,
        cooldown_seconds=playbook_in.cooldown_seconds,
        timeout_seconds=playbook_in.timeout_seconds,
        retry_policy=playbook_in.retry_policy,
        failure_policy=playbook_in.failure_policy.value,
        created_by_id=current_user.id,
        updated_by_id=current_user.id,
    )
    db.add(playbook)
    db.flush()

    for idx, act in enumerate(playbook_in.action_sequence):
        pb_action = PlaybookAction(
            id=str(uuid.uuid4()),
            playbook_id=playbook.id,
            action_type=act.action_type,
            action_config=act.action_config,
            order=idx,
            risk_level=act.risk_level.value,
            timeout_seconds=act.timeout_seconds,
            retry_count=act.retry_count,
            required_permission=act.required_permission,
        )
        db.add(pb_action)

    db.commit()
    db.refresh(playbook)

    audit_service.log_action(
        db=db,
        action="PLAYBOOK_CREATED",
        resource=f"playbook/{playbook.playbook_id}",
        user_id=current_user.id,
        username=current_user.username,
        details={"playbook_id": playbook.playbook_id, "name": playbook.name},
    )

    return playbook


@router.get("/{id}", response_model=PlaybookResponse)
def get_playbook(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_READ)),
):
    """Retrieve a playbook by internal UUID or unique playbook_id."""
    playbook = (
        db.query(Playbook)
        .filter((Playbook.id == id) | (Playbook.playbook_id == id))
        .first()
    )
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{id}' not found.",
        )
    return playbook


@router.put("/{id}", response_model=PlaybookResponse)
def update_playbook(
    id: str,
    playbook_in: PlaybookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_WRITE)),
):
    """Update playbook configuration."""
    playbook = (
        db.query(Playbook)
        .filter((Playbook.id == id) | (Playbook.playbook_id == id))
        .first()
    )
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{id}' not found.",
        )

    if playbook_in.name is not None:
        playbook.name = playbook_in.name
    if playbook_in.description is not None:
        playbook.description = playbook_in.description
    if playbook_in.enabled is not None:
        playbook.enabled = playbook_in.enabled
    if playbook_in.response_mode is not None:
        playbook.response_mode = playbook_in.response_mode.value
    if playbook_in.severity_threshold is not None:
        playbook.severity_threshold = playbook_in.severity_threshold
    if playbook_in.risk_score_threshold is not None:
        playbook.risk_score_threshold = playbook_in.risk_score_threshold
    if playbook_in.trigger_conditions is not None:
        playbook.trigger_conditions = [t.dict() for t in playbook_in.trigger_conditions]
    if playbook_in.action_sequence is not None:
        playbook.action_sequence = [a.dict() for a in playbook_in.action_sequence]
    if playbook_in.approval_required is not None:
        playbook.approval_required = playbook_in.approval_required
    if playbook_in.cooldown_seconds is not None:
        playbook.cooldown_seconds = playbook_in.cooldown_seconds
    if playbook_in.timeout_seconds is not None:
        playbook.timeout_seconds = playbook_in.timeout_seconds
    if playbook_in.retry_policy is not None:
        playbook.retry_policy = playbook_in.retry_policy
    if playbook_in.failure_policy is not None:
        playbook.failure_policy = playbook_in.failure_policy.value

    playbook.updated_by_id = current_user.id
    playbook.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(playbook)

    audit_service.log_action(
        db=db,
        action="PLAYBOOK_UPDATED",
        resource=f"playbook/{playbook.playbook_id}",
        user_id=current_user.id,
        username=current_user.username,
        details={"playbook_id": playbook.playbook_id, "name": playbook.name},
    )

    return playbook


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_playbook(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_WRITE)),
):
    """Delete a playbook."""
    playbook = (
        db.query(Playbook)
        .filter((Playbook.id == id) | (Playbook.playbook_id == id))
        .first()
    )
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{id}' not found.",
        )

    db.delete(playbook)
    db.commit()

    audit_service.log_action(
        db=db,
        action="PLAYBOOK_DELETED",
        resource=f"playbook/{id}",
        user_id=current_user.id,
        username=current_user.username,
        details={"playbook_id": id},
    )


@router.post("/{id}/enable", response_model=PlaybookResponse)
def enable_playbook(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_WRITE)),
):
    """Enable a playbook."""
    playbook = (
        db.query(Playbook)
        .filter((Playbook.id == id) | (Playbook.playbook_id == id))
        .first()
    )
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{id}' not found.",
        )

    playbook.enabled = True
    playbook.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(playbook)
    return playbook


@router.post("/{id}/disable", response_model=PlaybookResponse)
def disable_playbook(
    id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_WRITE)),
):
    """Disable a playbook."""
    playbook = (
        db.query(Playbook)
        .filter((Playbook.id == id) | (Playbook.playbook_id == id))
        .first()
    )
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{id}' not found.",
        )

    playbook.enabled = False
    playbook.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(playbook)
    return playbook


@router.post("/{id}/test", response_model=PlaybookTestResult)
def test_playbook_simulation(
    id: str,
    test_req: PlaybookTestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PLAYBOOKS_EXECUTE)),
):
    """Simulate/test a playbook safely using dry-run simulation adapters without real execution."""
    playbook = (
        db.query(Playbook)
        .filter((Playbook.id == id) | (Playbook.playbook_id == id))
        .first()
    )
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{id}' not found.",
        )

    test_context = {
        "risk_score": 85.0,
        "severity": "high",
        "source_ip": "198.51.100.25",
        "observer_host": "server-db-01",
        "source_user": "analyst_test",
        "alert_title": "Simulated Alert for Playbook Test",
    }
    if test_req.mock_event:
        test_context.update(test_req.mock_event)
    if test_req.mock_alert:
        test_context.update(test_req.mock_alert)
    if test_req.mock_incident:
        test_context.update(test_req.mock_incident)

    result = response_decision_engine.simulate_playbook_test(db, playbook, test_context)
    return result
