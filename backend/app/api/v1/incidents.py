from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.incident import Incident
from app.models.user import User
from app.schemas.incident import (
    IncidentRead,
    IncidentCreate,
    IncidentUpdate,
    IncidentNoteCreate,
)
from app.security.rbac import require_permission, Permission
from app.services.audit_service import audit_service

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


@router.get("", response_model=List[IncidentRead])
def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENTS_READ)),
):
    """Retrieve security incidents with filtering and pagination."""
    query = db.query(Incident)
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    if severity:
        query = query.filter(Incident.severity == severity)

    incidents = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()
    return incidents


@router.post("", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENTS_CREATE)),
):
    """Manually create a new security incident."""
    import uuid

    incident = Incident(
        id=str(uuid.uuid4()),
        incident_number=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        assigned_to_id=payload.assigned_to_id,
        status="new",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    audit_service.log_action(
        db=db,
        action="INCIDENT_CREATED",
        resource="incidents",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"incident_id": incident.id, "incident_number": incident.incident_number},
    )

    return incident


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENTS_READ)),
):
    """Retrieve detailed incident record by ID."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found"
        )
    return incident


@router.patch("/{incident_id}", response_model=IncidentRead)
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENTS_UPDATE)),
):
    """Update incident status, severity, or assignment."""
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found"
        )

    if payload.status:
        incident.status = payload.status
    if payload.severity:
        incident.severity = payload.severity
    if payload.assigned_to_id:
        incident.assigned_to_id = payload.assigned_to_id

    db.commit()
    db.refresh(incident)

    audit_service.log_action(
        db=db,
        action="INCIDENT_UPDATED",
        resource="incidents",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"incident_id": incident_id, "new_status": payload.status},
    )

    return incident
