from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import AlertRead, AlertStatusUpdate
from app.security.rbac import require_permission, Permission
from app.services.audit_service import audit_service

router = APIRouter(prefix="/alerts", tags=["Alert Management"])


@router.get("", response_model=List[AlertRead])
def list_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    detection_source: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ALERTS_READ)),
):
    """Retrieve security alerts with filtering and pagination."""
    query = db.query(Alert)
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    if severity:
        query = query.filter(Alert.severity == severity)
    if detection_source:
        query = query.filter(Alert.detection_source == detection_source)

    alerts = query.order_by(Alert.timestamp.desc()).offset(skip).limit(limit).all()
    return alerts


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ALERTS_READ)),
):
    """Retrieve detailed security alert by ID."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found"
        )
    return alert


@router.patch("/{alert_id}/status", response_model=AlertRead)
def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ALERTS_UPDATE)),
):
    """Update alert triage status (new, investigating, resolved, false_positive)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found"
        )

    old_status = alert.status
    alert.status = payload.status
    db.commit()
    db.refresh(alert)

    audit_service.log_action(
        db=db,
        action="ALERT_STATUS_UPDATED",
        resource="alerts",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={
            "alert_id": alert_id,
            "old_status": old_status,
            "new_status": payload.status,
        },
    )

    return alert
