import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.threat_intel import ThreatIoC
from app.models.user import User
from app.schemas.threat_intel import ThreatIoCRead, ThreatIoCCreate
from app.security.rbac import require_permission, Permission
from app.services.audit_service import audit_service

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence Feed"])


@router.get("/iocs", response_model=List[ThreatIoCRead])
def list_iocs(
    ioc_type: Optional[str] = Query(None),
    threat_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_READ)),
):
    """Retrieve threat intelligence IoC records."""
    query = db.query(ThreatIoC)
    if ioc_type:
        query = query.filter(ThreatIoC.ioc_type == ioc_type)
    if threat_type:
        query = query.filter(ThreatIoC.threat_type == threat_type)

    return query.order_by(ThreatIoC.created_at.desc()).all()


@router.post("/iocs", response_model=ThreatIoCRead, status_code=status.HTTP_201_CREATED)
def add_ioc(
    payload: ThreatIoCCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_WRITE)),
):
    """Add a new Indicator of Compromise (IoC) to threat intel database."""
    existing = db.query(ThreatIoC).filter(ThreatIoC.value == payload.value).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"IoC value '{payload.value}' already exists",
        )

    ioc = ThreatIoC(
        id=str(uuid.uuid4()),
        ioc_type=payload.ioc_type,
        value=payload.value,
        threat_type=payload.threat_type,
        confidence=payload.confidence,
        source=payload.source,
        description=payload.description,
        is_active=payload.is_active,
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)

    audit_service.log_action(
        db=db,
        action="IOC_CREATED",
        resource="threat_intel",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"ioc_value": ioc.value, "ioc_type": ioc.ioc_type},
    )

    return ioc
