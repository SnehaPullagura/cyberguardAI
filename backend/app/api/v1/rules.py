import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.rule import DetectionRule
from app.models.user import User
from app.schemas.rule import DetectionRuleRead, DetectionRuleCreate, DetectionRuleUpdate
from app.security.rbac import require_permission, Permission
from app.services.audit_service import audit_service

router = APIRouter(prefix="/rules", tags=["Detection Rules Engine"])


@router.get("", response_model=List[DetectionRuleRead])
def list_rules(
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RULES_READ)),
):
    """List detection rules with filtering."""
    query = db.query(DetectionRule)
    if category:
        query = query.filter(DetectionRule.category == category)
    if severity:
        query = query.filter(DetectionRule.severity == severity)
    if enabled is not None:
        query = query.filter(DetectionRule.enabled == enabled)

    return query.order_by(DetectionRule.created_at.desc()).all()


@router.post("", response_model=DetectionRuleRead, status_code=status.HTTP_201_CREATED)
def create_rule(
    request: DetectionRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RULES_WRITE)),
):
    """Create a new Sigma-style detection rule."""
    existing = db.query(DetectionRule).filter(DetectionRule.rule_id == request.rule_id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Rule with ID '{request.rule_id}' already exists",
        )

    rule = DetectionRule(
        id=str(uuid.uuid4()),
        rule_id=request.rule_id,
        title=request.title,
        description=request.description,
        severity=request.severity,
        category=request.category,
        mitre_attack_id=request.mitre_attack_id,
        condition=request.condition,
        enabled=request.enabled,
        author_id=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    audit_service.log_action(
        db=db,
        action="RULE_CREATED",
        resource="rules",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"rule_id": rule.rule_id, "title": rule.title},
    )

    return rule


@router.get("/{rule_id}", response_model=DetectionRuleRead)
def get_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RULES_READ)),
):
    """Retrieve detection rule by ID."""
    rule = (
        db.query(DetectionRule)
        .filter((DetectionRule.id == rule_id) | (DetectionRule.rule_id == rule_id))
        .first()
    )
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found"
        )
    return rule


@router.put("/{rule_id}", response_model=DetectionRuleRead)
def update_rule(
    rule_id: str,
    request: DetectionRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RULES_WRITE)),
):
    """Update detection rule attributes or logic."""
    rule = (
        db.query(DetectionRule)
        .filter((DetectionRule.id == rule_id) | (DetectionRule.rule_id == rule_id))
        .first()
    )
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found"
        )

    if request.title:
        rule.title = request.title
    if request.description:
        rule.description = request.description
    if request.severity:
        rule.severity = request.severity
    if request.condition:
        rule.condition = request.condition
    if request.enabled is not None:
        rule.enabled = request.enabled

    db.commit()
    db.refresh(rule)

    audit_service.log_action(
        db=db,
        action="RULE_UPDATED",
        resource="rules",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"rule_id": rule.rule_id},
    )

    return rule
