import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.audit import AuditLog

SENSITIVE_KEYS = {"password", "hashed_password", "token", "access_token", "refresh_token", "secret", "secret_key"}


def sanitize_audit_details(details: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Sanitize dictionary to prevent storing sensitive credentials or tokens in audit logs."""
    if not details:
        return details
    clean_details = {}
    for k, v in details.items():
        if any(s in k.lower() for s in SENSITIVE_KEYS):
            clean_details[k] = "[REDACTED]"
        elif isinstance(v, dict):
            clean_details[k] = sanitize_audit_details(v)
        else:
            clean_details[k] = v
    return clean_details


class AuditService:
    """Service for writing immutable security audit logs."""

    @staticmethod
    def log_action(
        db: Session,
        action: str,
        resource: str,
        user_id: Optional[str] = None,
        username: str = "system",
        ip_address: Optional[str] = None,
        status: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        clean_details = sanitize_audit_details(details)
        audit_entry = AuditLog(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            action=action,
            resource=resource,
            status=status,
            details=clean_details,
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)
        return audit_entry


audit_service = AuditService()
