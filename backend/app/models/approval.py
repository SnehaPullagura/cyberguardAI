import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class ResponseApprovalRequest(Base):
    __tablename__ = "response_approval_requests"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    approval_id = Column(String(100), unique=True, nullable=False, index=True)

    execution_id = Column(String(36), ForeignKey("response_executions.id", ondelete="CASCADE"), nullable=False)
    playbook_id = Column(String(36), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)

    requested_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    status = Column(String(20), default="pending", nullable=False, index=True)  # pending, approved, rejected, expired
    risk_level = Column(String(20), default="high", nullable=False)
    reason = Column(Text, nullable=True)

    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    decided_at = Column(DateTime, nullable=True)
