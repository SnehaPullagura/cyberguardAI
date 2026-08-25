import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class ResponseApproval(Base):
    __tablename__ = "response_approvals"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    approval_id = Column(String(100), unique=True, nullable=False, index=True)
    execution_id = Column(String(36), ForeignKey("response_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    
    incident_id = Column(String(100), nullable=True, index=True)
    playbook_id = Column(String(36), ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True)
    action_type = Column(String(100), nullable=False)
    risk_level = Column(String(20), default="high", nullable=False)
    
    requested_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    decided_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    
    decision = Column(String(30), default="pending", nullable=False, index=True)  # pending, approved, rejected, expired
    reason = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    execution = relationship("ResponseExecution", back_populates="approval_requests")
    requested_by = relationship("User", foreign_keys=[requested_by_id])
    decided_by = relationship("User", foreign_keys=[decided_by_id])
    playbook = relationship("Playbook")
