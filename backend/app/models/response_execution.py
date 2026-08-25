import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class ResponseExecution(Base):
    __tablename__ = "response_executions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(100), unique=True, nullable=False, index=True)
    
    playbook_id = Column(String(36), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)

    status = Column(String(30), default="pending", nullable=False, index=True)  # pending_approval, running, success, failed, simulated, rejected, cooldown_suppressed
    mode = Column(String(30), default="dry_run", nullable=False)  # dry_run, simulation, approval_required, authorized_execution

    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Float, nullable=True)

    requested_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approval_reason = Column(Text, nullable=True)

    verification_status = Column(String(30), default="unverified", nullable=False)  # verified, unverified, failed
    error_code = Column(String(100), nullable=True)
    result_metadata = Column(JSON, nullable=True, default=dict)

    playbook = relationship("Playbook", back_populates="executions")
    action_executions = relationship("ResponseActionExecution", back_populates="execution", cascade="all, delete-orphan")


class ResponseActionExecution(Base):
    __tablename__ = "response_action_executions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(36), ForeignKey("response_executions.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String(100), nullable=False)
    status = Column(String(30), default="running", nullable=False)  # success, failed, simulated, skipped
    risk_level = Column(String(20), default="low", nullable=False)

    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Float, nullable=True)

    verification_status = Column(String(30), default="unverified", nullable=False)
    output = Column(JSON, nullable=True, default=dict)
    error = Column(Text, nullable=True)

    execution = relationship("ResponseExecution", back_populates="action_executions")
