import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class ResponseExecution(Base):
    __tablename__ = "response_executions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(100), unique=True, nullable=False, index=True)
    playbook_id = Column(String(36), ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True, index=True)
    
    incident_id = Column(String(100), nullable=True, index=True)
    alert_id = Column(String(100), nullable=True, index=True)
    trigger_event_id = Column(String(100), nullable=True, index=True)
    correlation_id = Column(String(100), nullable=True, index=True)
    
    status = Column(String(30), default="pending_approval", nullable=False, index=True)  # pending_approval, approved, running, success, failed, simulated, rejected, cancelled, cooldown_suppressed
    mode = Column(String(30), default="dry_run", nullable=False)  # dry_run, simulation, approval_required, authorized_execution
    
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Float, default=0.0, nullable=False)
    
    triggered_by = Column(String(100), default="system", nullable=False)
    error_code = Column(String(100), nullable=True)
    error_message = Column(Text, nullable=True)
    execution_depth = Column(Integer, default=1, nullable=False)
    
    result_metadata = Column(JSON, nullable=True, default=dict)

    playbook = relationship("Playbook", back_populates="executions")
    action_executions = relationship("ResponseActionExecution", back_populates="execution", cascade="all, delete-orphan")
    approval_requests = relationship("ResponseApproval", back_populates="execution", cascade="all, delete-orphan")


class ResponseActionExecution(Base):
    __tablename__ = "response_action_executions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(36), ForeignKey("response_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    
    action_type = Column(String(100), nullable=False)
    action_id = Column(String(100), nullable=True)
    status = Column(String(30), default="running", nullable=False)  # success, failed, simulated, cancelled, timed_out
    mode = Column(String(30), default="dry_run", nullable=False)
    
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Float, default=0.0, nullable=False)
    
    verification_status = Column(String(30), default="unverified", nullable=False)  # verified, failed, skipped, simulated
    error_code = Column(String(100), nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    timeout_applied = Column(Integer, default=30, nullable=False)
    
    result_metadata = Column(JSON, nullable=True, default=dict)

    execution = relationship("ResponseExecution", back_populates="action_executions")
