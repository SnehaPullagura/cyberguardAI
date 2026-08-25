import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Integer, Float, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    playbook_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    response_mode = Column(String(30), default="dry_run", nullable=False)  # dry_run, simulation, approval_required, authorized_execution
    
    severity_threshold = Column(String(20), default="medium", nullable=False)  # critical, high, medium, low, info
    risk_score_threshold = Column(Float, default=50.0, nullable=False)
    
    # Structured JSON trigger conditions, e.g. [{"field": "risk_score", "operator": "gte", "value": 75}]
    trigger_conditions = Column(JSON, nullable=False, default=list)
    
    # Ordered list of action references or configs
    action_sequence = Column(JSON, nullable=False, default=list)
    
    approval_required = Column(Boolean, default=False, nullable=False)
    cooldown_seconds = Column(Integer, default=300, nullable=False)  # 5 minutes default
    timeout_seconds = Column(Integer, default=30, nullable=False)
    retry_policy = Column(JSON, nullable=True, default=lambda: {"max_retries": 0, "backoff_base": 2})
    failure_policy = Column(String(20), default="stop", nullable=False)  # stop, continue
    
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    actions = relationship("PlaybookAction", back_populates="playbook", cascade="all, delete-orphan", order_by="PlaybookAction.order")
    executions = relationship("ResponseExecution", back_populates="playbook", cascade="all, delete-orphan")


class PlaybookAction(Base):
    __tablename__ = "playbook_actions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    playbook_id = Column(String(36), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(100), nullable=False)  # must match allowlisted ActionRegistry
    action_config = Column(JSON, nullable=True, default=dict)
    order = Column(Integer, default=0, nullable=False)
    risk_level = Column(String(20), default="low", nullable=False)  # low, medium, high, critical
    timeout_seconds = Column(Integer, default=30, nullable=False)
    retry_count = Column(Integer, default=0, nullable=False)
    required_permission = Column(String(100), default="responses:execute", nullable=False)

    playbook = relationship("Playbook", back_populates="actions")
