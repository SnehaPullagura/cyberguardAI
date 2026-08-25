import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Float, Integer, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    playbook_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)

    severity_threshold = Column(String(20), default="high", nullable=False)  # critical, high, medium, low
    risk_score_threshold = Column(Float, default=75.0, nullable=False)
    trigger_conditions = Column(JSON, nullable=False, default=list)  # List of condition objects: [{"field": "risk_score", "operator": "gte", "value": 80}]
    action_sequence = Column(JSON, nullable=False, default=list)  # List of allowlisted action types: ["create_incident", "notify_security_team", "quarantine_simulation"]

    approval_required = Column(Boolean, default=False, nullable=False)
    cooldown_seconds = Column(Integer, default=300, nullable=False)  # 5 min default cooldown
    timeout_seconds = Column(Integer, default=60, nullable=False)
    retry_policy = Column(JSON, nullable=True, default=dict)  # {"max_retries": 2, "backoff_seconds": 5}

    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    executions = relationship("ResponseExecution", back_populates="playbook", cascade="all, delete-orphan")
