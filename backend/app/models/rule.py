import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, JSON, Text, Integer
from sqlalchemy.orm import relationship
from app.database import Base


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    category = Column(String(50), nullable=False, index=True)   # authentication, process, network, etc.
    mitre_attack_id = Column(String(50), nullable=True)        # e.g., T1110 (Brute Force)
    
    # Store condition standard structured definition
    condition = Column(JSON, nullable=False)
    raw_yaml = Column(Text, nullable=True)

    enabled = Column(Boolean, default=True, nullable=False)
    created_by = Column(String(100), default="system", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    alerts = relationship("Alert", back_populates="rule")
