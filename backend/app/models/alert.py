import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String(100), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    rule_id = Column(String(36), ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True)
    ioc_id = Column(String(36), ForeignKey("threat_iocs.id", ondelete="SET NULL"), nullable=True)
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    risk_score = Column(Float, default=0.0, nullable=False)
    status = Column(String(30), default="open", nullable=False, index=True)  # open, in_review, resolved, suppressed
    
    source_entity = Column(String(255), nullable=True, index=True)  # IP or User or Host
    target_entity = Column(String(255), nullable=True, index=True)
    
    detection_source = Column(String(50), nullable=False, default="rule") # rule, ml_anomaly, threat_intel
    event_details = Column(JSON, nullable=True)

    rule = relationship("DetectionRule", back_populates="alerts")
    ioc = relationship("ThreatIoC", back_populates="alerts")
    incidents = relationship("IncidentAlert", back_populates="alert")
