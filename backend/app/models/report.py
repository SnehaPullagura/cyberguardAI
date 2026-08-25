import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, DateTime, JSON, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class ComplianceEvaluation(Base):
    __tablename__ = "compliance_evaluations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    framework = Column(String(50), nullable=False, index=True)  # soc2, iso27001, nist_csf, pci_dss, hipaa
    overall_score = Column(Float, nullable=False, default=0.0)
    status = Column(String(30), nullable=False, default="compliant")  # compliant, needs_attention, non_compliant
    
    total_controls = Column(Integer, default=0, nullable=False)
    passed_controls = Column(Integer, default=0, nullable=False)
    warning_controls = Column(Integer, default=0, nullable=False)
    failed_controls = Column(Integer, default=0, nullable=False)
    
    summary_json = Column(JSON, nullable=False, default=dict)
    evaluated_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    evaluated_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)

    evaluated_by = relationship("User")


class ReportSchedule(Base):
    __tablename__ = "report_schedules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    report_type = Column(String(50), nullable=False)  # compliance, executive, audit, incidents
    framework = Column(String(50), nullable=True)     # soc2, iso27001, etc.
    frequency = Column(String(30), default="weekly", nullable=False)  # daily, weekly, monthly
    recipients = Column(JSON, default=list, nullable=False)           # list of email addresses
    is_active = Column(Boolean, default=True, nullable=False)
    delivery_channel = Column(String(50), default="email", nullable=False)  # email, webhook, s3
    
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)

    created_by = relationship("User")
