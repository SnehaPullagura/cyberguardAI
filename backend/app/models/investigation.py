import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, Boolean, Integer, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    status = Column(String(30), default="open", nullable=False, index=True)  # open, investigating, contained, closed, false_positive
    priority = Column(String(10), default="P3", nullable=False, index=True)  # P1, P2, P3, P4
    severity = Column(String(20), default="medium", nullable=False, index=True)  # critical, high, medium, low
    
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True, index=True)
    assignee_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    
    mitre_tactics = Column(JSON, nullable=True, default=list)
    tags = Column(JSON, nullable=True, default=list)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    closed_at = Column(DateTime, nullable=True)

    assignee = relationship("User", foreign_keys=[assignee_id])
    created_by = relationship("User", foreign_keys=[created_by_id])
    incident = relationship("Incident")
    evidence_items = relationship("CaseEvidence", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("CaseTimelineEvent", back_populates="case", cascade="all, delete-orphan")
    notes = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan")


class CaseEvidence(Base):
    __tablename__ = "case_evidence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("investigation_cases.id"), nullable=False, index=True)
    evidence_type = Column(String(50), nullable=False)  # event, alert, ioc, file_hash, raw_log, artifact
    title = Column(String(255), nullable=False)
    data = Column(JSON, nullable=False, default=dict)
    
    added_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    case = relationship("InvestigationCase", back_populates="evidence_items")
    added_by = relationship("User")


class CaseTimelineEvent(Base):
    __tablename__ = "case_timeline_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("investigation_cases.id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # alert, event, note, response_action, evidence, status_change
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    actor = Column(String(100), nullable=True)
    metadata_json = Column(JSON, nullable=True, default=dict)

    case = relationship("InvestigationCase", back_populates="timeline_events")


class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("investigation_cases.id"), nullable=False, index=True)
    author_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    case = relationship("InvestigationCase", back_populates="notes")
    author = relationship("User")


class SavedSearch(Base):
    __tablename__ = "saved_searches"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    target_entity = Column(String(50), default="cases", nullable=False)  # cases, alerts, events, iocs
    filter_params = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
