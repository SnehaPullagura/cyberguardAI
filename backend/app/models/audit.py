import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = Column(String(100), nullable=False)
    ip_address = Column(String(45), nullable=True)
    
    action = Column(String(100), nullable=False, index=True)  # e.g., "LOGIN", "RULE_CREATE", "INCIDENT_UPDATE"
    resource = Column(String(100), nullable=False)           # e.g., "/api/v1/incidents/123"
    status = Column(String(20), nullable=False, default="SUCCESS") # SUCCESS, FAILURE
    details = Column(JSON, nullable=True)

    user = relationship("User", back_populates="audit_logs")
