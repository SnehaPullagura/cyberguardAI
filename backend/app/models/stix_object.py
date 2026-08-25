import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, Text, Boolean, Integer, JSON
from app.database import Base


class STIXObject(Base):
    __tablename__ = "stix_objects"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    stix_id = Column(String(150), unique=True, nullable=False, index=True)
    spec_version = Column(String(10), default="2.1", nullable=False)
    type = Column(String(50), nullable=False, index=True)  # indicator, malware, intrusion-set, attack-pattern, tool, campaign, relationship
    name = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    
    pattern = Column(Text, nullable=True)
    pattern_type = Column(String(50), default="stix", nullable=True)
    valid_from = Column(DateTime, nullable=True)
    valid_until = Column(DateTime, nullable=True)
    
    source_ref = Column(String(150), nullable=True, index=True)
    target_ref = Column(String(150), nullable=True, index=True)
    relationship_type = Column(String(50), nullable=True)
    
    external_references = Column(JSON, nullable=True, default=list)  # MITRE ATT&CK, CVE, etc.
    stix_data = Column(JSON, nullable=False, default=dict)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
