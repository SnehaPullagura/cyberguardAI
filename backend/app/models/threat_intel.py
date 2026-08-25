import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, Text, Boolean, Integer, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class ThreatIoC(Base):
    __tablename__ = "threat_iocs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_type = Column(String(30), nullable=False, index=True)  # ip, domain, md5, sha256, url, email
    value = Column(String(255), nullable=False, index=True)
    threat_type = Column(String(100), nullable=False)          # malware, C2, phishing, ransomware, scanner, botnet
    confidence = Column(Float, default=1.0, nullable=False)    # 0.0 to 1.0
    source = Column(String(100), nullable=False)               # alienvault, abusech, internal, stix_feed, taxii
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    stix_id = Column(String(100), nullable=True, index=True)
    mitre_attack_id = Column(String(50), nullable=True, index=True)  # e.g. T1059.001
    tags = Column(JSON, nullable=True, default=list)
    sightings_count = Column(Integer, default=0, nullable=False)
    decay_score = Column(Float, default=1.0, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)

    alerts = relationship("Alert", back_populates="ioc")
