import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import relationship
from app.database import Base


class ThreatIoC(Base):
    __tablename__ = "threat_iocs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_type = Column(String(30), nullable=False, index=True)  # ip, domain, md5, sha256, url
    value = Column(String(255), nullable=False, index=True)
    threat_type = Column(String(100), nullable=False)          # malware, C2, phishing, ransomware, scanner
    confidence = Column(Float, default=1.0, nullable=False)    # 0.0 to 1.0
    source = Column(String(100), nullable=False)               # alienvault, abusech, internal, stix_feed
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)

    alerts = relationship("Alert", back_populates="ioc")
