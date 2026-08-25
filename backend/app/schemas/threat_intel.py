from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class ThreatIoCCreate(BaseModel):
    ioc_type: str  # ip, domain, md5, sha256, url
    value: str
    threat_type: str  # malware, C2, phishing, ransomware, scanner
    confidence: float = 1.0
    source: str
    description: Optional[str] = None
    expires_at: Optional[datetime] = None


class ThreatIoCRead(BaseModel):
    id: str
    ioc_type: str
    value: str
    threat_type: str
    confidence: float
    source: str
    description: Optional[str] = None
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
