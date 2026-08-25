from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class ThreatIoCCreate(BaseModel):
    ioc_type: str  # ip, domain, md5, sha256, url, email
    value: str
    threat_type: str  # malware, C2, phishing, ransomware, scanner, botnet
    confidence: float = 1.0
    source: str
    description: Optional[str] = None
    stix_id: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    tags: Optional[List[str]] = None
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
    stix_id: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    tags: Optional[List[str]] = None
    sightings_count: int = 0
    decay_score: float = 1.0
    last_seen: Optional[datetime] = None
    created_at: datetime
    expires_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ThreatFeedCreate(BaseModel):
    feed_id: str
    name: str
    feed_type: str = "taxii21"  # taxii21, stix_json, abusech, alienvault, custom_json
    url: str
    api_key: Optional[str] = None
    collection_id: Optional[str] = None
    poll_interval_minutes: int = 60
    enabled: bool = True
    confidence_weight: float = 0.85


class ThreatFeedRead(BaseModel):
    id: str
    feed_id: str
    name: str
    feed_type: str
    url: str
    collection_id: Optional[str] = None
    poll_interval_minutes: int
    enabled: bool
    confidence_weight: float
    last_sync: Optional[datetime] = None
    last_status: str
    last_error: Optional[str] = None
    ioc_count: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class STIXBundleImportRequest(BaseModel):
    bundle: Dict[str, Any]


class HistoricalCorrelationRequest(BaseModel):
    ioc_value: str
    ioc_type: str = "ip"
    lookback_days: int = 7
