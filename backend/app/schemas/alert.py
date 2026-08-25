from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict


class AlertRead(BaseModel):
    id: str
    alert_id: str
    timestamp: datetime
    rule_id: Optional[str] = None
    ioc_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    risk_score: float
    status: str
    source_entity: Optional[str] = None
    target_entity: Optional[str] = None
    detection_source: str
    event_details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class AlertUpdateStatus(BaseModel):
    status: str  # new, investigating, resolved, false_positive


class AlertStatusUpdate(AlertUpdateStatus):
    pass
