from typing import List, Dict, Any
from pydantic import BaseModel


class EntityRiskScore(BaseModel):
    entity_name: str
    entity_type: str  # IP, User, Host
    risk_score: float
    alert_count: int


class MetricPoint(BaseModel):
    timestamp: str
    count: int


class DashboardSummary(BaseModel):
    total_events_processed: int
    events_per_second: float
    total_active_incidents: int
    critical_incidents: int
    open_alerts: int
    high_risk_entities: List[EntityRiskScore]
    alerts_by_severity: Dict[str, int]
    events_trend: List[MetricPoint]
