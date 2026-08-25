from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict
from app.schemas.alert import AlertRead


class IncidentNoteCreate(BaseModel):
    content: str


class IncidentNoteRead(BaseModel):
    id: str
    incident_id: str
    author_id: Optional[str] = None
    author_name: str
    content: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str  # critical, high, medium, low, info
    alert_ids: List[str] = []


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None  # new, triaged, investigating, closed, false_positive
    assignee_id: Optional[str] = None


class IncidentRead(BaseModel):
    id: str
    incident_id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    risk_score: float
    assignee_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    notes: List[IncidentNoteRead] = []

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailRead(IncidentRead):
    alert_count: int = 0
    alerts: List[AlertRead] = []
