from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"  # critical, high, medium, low
    priority: str = "P3"      # P1, P2, P3, P4
    incident_id: Optional[str] = None
    assignee_id: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    severity: Optional[str] = None
    assignee_id: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class CaseAssignRequest(BaseModel):
    assignee_id: str


class EvidenceCreate(BaseModel):
    evidence_type: str  # event, alert, ioc, file_hash, raw_log, artifact
    title: str
    data: Dict[str, Any] = {}


class EvidenceRead(BaseModel):
    id: str
    case_id: str
    evidence_type: str
    title: str
    data: Dict[str, Any]
    added_by_id: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TimelineEventRead(BaseModel):
    id: str
    case_id: str
    timestamp: datetime
    event_type: str
    title: str
    description: Optional[str] = None
    actor: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class NoteCreate(BaseModel):
    content: str


class NoteRead(BaseModel):
    id: str
    case_id: str
    author_id: str
    content: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseRead(BaseModel):
    id: str
    case_id: str
    title: str
    description: Optional[str] = None
    status: str
    priority: str
    severity: str
    incident_id: Optional[str] = None
    assignee_id: Optional[str] = None
    created_by_id: Optional[str] = None
    mitre_tactics: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class SavedSearchCreate(BaseModel):
    name: str
    description: Optional[str] = None
    target_entity: str = "cases"
    filter_params: Dict[str, Any]


class SavedSearchRead(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    user_id: str
    target_entity: str
    filter_params: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
