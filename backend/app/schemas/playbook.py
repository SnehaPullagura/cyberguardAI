from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class TriggerConditionSchema(BaseModel):
    field: str = Field(..., example="risk_score")
    operator: str = Field(..., example="gte")  # gte, lte, eq, ne, in, contains
    value: Any = Field(..., example=75.0)


class PlaybookCreate(BaseModel):
    name: str = Field(..., example="High Risk Login Attack Containment")
    description: Optional[str] = None
    enabled: bool = True
    severity_threshold: str = Field("high", example="high")
    risk_score_threshold: float = Field(75.0, example=75.0)
    trigger_conditions: List[TriggerConditionSchema] = Field(default_factory=list)
    action_sequence: List[str] = Field(default_factory=list, example=["create_incident", "notify_security_team", "quarantine_simulation"])
    approval_required: bool = False
    cooldown_seconds: int = 300
    timeout_seconds: int = 60
    retry_policy: Optional[Dict[str, Any]] = Field(default_factory=dict)


class PlaybookRead(BaseModel):
    id: str
    playbook_id: str
    name: str
    description: Optional[str] = None
    enabled: bool
    severity_threshold: str
    risk_score_threshold: float
    trigger_conditions: List[Dict[str, Any]]
    action_sequence: List[str]
    approval_required: bool
    cooldown_seconds: int
    timeout_seconds: int
    retry_policy: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ResponseExecutionRead(BaseModel):
    id: str
    execution_id: str
    playbook_id: str
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    status: str
    mode: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    verification_status: str
    error_code: Optional[str] = None
    result_metadata: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class ResponseApprovalDecision(BaseModel):
    reason: Optional[str] = Field(None, example="Approved containment per SOC triage procedure.")
