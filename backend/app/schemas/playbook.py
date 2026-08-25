import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from app.response.enums import ResponseMode, RiskLevel, FailurePolicy


class TriggerConditionSchema(BaseModel):
    """Structured trigger condition without arbitrary code execution."""
    field: str = Field(..., description="Target field to evaluate, e.g. risk_score, severity, category, source_ip")
    operator: str = Field(..., description="Allowed operator: eq, ne, gt, gte, lt, lte, contains, in")
    value: Any = Field(..., description="Target comparison value")

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        allowed = {"eq", "ne", "gt", "gte", "lt", "lte", "contains", "in"}
        if v.lower() not in allowed:
            raise ValueError(f"Invalid operator '{v}'. Allowed operators: {allowed}")
        return v.lower()


class PlaybookActionConfigSchema(BaseModel):
    """Configuration for an action in a playbook sequence."""
    action_type: str = Field(..., description="Allowlisted action identifier")
    action_config: Dict[str, Any] = Field(default_factory=dict, description="Parameters passed to action adapter")
    order: int = Field(default=0)
    risk_level: RiskLevel = Field(default=RiskLevel.LOW)
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    retry_count: int = Field(default=0, ge=0, le=5)
    required_permission: str = Field(default="responses:execute")


class PlaybookCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    enabled: bool = True
    response_mode: ResponseMode = Field(default=ResponseMode.DRY_RUN)
    severity_threshold: str = Field(default="medium")
    risk_score_threshold: float = Field(default=50.0, ge=0.0, le=100.0)
    trigger_conditions: List[TriggerConditionSchema] = Field(default_factory=list)
    action_sequence: List[PlaybookActionConfigSchema] = Field(default_factory=list)
    approval_required: bool = False
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    retry_policy: Optional[Dict[str, Any]] = Field(default_factory=lambda: {"max_retries": 0, "backoff_base": 2})
    failure_policy: FailurePolicy = Field(default=FailurePolicy.STOP)


class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    response_mode: Optional[ResponseMode] = None
    severity_threshold: Optional[str] = None
    risk_score_threshold: Optional[float] = None
    trigger_conditions: Optional[List[TriggerConditionSchema]] = None
    action_sequence: Optional[List[PlaybookActionConfigSchema]] = None
    approval_required: Optional[bool] = None
    cooldown_seconds: Optional[int] = None
    timeout_seconds: Optional[int] = None
    retry_policy: Optional[Dict[str, Any]] = None
    failure_policy: Optional[FailurePolicy] = None


class PlaybookResponse(BaseModel):
    id: str
    playbook_id: str
    name: str
    description: Optional[str]
    enabled: bool
    response_mode: str
    severity_threshold: str
    risk_score_threshold: float
    trigger_conditions: List[Dict[str, Any]]
    action_sequence: List[Dict[str, Any]]
    approval_required: bool
    cooldown_seconds: int
    timeout_seconds: int
    retry_policy: Optional[Dict[str, Any]]
    failure_policy: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PlaybookTestRequest(BaseModel):
    """Payload to simulate/test a playbook safely."""
    mock_event: Optional[Dict[str, Any]] = None
    mock_alert: Optional[Dict[str, Any]] = None
    mock_incident: Optional[Dict[str, Any]] = None


class PlaybookTestResult(BaseModel):
    playbook_id: str
    playbook_name: str
    trigger_matched: bool
    matched_conditions: List[Dict[str, Any]]
    simulated_actions: List[Dict[str, Any]]
    policy_evaluation: Dict[str, Any]
    approval_required: bool
    execution_mode: str
    safety_summary: str
