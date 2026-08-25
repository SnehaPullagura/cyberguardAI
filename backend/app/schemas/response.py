from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.response.enums import ExecutionStatus, ResponseMode, ApprovalDecision, RiskLevel


class ResponseActionExecutionResponse(BaseModel):
    id: str
    action_type: str
    action_id: Optional[str]
    status: str
    mode: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration_ms: float
    verification_status: str
    error_code: Optional[str]
    error_message: Optional[str]
    retry_count: int
    result_metadata: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True


class ResponseApprovalResponse(BaseModel):
    id: str
    approval_id: str
    execution_id: str
    incident_id: Optional[str]
    playbook_id: Optional[str]
    action_type: str
    risk_level: str
    requested_by_id: Optional[str]
    requested_at: datetime
    decided_by_id: Optional[str]
    decided_at: Optional[datetime]
    decision: str
    reason: Optional[str]
    expires_at: Optional[datetime]

    class Config:
        from_attributes = True


class ResponseExecutionResponse(BaseModel):
    id: str
    execution_id: str
    playbook_id: Optional[str]
    incident_id: Optional[str]
    alert_id: Optional[str]
    trigger_event_id: Optional[str]
    correlation_id: Optional[str]
    status: str
    mode: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration_ms: float
    triggered_by: str
    error_code: Optional[str]
    error_message: Optional[str]
    execution_depth: int
    result_metadata: Optional[Dict[str, Any]]
    action_executions: List[ResponseActionExecutionResponse] = []
    approval_requests: List[ResponseApprovalResponse] = []

    class Config:
        from_attributes = True


class ApprovalDecisionRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Operational justification for approval/rejection decision")
