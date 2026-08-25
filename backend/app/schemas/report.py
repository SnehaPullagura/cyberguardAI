from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class ComplianceEvaluationRead(BaseModel):
    id: str
    framework: str
    overall_score: float
    status: str
    total_controls: int
    passed_controls: int
    warning_controls: int
    failed_controls: int
    summary_json: Dict[str, Any]
    evaluated_at: datetime
    evaluated_by_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ReportScheduleCreate(BaseModel):
    name: str
    report_type: str  # compliance, executive, audit, incidents
    framework: Optional[str] = None
    frequency: str = "weekly"  # daily, weekly, monthly
    recipients: List[str] = []
    delivery_channel: str = "email"


class ReportScheduleRead(BaseModel):
    id: str
    name: str
    report_type: str
    framework: Optional[str] = None
    frequency: str
    recipients: List[str]
    is_active: bool
    delivery_channel: str
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime
    created_by_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ReportGenerateRequest(BaseModel):
    report_type: str  # executive, compliance, incidents, audit
    format: str = "pdf"  # pdf, csv, json
    framework: Optional[str] = None
    time_window_days: Optional[int] = 30


class ReportGenerateResponse(BaseModel):
    report_id: str
    report_type: str
    format: str
    generated_at: datetime
    summary: Dict[str, Any]
