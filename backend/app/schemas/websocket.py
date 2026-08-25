import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class RealtimeEventEnvelope(BaseModel):
    """Standardized real-time WebSocket event message envelope."""

    message_id: str = Field(default_factory=lambda: f"msg-{uuid.uuid4()}")
    type: str = Field(..., json_schema_extra={"example": "security_event"})  # security_event, alert_created, alert_updated, incident_created, incident_updated, dashboard_metric, heartbeat, error
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    correlation_id: Optional[str] = None
    schema_version: str = "1.0"
    data: Dict[str, Any] = Field(default_factory=dict)
