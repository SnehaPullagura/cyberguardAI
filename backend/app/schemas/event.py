from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class ObserverSchema(BaseModel):
    hostname: Optional[str] = None
    ip: Optional[str] = None


class EndpointSchema(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    host: Optional[str] = None
    user: Optional[str] = None
    domain: Optional[str] = None


class ProcessSchema(BaseModel):
    name: Optional[str] = None
    pid: Optional[int] = None
    command_line: Optional[str] = None
    hash: Optional[str] = None


class SecurityEventCreate(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    source_type: str = Field(..., json_schema_extra={"example": "syslog"})
    category: str = Field(..., json_schema_extra={"example": "authentication"})
    action: str = Field(..., json_schema_extra={"example": "login_failed"})
    severity: str = Field("info", json_schema_extra={"example": "high"})

    observer: Optional[ObserverSchema] = None
    source: Optional[EndpointSchema] = None
    destination: Optional[EndpointSchema] = None
    process: Optional[ProcessSchema] = None

    raw_payload: Optional[str] = None
    normalized_payload: Optional[Dict[str, Any]] = None


class SecurityEventRead(BaseModel):
    id: str
    event_id: str
    timestamp: datetime
    ingested_at: datetime
    source_type: str
    category: str
    action: str
    severity: str

    observer_host: Optional[str] = None
    observer_ip: Optional[str] = None

    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    source_user: Optional[str] = None
    source_domain: Optional[str] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    destination_host: Optional[str] = None

    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_command_line: Optional[str] = None
    process_hash: Optional[str] = None

    raw_payload: Optional[str] = None
    normalized_payload: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class BatchEventIngestRequest(BaseModel):
    events: List[SecurityEventCreate]


class BatchEventIngestResponse(BaseModel):
    total_received: int
    total_ingested: int
    total_failed: int
    errors: List[str] = []


class EventFilterParams(BaseModel):
    source_type: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_name: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    search: Optional[str] = None
    page: int = 1
    limit: int = 50
