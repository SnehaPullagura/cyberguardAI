from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class AuditLogRead(BaseModel):
    id: str
    timestamp: datetime
    user_id: Optional[str] = None
    username: str
    ip_address: Optional[str] = None
    action: str
    resource: str
    status: str
    details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)
