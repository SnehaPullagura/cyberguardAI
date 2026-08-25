import json
import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from app.normalization.base import BaseLogParser
from app.schemas.event import (
    SecurityEventCreate,
    ObserverSchema,
    EndpointSchema,
)


class CloudTrailParser(BaseLogParser):
    """Parser for AWS CloudTrail JSON events."""

    def can_parse(self, raw_log: str, source_type: Optional[str] = None) -> bool:
        if source_type in ["cloudtrail", "aws"]:
            return True
        if raw_log.strip().startswith("{") and "eventSource" in raw_log:
            return True
        return False

    def parse(self, raw_log: str) -> SecurityEventCreate:
        raw_clean = raw_log.strip()
        event_name = "CloudTrailEvent"
        event_source = "aws"
        source_ip = None
        user_identity = None
        severity = "info"

        try:
            data: Dict[str, Any] = json.loads(raw_clean)
            event_name = data.get("eventName", event_name)
            event_source = data.get("eventSource", event_source)
            source_ip = data.get("sourceIPAddress")

            identity_data = data.get("userIdentity", {})
            user_identity = identity_data.get("userName") or identity_data.get("principalId")

            # High severity cloud events
            if event_name in ["ConsoleLogin", "CreateUser", "AttachUserPolicy", "DeleteTrail", "StopLogging"]:
                severity = "high"
                if data.get("errorMessage"):
                    severity = "critical"

        except Exception:
            pass

        return SecurityEventCreate(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            source_type="cloudtrail",
            category="iam",
            action=event_name.lower(),
            severity=severity,
            observer=ObserverSchema(hostname=event_source),
            source=EndpointSchema(ip=source_ip, user=user_identity),
            raw_payload=raw_clean,
            normalized_payload={
                "parser": "CloudTrailParser",
                "event_source": event_source,
                "event_name": event_name,
            },
        )
