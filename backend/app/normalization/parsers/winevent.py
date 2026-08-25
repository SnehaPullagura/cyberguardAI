import json
import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from app.normalization.base import BaseLogParser
from app.schemas.event import (
    SecurityEventCreate,
    ObserverSchema,
    EndpointSchema,
    ProcessSchema,
)


class WinEventParser(BaseLogParser):
    """Parser for Windows Security Event Log JSON representations."""

    EVENT_MAPPINGS = {
        4624: ("authentication", "login_success", "info"),
        4625: ("authentication", "login_failed", "high"),
        4672: ("iam", "special_privileges_assigned", "medium"),
        4688: ("process", "process_created", "info"),
        4689: ("process", "process_terminated", "info"),
        7045: ("system", "service_installed", "medium"),
        4720: ("iam", "user_created", "high"),
        4726: ("iam", "user_deleted", "high"),
    }

    def can_parse(self, raw_log: str, source_type: Optional[str] = None) -> bool:
        if source_type in ["winevent", "windows"]:
            return True
        if raw_log.strip().startswith("{") and "EventID" in raw_log:
            return True
        return False

    def parse(self, raw_log: str) -> SecurityEventCreate:
        raw_clean = raw_log.strip()
        event_id_num = 0
        computer_name = "windows-host"
        user_name = None
        source_ip = None
        process_name = None
        process_id = None
        cmd_line = None

        try:
            data: Dict[str, Any] = json.loads(raw_clean)
            event_id_num = int(data.get("EventID", 0))
            computer_name = data.get("Computer") or data.get("Host") or computer_name

            event_data = data.get("EventData", {})
            user_name = event_data.get("TargetUserName") or event_data.get("SubjectUserName")
            source_ip = event_data.get("IpAddress") or event_data.get("WorkstationName")
            process_name = event_data.get("NewProcessName") or event_data.get("ProcessName")
            process_id_raw = event_data.get("ProcessId")
            if process_id_raw:
                try:
                    process_id = int(str(process_id_raw), 16) if str(process_id_raw).startswith("0x") else int(process_id_raw)
                except ValueError:
                    process_id = None
            cmd_line = event_data.get("CommandLine")

        except Exception:
            pass

        category, action, severity = self.EVENT_MAPPINGS.get(
            event_id_num, ("system", f"winevent_{event_id_num}", "info")
        )

        return SecurityEventCreate(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            source_type="winevent",
            category=category,
            action=action,
            severity=severity,
            observer=ObserverSchema(hostname=computer_name),
            source=EndpointSchema(ip=source_ip if source_ip != "-" else None, user=user_name),
            process=ProcessSchema(
                name=process_name, pid=process_id, command_line=cmd_line
            ),
            raw_payload=raw_clean,
            normalized_payload={
                "parser": "WinEventParser",
                "windows_event_id": event_id_num,
            },
        )
