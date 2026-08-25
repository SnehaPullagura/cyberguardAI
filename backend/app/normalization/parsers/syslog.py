import re
import uuid
from datetime import datetime
from typing import Optional
from app.normalization.base import BaseLogParser
from app.schemas.event import (
    SecurityEventCreate,
    ObserverSchema,
    EndpointSchema,
    ProcessSchema,
)


class SyslogParser(BaseLogParser):
    """Parser for Linux Syslog (RFC3164 / RFC5424)."""

    SYSLOG_PATTERN = re.compile(
        r"^(?:<\d+>)?(?:1\s+)?(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\.\-]+)\s+(?P<app>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
    )

    SSHD_FAIL_PATTERN = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+)"
    )
    SSHD_SUCCESS_PATTERN = re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+)"
    )
    SUDO_PATTERN = re.compile(
        r"(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<cmd>.+)"
    )

    def can_parse(self, raw_log: str, source_type: Optional[str] = None) -> bool:
        if source_type == "syslog":
            return True
        if "Failed password" in raw_log or "Accepted password" in raw_log or "sshd" in raw_log:
            return True
        return bool(self.SYSLOG_PATTERN.match(raw_log.strip()))

    def parse(self, raw_log: str) -> SecurityEventCreate:
        raw_clean = raw_log.strip()
        match = self.SYSLOG_PATTERN.match(raw_clean)

        observer_host = "unknown"
        app_name = "sshd" if ("sshd" in raw_clean or "password" in raw_clean) else "syslog"
        pid = None
        message = raw_clean
        timestamp = datetime.utcnow()

        if match:
            gd = match.groupdict()
            observer_host = gd.get("host") or observer_host
            app_name = gd.get("app") or app_name
            pid = int(gd["pid"]) if gd.get("pid") else None
            message = gd.get("message") or message
            ts_str = gd.get("timestamp")
            if ts_str:
                try:
                    if ts_str.endswith("Z"):
                        timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except Exception:
                    pass

        category = "system"
        action = "log_event"
        severity = "info"
        source_user = None
        source_ip = None
        source_port = None
        process_cmd = None

        # Determine Specific Linux Event Patterns
        if "sshd" in app_name.lower() or "password" in message.lower():
            category = "authentication"
            fail_match = self.SSHD_FAIL_PATTERN.search(message)
            if fail_match:
                action = "login_failed"
                severity = "high"
                source_user = fail_match.group("user")
                source_ip = fail_match.group("ip")
                source_port = int(fail_match.group("port"))
            else:
                success_match = self.SSHD_SUCCESS_PATTERN.search(message)
                if success_match:
                    action = "login_success"
                    severity = "info"
                    source_user = success_match.group("user")
                    source_ip = success_match.group("ip")
                    source_port = int(success_match.group("port"))

        elif "sudo" in app_name.lower():
            category = "iam"
            action = "privilege_escalation"
            severity = "medium"
            sudo_match = self.SUDO_PATTERN.search(message)
            if sudo_match:
                source_user = sudo_match.group("user")
                process_cmd = sudo_match.group("cmd")

        return SecurityEventCreate(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            source_type="syslog",
            category=category,
            action=action,
            severity=severity,
            observer=ObserverSchema(hostname=observer_host),
            source=EndpointSchema(ip=source_ip, port=source_port, user=source_user),
            process=ProcessSchema(name=app_name, pid=pid, command_line=process_cmd),
            raw_payload=raw_clean,
            normalized_payload={
                "parser": "SyslogParser",
                "app": app_name,
                "message": message,
            },
        )
