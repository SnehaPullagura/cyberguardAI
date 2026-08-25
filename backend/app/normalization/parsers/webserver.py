import re
import uuid
from datetime import datetime
from typing import Optional
from app.normalization.base import BaseLogParser
from app.schemas.event import (
    SecurityEventCreate,
    ObserverSchema,
    EndpointSchema,
)


class WebServerParser(BaseLogParser):
    """Parser for Nginx and Apache Web Server access logs."""

    # Combined Log Format: 192.168.1.10 - - [25/Aug/2026:10:00:00 +0000] "GET /admin/login HTTP/1.1" 401 532 "https://example.com" "Mozilla/5.0"
    LOG_PATTERN = re.compile(
        r'^(?P<client_ip>[\d\.\:]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+HTTP\/(?P<http_ver>[\d\.]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    def can_parse(self, raw_log: str, source_type: Optional[str] = None) -> bool:
        if source_type in ["nginx", "apache", "webserver"]:
            return True
        return bool(self.LOG_PATTERN.match(raw_log.strip()))

    def parse(self, raw_log: str) -> SecurityEventCreate:
        raw_clean = raw_log.strip()
        match = self.LOG_PATTERN.match(raw_clean)

        client_ip = "127.0.0.1"
        method = "GET"
        url = "/"
        status_code = 200
        user_agent = None

        if match:
            gd = match.groupdict()
            client_ip = gd.get("client_ip") or client_ip
            method = gd.get("method") or method
            url = gd.get("url") or url
            status_code = int(gd.get("status", 200))
            user_agent = gd.get("user_agent")

        category = "network"
        action = f"http_{method.lower()}"
        severity = "info"

        if status_code in [401, 403]:
            severity = "medium"
            action = "http_unauthorized"
        elif status_code >= 500:
            severity = "medium"
            action = "http_server_error"

        # Suspicious Web Attacks Detection in URL
        url_lower = url.lower()
        if any(sql in url_lower for sql in ["union", "select", "drop", "--", "' or '1'='1"]):
            action = "sql_injection_attempt"
            severity = "critical"
        elif any(xss in url_lower for xss in ["<script>", "javascript:", "onerror="]):
            action = "xss_attempt"
            severity = "high"
        elif "../" in url_lower or "..\\" in url_lower or "/etc/passwd" in url_lower:
            action = "path_traversal_attempt"
            severity = "high"

        return SecurityEventCreate(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            source_type="nginx",
            category=category,
            action=action,
            severity=severity,
            observer=ObserverSchema(hostname="web-gateway"),
            source=EndpointSchema(ip=client_ip),
            destination=EndpointSchema(host="web-server", port=80),
            raw_payload=raw_clean,
            normalized_payload={
                "parser": "WebServerParser",
                "method": method,
                "url": url,
                "status_code": status_code,
                "user_agent": user_agent,
            },
        )
