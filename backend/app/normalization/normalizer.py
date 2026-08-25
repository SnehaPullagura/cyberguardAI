import uuid
from datetime import datetime
from typing import Optional, List
from app.schemas.event import (
    SecurityEventCreate,
    ObserverSchema,
    EndpointSchema,
    ProcessSchema,
)
from app.normalization.base import BaseLogParser
from app.normalization.parsers.syslog import SyslogParser
from app.normalization.parsers.winevent import WinEventParser
from app.normalization.parsers.webserver import WebServerParser
from app.normalization.parsers.cloudtrail import CloudTrailParser
from app.normalization.enrichers.geoip import GeoIPEnricher


class EventNormalizer:
    """Main Normalization Engine coordinating registered parsers and enrichers."""

    def __init__(self):
        self.parsers: List[BaseLogParser] = [
            SyslogParser(),
            WinEventParser(),
            WebServerParser(),
            CloudTrailParser(),
        ]
        self.geoip_enricher = GeoIPEnricher()

    def normalize(
        self, raw_log: str, source_type_hint: Optional[str] = None
    ) -> SecurityEventCreate:
        """Parse raw log into unified schema and apply enrichments."""
        parsed_event: Optional[SecurityEventCreate] = None

        for parser in self.parsers:
            if parser.can_parse(raw_log, source_type_hint):
                parsed_event = parser.parse(raw_log)
                break

        # Generic fallback parser if no parser matches explicitly
        if not parsed_event:
            parsed_event = SecurityEventCreate(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.utcnow(),
                source_type=source_type_hint or "generic",
                category="uncategorized",
                action="raw_log_ingest",
                severity="info",
                observer=ObserverSchema(hostname="ingestion-gateway"),
                raw_payload=raw_log,
                normalized_payload={"parser": "GenericFallbackParser"},
            )

        # Apply Enrichments
        enrichment = self.geoip_enricher.enrich(
            {
                "source_ip": parsed_event.source.ip if parsed_event.source else None,
                "destination_ip": (
                    parsed_event.destination.ip if parsed_event.destination else None
                ),
            }
        )

        if parsed_event.normalized_payload is None:
            parsed_event.normalized_payload = {}
        parsed_event.normalized_payload["enrichment"] = enrichment

        return parsed_event


normalizer = EventNormalizer()
