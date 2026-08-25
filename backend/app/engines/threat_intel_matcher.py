from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from app.models.threat_intel import ThreatIoC
from app.schemas.event import SecurityEventCreate


class ThreatIntelMatcher:
    """Matches events against Threat Intelligence IoC feeds."""

    def check_event(
        self, db: Session, event: SecurityEventCreate
    ) -> List[Tuple[ThreatIoC, str]]:
        """Return list of matched IoCs and match details for an event."""
        matches: List[Tuple[ThreatIoC, str]] = []

        # Collect candidate values from event
        ips_to_check = []
        if event.source and event.source.ip:
            ips_to_check.append((event.source.ip, "source_ip"))
        if event.destination and event.destination.ip:
            ips_to_check.append((event.destination.ip, "destination_ip"))

        domains_to_check = []
        if event.destination and event.destination.host:
            domains_to_check.append((event.destination.host, "destination_host"))

        hashes_to_check = []
        if event.process and event.process.hash:
            hashes_to_check.append((event.process.hash, "process_hash"))

        # Query active IoCs
        for ip, field in ips_to_check:
            ioc = (
                db.query(ThreatIoC)
                .filter(
                    ThreatIoC.ioc_type == "ip",
                    ThreatIoC.value == ip,
                    ThreatIoC.is_active == True,
                )
                .first()
            )
            if ioc:
                matches.append((ioc, f"Matched {field} IP: {ip}"))

        for domain, field in domains_to_check:
            ioc = (
                db.query(ThreatIoC)
                .filter(
                    ThreatIoC.ioc_type == "domain",
                    ThreatIoC.value == domain,
                    ThreatIoC.is_active == True,
                )
                .first()
            )
            if ioc:
                matches.append((ioc, f"Matched {field} Domain: {domain}"))

        for file_hash, field in hashes_to_check:
            ioc = (
                db.query(ThreatIoC)
                .filter(
                    ThreatIoC.ioc_type.in_(["md5", "sha256"]),
                    ThreatIoC.value == file_hash,
                    ThreatIoC.is_active == True,
                )
                .first()
            )
            if ioc:
                matches.append((ioc, f"Matched {field} File Hash: {file_hash}"))

        return matches


threat_intel_matcher = ThreatIntelMatcher()
