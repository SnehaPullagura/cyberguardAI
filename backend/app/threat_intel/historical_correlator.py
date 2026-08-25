import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.models.event import SecurityEvent
from app.models.threat_intel import ThreatIoC

logger = logging.getLogger(__name__)


class HistoricalIoCCorrelator:
    """Performs retroactive correlation scans of new Threat IoCs against historical Security Events."""

    def correlate_ioc(
        self,
        db: Session,
        ioc: ThreatIoC,
        lookback_days: int = 7,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Queries historical security events within lookback window matching the specified IoC value."""
        cutoff_date = datetime.utcnow() - timedelta(days=lookback_days)
        val = ioc.value.strip()

        matched_events: List[SecurityEvent] = []

        if ioc.ioc_type in ["ip", "ipv4-addr", "ipv6-addr"]:
            matched_events = (
                db.query(SecurityEvent)
                .filter(
                    SecurityEvent.timestamp >= cutoff_date,
                    or_(
                        SecurityEvent.source_ip == val,
                        SecurityEvent.destination_ip == val,
                    ),
                )
                .limit(limit)
                .all()
            )
        elif ioc.ioc_type in ["domain", "url", "sha256", "md5"]:
            # Match against raw_payload string or event attributes
            matched_events = (
                db.query(SecurityEvent)
                .filter(
                    SecurityEvent.timestamp >= cutoff_date,
                    SecurityEvent.raw_payload.contains(val),
                )
                .limit(limit)
                .all()
            )

        results = []
        for ev in matched_events:
            results.append({
                "event_id": ev.event_id,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "source_type": ev.source_type,
                "category": ev.category,
                "action": ev.action,
                "source_ip": ev.source_ip,
                "destination_ip": ev.destination_ip,
                "matched_ioc": val,
                "threat_type": ioc.threat_type,
                "mitre_attack_id": ioc.mitre_attack_id,
            })

        logger.info(f"[CORRELATOR] Retroactive scan for IoC '{val}' found {len(results)} historical events.")
        return results


historical_correlator = HistoricalIoCCorrelator()
