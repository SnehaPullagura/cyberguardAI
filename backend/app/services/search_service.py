import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.models.investigation import InvestigationCase, SavedSearch
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.models.threat_intel import ThreatIoC
from app.models.user import User

logger = logging.getLogger(__name__)


class SearchService:
    """Global Multi-Entity Search and Saved Filter Evaluator."""

    def global_search(self, db: Session, query_str: str, limit: int = 15) -> Dict[str, Any]:
        """Performs global search across Cases, Alerts, Security Events, and Threat IoCs."""
        q = f"%{query_str.strip()}%"

        # 1. Cases
        cases = (
            db.query(InvestigationCase)
            .filter(
                or_(
                    InvestigationCase.case_id.ilike(q),
                    InvestigationCase.title.ilike(q),
                    InvestigationCase.description.ilike(q),
                )
            )
            .limit(limit)
            .all()
        )

        # 2. Alerts
        alerts = (
            db.query(Alert)
            .filter(
                or_(
                    Alert.title.ilike(q),
                    Alert.source_entity.ilike(q),
                    Alert.target_entity.ilike(q),
                    Alert.description.ilike(q),
                )
            )
            .limit(limit)
            .all()
        )

        # 3. Events
        events = (
            db.query(SecurityEvent)
            .filter(
                or_(
                    SecurityEvent.source_ip.ilike(q),
                    SecurityEvent.destination_ip.ilike(q),
                    SecurityEvent.action.ilike(q),
                    SecurityEvent.raw_payload.ilike(q),
                )
            )
            .limit(limit)
            .all()
        )

        # 4. Threat IoCs
        iocs = (
            db.query(ThreatIoC)
            .filter(
                or_(
                    ThreatIoC.value.ilike(q),
                    ThreatIoC.description.ilike(q),
                    ThreatIoC.threat_type.ilike(q),
                )
            )
            .limit(limit)
            .all()
        )

        return {
            "query": query_str,
            "results": {
                "cases": [
                    {"id": c.id, "case_id": c.case_id, "title": c.title, "severity": c.severity, "status": c.status}
                    for c in cases
                ],
                "alerts": [
                    {"id": a.id, "title": a.title, "severity": a.severity, "source_entity": a.source_entity}
                    for a in alerts
                ],
                "events": [
                    {"event_id": e.event_id, "action": e.action, "source_ip": e.source_ip, "timestamp": e.timestamp.isoformat() if e.timestamp else None}
                    for e in events
                ],
                "threat_iocs": [
                    {"id": i.id, "value": i.value, "ioc_type": i.ioc_type, "threat_type": i.threat_type}
                    for i in iocs
                ],
            },
            "total_matches": len(cases) + len(alerts) + len(events) + len(iocs),
        }

    def create_saved_search(
        self,
        db: Session,
        user: User,
        name: str,
        target_entity: str,
        filter_params: Dict[str, Any],
        description: Optional[str] = None,
    ) -> SavedSearch:
        """Saves a user search filter."""
        saved = SavedSearch(
            name=name,
            description=description,
            user_id=user.id,
            target_entity=target_entity,
            filter_params=filter_params,
        )
        db.add(saved)
        db.commit()
        db.refresh(saved)
        return saved


search_service = SearchService()
