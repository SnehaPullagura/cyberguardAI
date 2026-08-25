import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.schemas.event import SecurityEventCreate
from app.engines.correlation_engine import correlation_engine


class AlertService:
    """Service managing security alerts life-cycle."""

    DEDUPLICATION_WINDOW_MINUTES = 15

    def create_alert(
        self,
        db: Session,
        title: str,
        severity: str,
        risk_score: float,
        detection_source: str,
        rule_id: Optional[str] = None,
        ioc_id: Optional[str] = None,
        source_entity: Optional[str] = None,
        target_entity: Optional[str] = None,
        description: Optional[str] = None,
        event_details: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """Create alert with deduplication check."""
        window_start = datetime.utcnow() - timedelta(
            minutes=self.DEDUPLICATION_WINDOW_MINUTES
        )

        # Deduplication check: Same title, rule_id, and source entity within 15 min window
        duplicate = (
            db.query(Alert)
            .filter(
                Alert.title == title,
                Alert.source_entity == source_entity,
                Alert.timestamp >= window_start,
                Alert.status.in_(["open", "in_review"]),
            )
            .first()
        )

        if duplicate:
            # Update duplicate score and bump timestamp
            duplicate.risk_score = max(duplicate.risk_score, risk_score)
            db.commit()
            db.refresh(duplicate)
            return duplicate

        alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
        alert = Alert(
            id=str(uuid.uuid4()),
            alert_id=alert_id,
            timestamp=datetime.utcnow(),
            rule_id=rule_id,
            ioc_id=ioc_id,
            title=title,
            description=description or f"Triggered by {detection_source} detection.",
            severity=severity,
            risk_score=risk_score,
            status="open",
            source_entity=source_entity,
            target_entity=target_entity,
            detection_source=detection_source,
            event_details=event_details,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        # Trigger event correlation to group alerts into incidents automatically
        correlation_engine.correlate_alerts(db, alert)

        return alert

    def update_alert_status(self, db: Session, alert_id: str, new_status: str) -> Alert:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise ValueError(f"Alert with ID {alert_id} not found.")

        alert.status = new_status
        db.commit()
        db.refresh(alert)
        return alert


alert_service = AlertService()
