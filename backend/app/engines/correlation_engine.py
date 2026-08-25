import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.incident import Incident, IncidentAlert


class EventCorrelationEngine:
    """Correlates related security alerts into actionable Incidents."""

    CORRELATION_WINDOW_MINUTES = 30

    def correlate_alerts(self, db: Session, alert: Alert) -> Optional[Incident]:
        """Check if alert belongs to existing active incident or create a new incident if alert severity >= high."""
        entity = alert.source_entity or alert.target_entity
        if not entity:
            return None

        window_start = datetime.utcnow() - timedelta(
            minutes=self.CORRELATION_WINDOW_MINUTES
        )

        # Search for an active incident involving the same entity in the recent window
        existing_incident = (
            db.query(Incident)
            .join(IncidentAlert)
            .join(Alert)
            .filter(
                Incident.status.in_(["new", "triaged", "investigating"]),
                Incident.updated_at >= window_start,
                (Alert.source_entity == entity) | (Alert.target_entity == entity),
            )
            .first()
        )

        if existing_incident:
            # Link alert to existing incident
            inc_alert = IncidentAlert(
                incident_id=existing_incident.id, alert_id=alert.id
            )
            db.add(inc_alert)
            existing_incident.updated_at = datetime.utcnow()

            # Upgrade incident severity if alert is more severe
            if alert.severity == "critical" and existing_incident.severity != "critical":
                existing_incident.severity = "critical"
            elif alert.severity == "high" and existing_incident.severity in ["medium", "low", "info"]:
                existing_incident.severity = "high"

            existing_incident.risk_score = min(
                100.0, existing_incident.risk_score + alert.risk_score
            )
            db.commit()
            db.refresh(existing_incident)
            return existing_incident

        # If alert is High or Critical, generate a new Incident
        if alert.severity in ["high", "critical"]:
            new_incident = Incident(
                id=str(uuid.uuid4()),
                incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                title=f"Potential Security Compromise on {entity}: {alert.title}",
                description=f"Correlated incident triggered by {alert.severity} alert '{alert.title}' on entity {entity}.",
                severity=alert.severity,
                status="new",
                risk_score=alert.risk_score,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(new_incident)
            db.flush()

            inc_alert = IncidentAlert(incident_id=new_incident.id, alert_id=alert.id)
            db.add(inc_alert)
            db.commit()
            db.refresh(new_incident)
            return new_incident

        return None


correlation_engine = EventCorrelationEngine()
