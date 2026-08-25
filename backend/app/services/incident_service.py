import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy.orm import Session
from app.models.incident import Incident, IncidentNote, IncidentAlert
from app.models.alert import Alert
from app.models.user import User


class IncidentService:
    """Service managing security incidents life-cycle and triage notes."""

    def create_incident(
        self,
        db: Session,
        title: str,
        severity: str,
        description: Optional[str] = None,
        alert_ids: Optional[List[str]] = None,
    ) -> Incident:
        inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        incident = Incident(
            id=str(uuid.uuid4()),
            incident_id=inc_id,
            title=title,
            description=description,
            severity=severity,
            status="new",
            risk_score=50.0 if severity == "high" else 85.0 if severity == "critical" else 20.0,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(incident)
        db.flush()

        if alert_ids:
            for aid in alert_ids:
                inc_alert = IncidentAlert(incident_id=incident.id, alert_id=aid)
                db.add(inc_alert)

        db.commit()
        db.refresh(incident)
        return incident

    def add_note(
        self,
        db: Session,
        incident_id: str,
        author: User,
        content: str,
    ) -> IncidentNote:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found.")

        note = IncidentNote(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            author_id=author.id,
            author_name=author.username,
            content=content,
            created_at=datetime.utcnow(),
        )
        db.add(note)
        incident.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(note)
        return note

    def update_incident(
        self,
        db: Session,
        incident_id: str,
        title: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        assignee_id: Optional[str] = None,
    ) -> Incident:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found.")

        if title:
            incident.title = title
        if severity:
            incident.severity = severity
        if status:
            incident.status = status
            if status == "closed":
                incident.closed_at = datetime.utcnow()
        if assignee_id:
            incident.assignee_id = assignee_id

        incident.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(incident)
        return incident


incident_service = IncidentService()
