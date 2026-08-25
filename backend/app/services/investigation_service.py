import uuid
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.investigation import (
    InvestigationCase,
    CaseEvidence,
    CaseTimelineEvent,
    CaseNote,
)
from app.models.user import User
from app.websockets.pubsub import publish_realtime_event
from app.schemas.websocket import RealtimeEventEnvelope
from app.services.audit_service import audit_service

logger = logging.getLogger(__name__)


class InvestigationService:
    """Manages Case Lifecycle, Evidence Attachments, Analyst Notes, and Timeline Events."""

    VALID_STATUSES = {"open", "investigating", "contained", "closed", "false_positive"}
    VALID_PRIORITIES = {"P1", "P2", "P3", "P4"}

    def create_case(
        self,
        db: Session,
        title: str,
        description: Optional[str] = None,
        severity: str = "medium",
        priority: str = "P3",
        incident_id: Optional[str] = None,
        assignee_id: Optional[str] = None,
        creator: Optional[User] = None,
        mitre_tactics: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> InvestigationCase:
        """Creates a new Investigation Case with initial timeline entry."""
        case_num = f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        case = InvestigationCase(
            case_id=case_num,
            title=title,
            description=description,
            severity=severity.lower(),
            priority=priority.upper(),
            status="open",
            incident_id=incident_id,
            assignee_id=assignee_id,
            created_by_id=creator.id if creator else None,
            mitre_tactics=mitre_tactics or [],
            tags=tags or [],
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        # Initial Timeline Event
        self.add_timeline_event(
            db=db,
            case_id=case.id,
            event_type="status_change",
            title="Case Opened",
            description=f"Case {case.case_id} initialized with priority {case.priority}.",
            actor=creator.username if creator else "system",
        )

        if creator:
            audit_service.log_action(
                db=db,
                action="CASE_CREATED",
                resource="investigations",
                user_id=creator.id,
                username=creator.username,
                status="SUCCESS",
                details={"case_id": case.case_id, "priority": case.priority, "severity": case.severity},
            )

        publish_realtime_event(
            RealtimeEventEnvelope(
                type="case_updated",
                data={"case_id": case.case_id, "title": case.title, "status": case.status, "priority": case.priority},
            )
        )

        return case

    def update_case_status(
        self,
        db: Session,
        case: InvestigationCase,
        new_status: str,
        actor: Optional[User] = None,
    ) -> InvestigationCase:
        """Transitions case status and logs timeline event."""
        if new_status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status '{new_status}'. Allowed: {self.VALID_STATUSES}")

        old_status = case.status
        case.status = new_status
        if new_status in ["closed", "false_positive"]:
            case.closed_at = datetime.utcnow()

        db.commit()
        db.refresh(case)

        self.add_timeline_event(
            db=db,
            case_id=case.id,
            event_type="status_change",
            title=f"Status Changed: {old_status.upper()} → {new_status.upper()}",
            description=f"Case status transitioned to {new_status}.",
            actor=actor.username if actor else "system",
        )

        publish_realtime_event(
            RealtimeEventEnvelope(
                type="case_updated",
                data={"case_id": case.case_id, "status": case.status, "old_status": old_status},
            )
        )

        return case

    def assign_case(
        self,
        db: Session,
        case: InvestigationCase,
        assignee_id: str,
        actor: Optional[User] = None,
    ) -> InvestigationCase:
        """Assigns case to an analyst."""
        assignee = db.query(User).filter(User.id == assignee_id).first()
        if not assignee:
            raise ValueError(f"User ID '{assignee_id}' not found.")

        case.assignee_id = assignee.id
        db.commit()
        db.refresh(case)

        self.add_timeline_event(
            db=db,
            case_id=case.id,
            event_type="status_change",
            title="Case Assigned",
            description=f"Assigned to analyst {assignee.username}.",
            actor=actor.username if actor else "system",
        )

        publish_realtime_event(
            RealtimeEventEnvelope(
                type="case_assigned",
                data={"case_id": case.case_id, "assignee": assignee.username, "assignee_id": assignee.id},
            )
        )

        return case

    def add_evidence(
        self,
        db: Session,
        case_id: str,
        evidence_type: str,
        title: str,
        data: Dict[str, Any],
        actor: Optional[User] = None,
    ) -> CaseEvidence:
        """Attaches an evidence artifact to the case and creates a timeline record."""
        evidence = CaseEvidence(
            case_id=case_id,
            evidence_type=evidence_type,
            title=title,
            data=data,
            added_by_id=actor.id if actor else None,
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)

        self.add_timeline_event(
            db=db,
            case_id=case_id,
            event_type="evidence",
            title=f"Evidence Attached: {title}",
            description=f"Type: {evidence_type}",
            actor=actor.username if actor else "system",
            metadata_json={"evidence_id": evidence.id, "evidence_type": evidence_type},
        )

        publish_realtime_event(
            RealtimeEventEnvelope(
                type="evidence_added",
                data={"case_id": case_id, "evidence_id": evidence.id, "title": title},
            )
        )

        return evidence

    def add_note(
        self,
        db: Session,
        case_id: str,
        content: str,
        author: User,
    ) -> CaseNote:
        """Appends analyst note and adds to timeline."""
        note = CaseNote(
            case_id=case_id,
            author_id=author.id,
            content=content,
        )
        db.add(note)
        db.commit()
        db.refresh(note)

        self.add_timeline_event(
            db=db,
            case_id=case_id,
            event_type="note",
            title="Analyst Note Added",
            description=content[:200] + ("..." if len(content) > 200 else ""),
            actor=author.username,
        )

        return note

    def add_timeline_event(
        self,
        db: Session,
        case_id: str,
        event_type: str,
        title: str,
        description: Optional[str] = None,
        actor: Optional[str] = "system",
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> CaseTimelineEvent:
        """Adds a discrete timeline event to the case."""
        timeline_event = CaseTimelineEvent(
            case_id=case_id,
            event_type=event_type,
            title=title,
            description=description,
            actor=actor,
            metadata_json=metadata_json or {},
        )
        db.add(timeline_event)
        db.commit()
        db.refresh(timeline_event)
        return timeline_event


investigation_service = InvestigationService()
