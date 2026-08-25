import uuid
from datetime import datetime
import pytest
from sqlalchemy.orm import Session

from app.models.user import User, Role
from app.models.investigation import InvestigationCase, CaseEvidence, CaseNote
from app.models.event import SecurityEvent
from app.models.threat_intel import ThreatIoC
from app.models.audit import AuditLog
from app.services.investigation_service import investigation_service
from app.services.search_service import search_service


def test_case_lifecycle_transitions(db_session: Session):
    # 1. Create Case
    case = investigation_service.create_case(
        db=db_session,
        title="APT29 Phishing Case",
        description="Suspected spear phishing targeting executive credentials.",
        severity="high",
        priority="P2",
        mitre_tactics=["Initial Access", "Execution"],
        tags=["apt29", "phishing"],
    )
    assert case.status == "open"
    assert case.priority == "P2"
    assert len(case.timeline_events) == 1
    assert case.timeline_events[0].event_type == "status_change"

    # 2. Transition to Investigating
    case_inv = investigation_service.update_case_status(
        db=db_session, case=case, new_status="investigating"
    )
    assert case_inv.status == "investigating"
    assert len(case.timeline_events) == 2

    # 3. Transition to Contained
    case_cont = investigation_service.update_case_status(
        db=db_session, case=case, new_status="contained"
    )
    assert case_cont.status == "contained"

    # 4. Transition to Closed -> verifies closed_at is populated
    case_closed = investigation_service.update_case_status(
        db=db_session, case=case, new_status="closed"
    )
    assert case_closed.status == "closed"
    assert case_closed.closed_at is not None

    # 5. Invalid status transition raises ValueError
    with pytest.raises(ValueError, match="Invalid status"):
        investigation_service.update_case_status(
            db=db_session, case=case, new_status="unknown_status"
        )


def test_case_evidence_and_notes(db_session: Session):
    case = investigation_service.create_case(
        db=db_session,
        title="Ransomware Outbreak Case",
        description="LockBit activity detected across subnet.",
        severity="critical",
        priority="P1",
    )

    # 1. Attach Evidence
    ev1 = investigation_service.add_evidence(
        db=db_session,
        case_id=case.id,
        evidence_type="file_hash",
        title="LockBit Binary SHA256",
        data={"hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    )
    assert ev1.id is not None
    assert ev1.evidence_type == "file_hash"

    # 2. Add Analyst Note
    admin_user = db_session.query(User).filter(User.username == "admin").first()
    note = investigation_service.add_note(
        db=db_session,
        case_id=case.id,
        content="Quarantine applied to target workstation.",
        author=admin_user,
    )
    assert note.id is not None
    assert note.content == "Quarantine applied to target workstation."

    # Check timeline events
    timeline = case.timeline_events
    event_types = [t.event_type for t in timeline]
    assert "evidence" in event_types
    assert "note" in event_types


def test_case_assignment(db_session: Session):
    case = investigation_service.create_case(
        db=db_session,
        title="Data Exfiltration Alert Case",
        description="Abnormal outbound traffic to unknown cloud storage.",
    )

    admin_user = db_session.query(User).filter(User.username == "admin").first()
    updated_case = investigation_service.assign_case(
        db=db_session,
        case=case,
        assignee_id=admin_user.id,
    )
    assert updated_case.assignee_id == admin_user.id


def test_case_invalid_assignee(db_session: Session):
    case = investigation_service.create_case(
        db=db_session,
        title="Invalid Assignee Test Case",
    )
    with pytest.raises(ValueError, match="User ID 'non-existent-user' not found"):
        investigation_service.assign_case(
            db=db_session,
            case=case,
            assignee_id="non-existent-user",
        )


def test_case_tags_and_mitre_tactics(db_session: Session):
    case = investigation_service.create_case(
        db=db_session,
        title="MITRE Tactics Case",
        mitre_tactics=["Defense Evasion", "Credential Access"],
        tags=["mimikatz", "memory_dump"],
    )
    assert len(case.mitre_tactics) == 2
    assert "mimikatz" in case.tags


def test_case_false_positive_status(db_session: Session):
    case = investigation_service.create_case(
        db=db_session,
        title="Benign Scanner Alert Case",
        severity="low",
        priority="P4",
    )
    updated = investigation_service.update_case_status(
        db=db_session, case=case, new_status="false_positive"
    )
    assert updated.status == "false_positive"
    assert updated.closed_at is not None


def test_saved_search_service_creation(db_session: Session):
    admin_user = db_session.query(User).filter(User.username == "admin").first()
    saved = search_service.create_saved_search(
        db=db_session,
        user=admin_user,
        name="Critical Incidents Filter",
        target_entity="incidents",
        filter_params={"severity": "critical"},
        description="Filter for all critical incidents.",
    )
    assert saved.id is not None
    assert saved.name == "Critical Incidents Filter"
    assert saved.target_entity == "incidents"


def test_case_multiple_notes_accumulation(db_session: Session):
    admin_user = db_session.query(User).filter(User.username == "admin").first()
    case = investigation_service.create_case(
        db=db_session,
        title="Multi-Note Case",
    )
    investigation_service.add_note(db=db_session, case_id=case.id, content="Note 1", author=admin_user)
    investigation_service.add_note(db=db_session, case_id=case.id, content="Note 2", author=admin_user)
    investigation_service.add_note(db=db_session, case_id=case.id, content="Note 3", author=admin_user)

    assert len(case.notes) == 3


def test_global_search_matching_events_and_iocs(db_session: Session):
    # Create Event
    event = SecurityEvent(
        event_id=f"evt-search-{uuid.uuid4().hex[:6]}",
        action="searchable_malicious_action",
        category="network",
        severity="high",
        source_type="syslog",
        source_ip="192.0.2.145",
        raw_payload="searchable_malicious_action test",
    )
    db_session.add(event)

    # Create IoC
    ioc = ThreatIoC(
        ioc_type="domain",
        value="searchable-c2-domain.org",
        threat_type="c2",
        source="mandiant",
        description="Searchable C2 domain test",
    )
    db_session.add(ioc)
    db_session.commit()

    search_res = search_service.global_search(db=db_session, query_str="searchable")
    assert search_res["total_matches"] >= 2
    assert any("searchable-c2-domain.org" in i["value"] for i in search_res["results"]["threat_iocs"])


def test_investigation_service_audit_logging(db_session: Session):
    admin_user = db_session.query(User).filter(User.username == "admin").first()
    case = investigation_service.create_case(
        db=db_session,
        title="Audited Case Creation",
        creator=admin_user,
    )
    audit_logs = db_session.query(AuditLog).filter(
        AuditLog.action == "CASE_CREATED",
        AuditLog.user_id == admin_user.id,
    ).all()
    assert len(audit_logs) >= 1
