import uuid
from datetime import datetime
import pytest
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationCase
from app.models.incident import Incident, IncidentAlert
from app.models.alert import Alert
from app.services.investigation_service import investigation_service
from app.services.entity_graph_service import entity_graph_service


def test_entity_graph_construction(db_session: Session):
    # 1. Create Alert with source and target entity
    alert = Alert(
        id=str(uuid.uuid4()),
        alert_id=f"ALT-{uuid.uuid4().hex[:6].upper()}",
        title="SSH Brute Force Detected",
        severity="high",
        risk_score=85.0,
        source_entity="198.51.100.33",
        target_entity="10.0.0.15",
        status="open",
        detection_source="rule",
    )
    db_session.add(alert)
    db_session.commit()

    # 2. Create Incident linking Alert
    incident = Incident(
        id=str(uuid.uuid4()),
        incident_id=f"INC-{uuid.uuid4().hex[:6].upper()}",
        title="Compromised Linux Bastion",
        severity="high",
        risk_score=85.0,
        status="investigating",
    )
    db_session.add(incident)
    db_session.commit()

    inc_alert = IncidentAlert(incident_id=incident.id, alert_id=alert.id)
    db_session.add(inc_alert)
    db_session.commit()

    # 3. Create Case linking Incident
    case = investigation_service.create_case(
        db=db_session,
        title="Bastion Host Security Case",
        description="Investigation into brute force on bastion host.",
        incident_id=incident.id,
    )

    # 4. Attach Evidence with User and Hash
    investigation_service.add_evidence(
        db=db_session,
        case_id=case.id,
        evidence_type="ioc",
        title="C2 Connection Evidence",
        data={
            "source_ip": "198.51.100.33",
            "user": "root",
            "hash": "abcdef1234567890abcdef1234567890",
        },
    )

    # 5. Build Graph
    graph = entity_graph_service.build_case_graph(db=db_session, case_id=case.id)
    assert graph["case_id"] == case.case_id
    assert graph["nodes_count"] >= 5
    assert graph["edges_count"] >= 4

    # Verify node types exist
    node_types = {n["type"] for n in graph["nodes"]}
    assert "case" in node_types
    assert "incident" in node_types
    assert "alert" in node_types
    assert "entity" in node_types
    assert "evidence" in node_types
    assert "user" in node_types
    assert "file_hash" in node_types


def test_entity_graph_empty_or_missing_case(db_session: Session):
    graph = entity_graph_service.build_case_graph(db=db_session, case_id="CASE-NON-EXISTENT")
    assert graph["nodes_count"] == 0
    assert graph["edges_count"] == 0


def test_entity_graph_deduplication(db_session: Session):
    case = investigation_service.create_case(
        db=db_session,
        title="Deduplication Test Case",
    )
    # Add multiple evidence referring to same IP
    investigation_service.add_evidence(
        db=db_session,
        case_id=case.id,
        evidence_type="ioc",
        title="Evidence 1",
        data={"source_ip": "203.0.113.5"},
    )
    investigation_service.add_evidence(
        db=db_session,
        case_id=case.id,
        evidence_type="ioc",
        title="Evidence 2",
        data={"source_ip": "203.0.113.5"},
    )
    graph = entity_graph_service.build_case_graph(db=db_session, case_id=case.id)
    ip_nodes = [n for n in graph["nodes"] if n["id"] == "ip:203.0.113.5"]
    assert len(ip_nodes) == 1  # Node is deduplicated
