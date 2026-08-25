from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.investigation import (
    InvestigationCase,
    CaseEvidence,
    CaseTimelineEvent,
    CaseNote,
    SavedSearch,
)
from app.models.user import User
from app.schemas.investigation import (
    CaseCreate,
    CaseUpdate,
    CaseAssignRequest,
    CaseRead,
    EvidenceCreate,
    EvidenceRead,
    TimelineEventRead,
    NoteCreate,
    NoteRead,
    SavedSearchCreate,
    SavedSearchRead,
)
from app.security.rbac import require_permission, Permission
from app.services.investigation_service import investigation_service
from app.services.entity_graph_service import entity_graph_service
from app.services.search_service import search_service

router = APIRouter(prefix="/investigations", tags=["Investigation Workspace"])


# --- Cases CRUD ---

@router.get("/cases", response_model=List[CaseRead])
def list_cases(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    assignee_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_READ)),
):
    """List investigation cases with optional filters."""
    query = db.query(InvestigationCase)
    if status:
        query = query.filter(InvestigationCase.status == status.lower())
    if priority:
        query = query.filter(InvestigationCase.priority == priority.upper())
    if severity:
        query = query.filter(InvestigationCase.severity == severity.lower())
    if assignee_id:
        query = query.filter(InvestigationCase.assignee_id == assignee_id)

    return query.order_by(InvestigationCase.created_at.desc()).all()


@router.post("/cases", response_model=CaseRead, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_WRITE)),
):
    """Create a new investigation case."""
    case = investigation_service.create_case(
        db=db,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        priority=payload.priority,
        incident_id=payload.incident_id,
        assignee_id=payload.assignee_id,
        creator=current_user,
        mitre_tactics=payload.mitre_tactics,
        tags=payload.tags,
    )
    return case


@router.get("/cases/{case_id}", response_model=CaseRead)
def get_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_READ)),
):
    """Retrieve an investigation case by ID or Case number."""
    case = db.query(InvestigationCase).filter(
        (InvestigationCase.id == case_id) | (InvestigationCase.case_id == case_id)
    ).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case


@router.patch("/cases/{case_id}", response_model=CaseRead)
def update_case(
    case_id: str,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_WRITE)),
):
    """Update case status, priority, severity, or notes."""
    case = db.query(InvestigationCase).filter(
        (InvestigationCase.id == case_id) | (InvestigationCase.case_id == case_id)
    ).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    if payload.status and payload.status != case.status:
        investigation_service.update_case_status(
            db=db, case=case, new_status=payload.status, actor=current_user
        )

    if payload.title:
        case.title = payload.title
    if payload.description is not None:
        case.description = payload.description
    if payload.priority:
        case.priority = payload.priority.upper()
    if payload.severity:
        case.severity = payload.severity.lower()
    if payload.mitre_tactics is not None:
        case.mitre_tactics = payload.mitre_tactics
    if payload.tags is not None:
        case.tags = payload.tags

    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(case)
    return case


@router.post("/cases/{case_id}/assign", response_model=CaseRead)
def assign_case_endpoint(
    case_id: str,
    payload: CaseAssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_ASSIGN)),
):
    """Assign case to a specific analyst."""
    case = db.query(InvestigationCase).filter(
        (InvestigationCase.id == case_id) | (InvestigationCase.case_id == case_id)
    ).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    try:
        updated = investigation_service.assign_case(
            db=db, case=case, assignee_id=payload.assignee_id, actor=current_user
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- Timeline & Entity Graph ---

@router.get("/cases/{case_id}/timeline", response_model=List[TimelineEventRead])
def get_case_timeline(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_READ)),
):
    """Get aggregated chronological timeline for an investigation case."""
    case = db.query(InvestigationCase).filter(
        (InvestigationCase.id == case_id) | (InvestigationCase.case_id == case_id)
    ).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    return (
        db.query(CaseTimelineEvent)
        .filter(CaseTimelineEvent.case_id == case.id)
        .order_by(CaseTimelineEvent.timestamp.asc())
        .all()
    )


@router.get("/cases/{case_id}/graph")
def get_case_entity_graph(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_READ)),
):
    """Generates interactive multi-hop Entity Relationship Graph for the case."""
    graph_data = entity_graph_service.build_case_graph(db=db, case_id=case_id)
    return graph_data


# --- Evidence Attachments ---

@router.post("/cases/{case_id}/evidence", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED)
def attach_evidence(
    case_id: str,
    payload: EvidenceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_WRITE)),
):
    """Attach evidence artifact to the case."""
    case = db.query(InvestigationCase).filter(
        (InvestigationCase.id == case_id) | (InvestigationCase.case_id == case_id)
    ).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    evidence = investigation_service.add_evidence(
        db=db,
        case_id=case.id,
        evidence_type=payload.evidence_type,
        title=payload.title,
        data=payload.data,
        actor=current_user,
    )
    return evidence


@router.get("/cases/{case_id}/evidence", response_model=List[EvidenceRead])
def list_case_evidence(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_READ)),
):
    """List all evidence artifacts attached to a case."""
    case = db.query(InvestigationCase).filter(
        (InvestigationCase.id == case_id) | (InvestigationCase.case_id == case_id)
    ).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    return (
        db.query(CaseEvidence)
        .filter(CaseEvidence.case_id == case.id)
        .order_by(CaseEvidence.created_at.desc())
        .all()
    )


# --- Analyst Notes ---

@router.post("/cases/{case_id}/notes", response_model=NoteRead, status_code=status.HTTP_201_CREATED)
def add_case_note(
    case_id: str,
    payload: NoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_WRITE)),
):
    """Add an analyst note to the case."""
    case = db.query(InvestigationCase).filter(
        (InvestigationCase.id == case_id) | (InvestigationCase.case_id == case_id)
    ).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    note = investigation_service.add_note(
        db=db,
        case_id=case.id,
        content=payload.content,
        author=current_user,
    )
    return note


@router.get("/cases/{case_id}/notes", response_model=List[NoteRead])
def list_case_notes(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_READ)),
):
    """List all analyst notes for a case."""
    case = db.query(InvestigationCase).filter(
        (InvestigationCase.id == case_id) | (InvestigationCase.case_id == case_id)
    ).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    return (
        db.query(CaseNote)
        .filter(CaseNote.case_id == case.id)
        .order_by(CaseNote.created_at.desc())
        .all()
    )


# --- Global Search & Saved Searches ---

@router.get("/search")
def global_search_endpoint(
    q: str = Query(..., min_length=1),
    limit: int = Query(15, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_READ)),
):
    """Performs global search across Cases, Alerts, Events, and Threat IoCs."""
    return search_service.global_search(db=db, query_str=q, limit=limit)


@router.get("/saved-searches", response_model=List[SavedSearchRead])
def list_saved_searches(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_READ)),
):
    """List saved searches for current user."""
    return (
        db.query(SavedSearch)
        .filter(SavedSearch.user_id == current_user.id)
        .order_by(SavedSearch.created_at.desc())
        .all()
    )


@router.post("/saved-searches", response_model=SavedSearchRead, status_code=status.HTTP_201_CREATED)
def create_saved_search(
    payload: SavedSearchCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.CASES_WRITE)),
):
    """Save a search filter."""
    return search_service.create_saved_search(
        db=db,
        user=current_user,
        name=payload.name,
        target_entity=payload.target_entity,
        filter_params=payload.filter_params,
        description=payload.description,
    )
