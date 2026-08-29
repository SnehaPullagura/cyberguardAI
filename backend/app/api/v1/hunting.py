"""Threat Hunting REST API Router."""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.hunting.hunting_engine import hunting_engine
from app.security.auth import get_current_active_user
from app.models.user import User

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])


class HuntQueryRequest(BaseModel):
    query: str = Field(..., description="KQL or Splunk SPL query expression")
    query_type: str = Field("kql", description="'kql' or 'spl'")
    max_results: int = Field(100, ge=1, le=1000)


@router.post("/query")
def execute_threat_hunt(
    payload: HuntQueryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Execute real-time or historical threat hunt query via KQL or SPL."""
    return hunting_engine.execute_hunt_query(
        db=db,
        query=payload.query,
        query_type=payload.query_type,
        max_results=payload.max_results,
    )


@router.get("/playbooks")
def list_hunting_playbooks(
    tactic: Optional[str] = Query(None, description="Filter by MITRE ATT&CK tactic"),
    current_user: User = Depends(get_current_active_user),
):
    """List curated proactive threat hunting hypotheses and playbooks."""
    return hunting_engine.list_playbooks(tactic=tactic)


@router.post("/playbooks/{hunt_id}/run")
def run_playbook_hunt(
    hunt_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Execute a specific threat hunting playbook against live telemetry."""
    res = hunting_engine.run_playbook_hunt(db=db, hunt_id=hunt_id)
    if res.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=res["message"])
    return res
