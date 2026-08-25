import csv
import io
import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Response, status, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.incident import Incident
from app.models.report import ComplianceEvaluation, ReportSchedule
from app.models.user import User
from app.schemas.report import (
    ComplianceEvaluationRead,
    ReportScheduleCreate,
    ReportScheduleRead,
    ReportGenerateRequest,
    ReportGenerateResponse,
)
from app.security.rbac import require_permission, Permission
from app.compliance.evaluator import compliance_evaluator
from app.services.report_service import report_service

router = APIRouter(prefix="/reports", tags=["Executive Reporting & Compliance"])


# --- Compliance Framework Evaluations ---

@router.get("/compliance/{framework}", response_model=ComplianceEvaluationRead)
def get_or_evaluate_compliance(
    framework: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_READ)),
):
    """Retrieve latest compliance evaluation for a framework, or run a new one."""
    latest = (
        db.query(ComplianceEvaluation)
        .filter(ComplianceEvaluation.framework == framework.lower())
        .order_by(ComplianceEvaluation.evaluated_at.desc())
        .first()
    )
    if latest:
        return latest

    try:
        evaluated = compliance_evaluator.evaluate_framework(
            db=db, framework=framework, evaluator=current_user
        )
        return evaluated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/compliance/{framework}/evaluate", response_model=ComplianceEvaluationRead)
def run_compliance_evaluation(
    framework: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_READ)),
):
    """Trigger a fresh compliance evaluation against current telemetry."""
    try:
        evaluated = compliance_evaluator.evaluate_framework(
            db=db, framework=framework, evaluator=current_user
        )
        return evaluated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/compliance-history", response_model=List[ComplianceEvaluationRead])
def list_compliance_history(
    framework: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_READ)),
):
    """List historical compliance evaluation audits."""
    query = db.query(ComplianceEvaluation)
    if framework:
        query = query.filter(ComplianceEvaluation.framework == framework.lower())
    return query.order_by(ComplianceEvaluation.evaluated_at.desc()).limit(limit).all()


# --- Exports (PDF, CSV) ---

@router.get("/export/csv")
def export_csv(
    report_type: str = Query("incidents", description="incidents or audit"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_EXPORT)),
):
    """Export tabular reports in CSV format."""
    if report_type == "audit":
        csv_content = report_service.generate_audit_csv(db)
        filename = "cyberguard_audit_trail.csv"
    else:
        csv_content = report_service.generate_incidents_csv(db)
        filename = "cyberguard_incidents.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/pdf")
def export_pdf(
    report_type: str = Query("executive", description="executive or compliance"),
    framework: Optional[str] = Query("soc2"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_EXPORT)),
):
    """Export styled PDF reports."""
    if report_type == "compliance":
        pdf_bytes = report_service.generate_compliance_pdf(db=db, framework=framework)
        filename = f"cyberguard_compliance_{framework}.pdf"
    else:
        pdf_bytes = report_service.generate_executive_pdf(db=db)
        filename = "cyberguard_executive_report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# Backward compatibility endpoints
@router.get("/incidents.csv")
def export_incidents_csv_legacy(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_EXPORT)),
):
    return export_csv(report_type="incidents", db=db, current_user=current_user)


@router.get("/executive.pdf")
def export_executive_pdf_legacy(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_EXPORT)),
):
    return export_pdf(report_type="executive", db=db, current_user=current_user)


# --- Report Generation API ---

@router.post("/generate", response_model=ReportGenerateResponse)
def generate_report_endpoint(
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_EXPORT)),
):
    """Generate structured on-demand report metadata."""
    report_id = f"RPT-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    return ReportGenerateResponse(
        report_id=report_id,
        report_type=payload.report_type,
        format=payload.format,
        generated_at=datetime.utcnow(),
        summary={
            "requested_by": current_user.username,
            "status": "ready",
            "framework": payload.framework,
            "download_url": f"/api/v1/reports/export/{payload.format}?report_type={payload.report_type}"
            + (f"&framework={payload.framework}" if payload.framework else ""),
        },
    )


# --- Report Scheduling ---

@router.get("/schedules", response_model=List[ReportScheduleRead])
def list_schedules(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_READ)),
):
    """List all scheduled recurring reports."""
    return db.query(ReportSchedule).order_by(ReportSchedule.created_at.desc()).all()


@router.post("/schedules", response_model=ReportScheduleRead, status_code=status.HTTP_201_CREATED)
def create_schedule(
    payload: ReportScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_EXPORT)),
):
    """Schedule recurring report generation and distribution."""
    return report_service.create_schedule(
        db=db,
        name=payload.name,
        report_type=payload.report_type,
        framework=payload.framework,
        frequency=payload.frequency,
        recipients=payload.recipients,
        delivery_channel=payload.delivery_channel,
        user=current_user,
    )


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_EXPORT)),
):
    """Delete a report schedule."""
    sched = db.query(ReportSchedule).filter(ReportSchedule.id == schedule_id).first()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(sched)
    db.commit()
    return None
