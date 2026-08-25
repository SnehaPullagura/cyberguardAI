import csv
import io
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.incident import Incident
from app.models.user import User
from app.security.rbac import require_permission, Permission

router = APIRouter(prefix="/reports", tags=["Executive Reporting"])


@router.get("/incidents.csv")
def export_incidents_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_EXPORT)),
):
    """Export security incident summary report in CSV format."""
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["Incident ID", "Incident Number", "Title", "Severity", "Status", "Created At"]
    )

    for inc in incidents:
        writer.writerow(
            [
                inc.id,
                inc.incident_number,
                inc.title,
                inc.severity,
                inc.status,
                inc.created_at.isoformat() if inc.created_at else "",
            ]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=incidents_report.csv"},
    )


@router.get("/executive.pdf")
def export_executive_pdf(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.REPORTS_EXPORT)),
):
    """Export executive security summary report (Placeholder PDF format)."""
    return {
        "report_type": "Executive Security Summary",
        "status": "generated",
        "generated_by": current_user.username,
        "format": "pdf",
    }
