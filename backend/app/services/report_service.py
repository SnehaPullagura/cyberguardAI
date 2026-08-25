import csv
import io
import uuid
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.models.audit import AuditLog
from app.models.report import ComplianceEvaluation, ReportSchedule
from app.models.user import User
from app.compliance.evaluator import compliance_evaluator

logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


class ReportService:
    """Enterprise Executive, Compliance, Audit, and Incident Report Generation Engine."""

    def generate_incidents_csv(self, db: Session) -> str:
        """Export incidents as CSV string."""
        incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["Incident ID", "Title", "Severity", "Status", "Risk Score", "Created At", "Closed At"]
        )
        for inc in incidents:
            writer.writerow(
                [
                    inc.incident_id,
                    inc.title,
                    inc.severity,
                    inc.status,
                    inc.risk_score,
                    inc.created_at.isoformat() if inc.created_at else "",
                    inc.closed_at.isoformat() if inc.closed_at else "",
                ]
            )
        return output.getvalue()

    def generate_audit_csv(self, db: Session) -> str:
        """Export audit trail as CSV string."""
        logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(1000).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["Timestamp", "User ID", "Username", "Action", "Resource", "Status", "IP Address"]
        )
        for l in logs:
            writer.writerow(
                [
                    l.timestamp.isoformat() if l.timestamp else "",
                    l.user_id or "",
                    l.username or "",
                    l.action,
                    l.resource or "",
                    l.status,
                    l.ip_address or "",
                ]
            )
        return output.getvalue()

    def generate_executive_pdf(self, db: Session) -> bytes:
        """Generate executive summary PDF."""
        total_events = db.query(SecurityEvent).count()
        total_alerts = db.query(Alert).count()
        total_incidents = db.query(Incident).count()
        critical_incidents = db.query(Incident).filter(Incident.severity == "critical").count()

        if HAS_REPORTLAB:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle(
                "DocTitle",
                parent=styles["Heading1"],
                fontSize=20,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=12,
            )
            story.append(Paragraph("CyberGuard AI Executive Security Report", title_style))
            story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
            story.append(Spacer(1, 14))

            story.append(Paragraph("Executive Key Security Metrics", styles["Heading2"]))
            story.append(Spacer(1, 8))

            table_data = [
                ["Security Indicator", "Value"],
                ["Total Events Processed", str(total_events)],
                ["Total Alerts Raised", str(total_alerts)],
                ["Total Incidents Correlated", str(total_incidents)],
                ["Critical Severity Incidents", str(critical_incidents)],
            ]

            t = Table(table_data, colWidths=[250, 150])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                    ]
                )
            )
            story.append(t)
            doc.build(story)
            pdf_bytes = buffer.getvalue()
            buffer.close()
            return pdf_bytes
        else:
            report_str = (
                f"CYBERGUARD AI EXECUTIVE REPORT\n"
                f"Date: {datetime.utcnow().isoformat()}\n"
                f"Total Events: {total_events}\n"
                f"Total Alerts: {total_alerts}\n"
                f"Total Incidents: {total_incidents}\n"
                f"Critical Incidents: {critical_incidents}\n"
            )
            return report_str.encode("utf-8")

    def generate_compliance_pdf(self, db: Session, framework: str) -> bytes:
        """Generate compliance evaluation PDF."""
        evaluation = compliance_evaluator.evaluate_framework(db=db, framework=framework)

        if HAS_REPORTLAB:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle(
                "DocTitle",
                parent=styles["Heading1"],
                fontSize=18,
                textColor=colors.HexColor("#0f172a"),
                spaceAfter=8,
            )
            story.append(Paragraph(f"Compliance Report: {evaluation.framework.upper()}", title_style))
            story.append(Paragraph(f"Overall Score: {evaluation.overall_score}% | Status: {evaluation.status.upper()}", styles["Heading3"]))
            story.append(Paragraph(f"Evaluated At: {evaluation.evaluated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
            story.append(Spacer(1, 14))

            controls = evaluation.summary_json.get("controls", [])
            table_data = [["Control ID", "Name", "Status", "Score"]]
            for c in controls:
                table_data.append([c["id"], c["name"][:30], c["status"], f"{c['score']}%"])

            t = Table(table_data, colWidths=[80, 200, 70, 50])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ]
                )
            )
            story.append(t)
            doc.build(story)
            pdf_bytes = buffer.getvalue()
            buffer.close()
            return pdf_bytes
        else:
            report_str = (
                f"COMPLIANCE REPORT: {evaluation.framework.upper()}\n"
                f"Overall Score: {evaluation.overall_score}%\n"
                f"Status: {evaluation.status}\n"
                f"Passed: {evaluation.passed_controls}/{evaluation.total_controls}\n"
            )
            return report_str.encode("utf-8")

    def create_schedule(
        self,
        db: Session,
        name: str,
        report_type: str,
        framework: Optional[str] = None,
        frequency: str = "weekly",
        recipients: Optional[List[str]] = None,
        delivery_channel: str = "email",
        user: Optional[User] = None,
    ) -> ReportSchedule:
        """Create a recurring report delivery schedule."""
        now = datetime.utcnow()
        if frequency == "daily":
            next_run = now + timedelta(days=1)
        elif frequency == "monthly":
            next_run = now + timedelta(days=30)
        else:
            next_run = now + timedelta(days=7)

        sched = ReportSchedule(
            name=name,
            report_type=report_type,
            framework=framework,
            frequency=frequency,
            recipients=recipients or [],
            delivery_channel=delivery_channel,
            is_active=True,
            next_run=next_run,
            created_by_id=user.id if user else None,
        )
        db.add(sched)
        db.commit()
        db.refresh(sched)
        return sched


report_service = ReportService()
