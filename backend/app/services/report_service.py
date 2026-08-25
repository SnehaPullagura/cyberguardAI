import csv
import io
from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.event import SecurityEvent

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


class ReportService:
    """Generates executive PDF and CSV security summaries and compliance exports."""

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
                    inc.created_at.isoformat(),
                    inc.closed_at.isoformat() if inc.closed_at else "",
                ]
            )
        return output.getvalue()

    def generate_executive_pdf(self, db: Session) -> bytes:
        """Generate PDF report using ReportLab or fallback text bytes."""
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
                textColor=colors.HexColor("#1e293b"),
                spaceAfter=12,
            )
            story.append(Paragraph("CyberGuard AI Executive Security Summary", title_style))
            story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["Normal"]))
            story.append(Spacer(1, 18))

            story.append(Paragraph("Executive Key Security Metrics", styles["Heading2"]))
            story.append(Spacer(1, 8))

            table_data = [
                ["Metric Name", "Value"],
                ["Total Events Processed", str(total_events)],
                ["Total Security Alerts Raised", str(total_alerts)],
                ["Total Correlated Incidents", str(total_incidents)],
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
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
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
            # Fallback string representation
            report_str = (
                f"CYBERGUARD AI EXECUTIVE REPORT\n"
                f"Date: {datetime.utcnow().isoformat()}\n"
                f"Total Events: {total_events}\n"
                f"Total Alerts: {total_alerts}\n"
                f"Total Incidents: {total_incidents}\n"
                f"Critical Incidents: {critical_incidents}\n"
            )
            return report_str.encode("utf-8")


report_service = ReportService()
