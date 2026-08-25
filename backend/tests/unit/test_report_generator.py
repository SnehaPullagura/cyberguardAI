import pytest
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.user import User
from app.services.report_service import report_service


def test_generate_incidents_csv(db_session: Session):
    csv_str = report_service.generate_incidents_csv(db=db_session)
    assert isinstance(csv_str, str)
    assert "Incident ID,Title,Severity,Status,Risk Score,Created At,Closed At" in csv_str


def test_generate_audit_csv(db_session: Session):
    csv_str = report_service.generate_audit_csv(db=db_session)
    assert isinstance(csv_str, str)
    assert "Timestamp,User ID,Username,Action,Resource,Status,IP Address" in csv_str


def test_generate_executive_pdf(db_session: Session):
    pdf_bytes = report_service.generate_executive_pdf(db=db_session)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0


def test_generate_compliance_pdf(db_session: Session):
    for fw in ["soc2", "iso27001", "nist_csf", "pci_dss", "hipaa"]:
        pdf_bytes = report_service.generate_compliance_pdf(db=db_session, framework=fw)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0


def test_create_report_schedule_frequencies(db_session: Session):
    admin_user = db_session.query(User).filter(User.username == "admin").first()
    
    # Daily
    sched_daily = report_service.create_schedule(
        db=db_session, name="Daily Digest", report_type="incidents", frequency="daily", user=admin_user
    )
    assert sched_daily.frequency == "daily"
    assert sched_daily.next_run is not None

    # Monthly
    sched_monthly = report_service.create_schedule(
        db=db_session, name="Monthly Audit", report_type="compliance", framework="soc2", frequency="monthly", user=admin_user
    )
    assert sched_monthly.frequency == "monthly"
    assert sched_monthly.framework == "soc2"


def test_generate_incidents_csv_with_multiple_incidents(db_session: Session):
    inc1 = Incident(incident_id="INC-CSV-1", title="Incident 1", severity="high", status="open")
    inc2 = Incident(incident_id="INC-CSV-2", title="Incident 2", severity="medium", status="closed")
    db_session.add_all([inc1, inc2])
    db_session.commit()

    csv_data = report_service.generate_incidents_csv(db=db_session)
    assert "INC-CSV-1" in csv_data
    assert "INC-CSV-2" in csv_data


def test_generate_audit_csv_with_multiple_logs(db_session: Session):
    log1 = AuditLog(action="USER_LOGIN_TEST", username="admin", resource="/api/v1/auth/login", status="SUCCESS")
    log2 = AuditLog(action="USER_LOGOUT_TEST", username="admin", resource="/api/v1/auth/logout", status="SUCCESS")
    db_session.add_all([log1, log2])
    db_session.commit()

    csv_data = report_service.generate_audit_csv(db=db_session)
    assert "USER_LOGIN_TEST" in csv_data
    assert "USER_LOGOUT_TEST" in csv_data
