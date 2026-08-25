import pytest
from sqlalchemy.orm import Session

from app.models.user import User, Role
from app.models.rule import DetectionRule
from app.models.audit import AuditLog
from app.models.playbook import Playbook
from app.models.threat_intel import ThreatIoC
from app.models.incident import Incident
from app.compliance.evaluator import compliance_evaluator


def test_evaluate_soc2_framework(db_session: Session):
    admin_user = db_session.query(User).filter(User.username == "admin").first()
    
    evaluation = compliance_evaluator.evaluate_framework(
        db=db_session, framework="soc2", evaluator=admin_user
    )

    assert evaluation.framework == "soc2"
    assert evaluation.overall_score >= 0.0
    assert evaluation.total_controls == 4
    assert evaluation.passed_controls + evaluation.warning_controls + evaluation.failed_controls == 4
    assert "controls" in evaluation.summary_json
    assert len(evaluation.summary_json["controls"]) == 4


def test_evaluate_iso27001_framework(db_session: Session):
    evaluation = compliance_evaluator.evaluate_framework(db=db_session, framework="iso27001")
    assert evaluation.framework == "iso27001"
    assert evaluation.total_controls == 4
    assert evaluation.status in ["compliant", "needs_attention", "non_compliant"]


def test_evaluate_nist_csf_framework(db_session: Session):
    evaluation = compliance_evaluator.evaluate_framework(db=db_session, framework="nist_csf")
    assert evaluation.framework == "nist_csf"
    assert evaluation.total_controls == 4
    assert any(c["id"] == "DE.CM" for c in evaluation.summary_json["controls"])


def test_evaluate_pci_dss_framework(db_session: Session):
    evaluation = compliance_evaluator.evaluate_framework(db=db_session, framework="pci_dss")
    assert evaluation.framework == "pci_dss"
    assert evaluation.total_controls == 2
    assert any(c["id"] == "Req 10.2" for c in evaluation.summary_json["controls"])


def test_evaluate_hipaa_framework(db_session: Session):
    evaluation = compliance_evaluator.evaluate_framework(db=db_session, framework="hipaa")
    assert evaluation.framework == "hipaa"
    assert evaluation.total_controls == 2


def test_evaluate_unsupported_framework(db_session: Session):
    with pytest.raises(ValueError, match="Unsupported framework"):
        compliance_evaluator.evaluate_framework(db=db_session, framework="unsupported_framework_xyz")


def test_soc2_unresolved_critical_incident_warning(db_session: Session):
    crit_inc = Incident(
        incident_id="INC-CRIT-COMP-TEST",
        title="Open Critical Ransomware",
        severity="critical",
        status="investigating",
    )
    db_session.add(crit_inc)
    db_session.commit()

    evaluation = compliance_evaluator.evaluate_framework(db=db_session, framework="soc2")
    cc73 = next(c for c in evaluation.summary_json["controls"] if c["id"] == "CC7.3")
    assert cc73["status"] == "WARNING"


def test_compliance_status_tiering(db_session: Session):
    evaluation = compliance_evaluator.evaluate_framework(db=db_session, framework="soc2")
    if evaluation.overall_score >= 85.0:
        assert evaluation.status == "compliant"
    elif evaluation.overall_score >= 60.0:
        assert evaluation.status == "needs_attention"
    else:
        assert evaluation.status == "non_compliant"


def test_hipaa_controls_evaluation_detail(db_session: Session):
    eval_hipaa = compliance_evaluator.evaluate_framework(db=db_session, framework="hipaa")
    ctrl_ids = [c["id"] for c in eval_hipaa.summary_json["controls"]]
    assert "§164.312(a)(1)" in ctrl_ids
    assert "§164.312(b)" in ctrl_ids


def test_pci_dss_controls_evaluation_detail(db_session: Session):
    eval_pci = compliance_evaluator.evaluate_framework(db=db_session, framework="pci_dss")
    ctrl_ids = [c["id"] for c in eval_pci.summary_json["controls"]]
    assert "Req 10.2" in ctrl_ids
    assert "Req 12.10" in ctrl_ids
