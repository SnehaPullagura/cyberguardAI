import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.models.user import User, Role
from app.models.rule import DetectionRule
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.threat_intel import ThreatIoC
from app.models.playbook import Playbook
from app.models.report import ComplianceEvaluation

logger = logging.getLogger(__name__)


class ComplianceEvaluator:
    """Evaluates organization telemetry against SOC 2, ISO 27001, NIST CSF, PCI-DSS, and HIPAA frameworks."""

    FRAMEWORKS = ["soc2", "iso27001", "nist_csf", "pci_dss", "hipaa"]

    def evaluate_framework(self, db: Session, framework: str, evaluator: User = None) -> ComplianceEvaluation:
        """Runs automated evaluation of a compliance framework against active system telemetry."""
        fw = framework.lower()
        if fw not in self.FRAMEWORKS:
            raise ValueError(f"Unsupported framework '{framework}'. Supported: {self.FRAMEWORKS}")

        if fw == "soc2":
            results = self._evaluate_soc2(db)
        elif fw == "iso27001":
            results = self._evaluate_iso27001(db)
        elif fw == "nist_csf":
            results = self._evaluate_nist_csf(db)
        elif fw == "pci_dss":
            results = self._evaluate_pci_dss(db)
        elif fw == "hipaa":
            results = self._evaluate_hipaa(db)

        # Calculate totals and score
        controls = results["controls"]
        total = len(controls)
        passed = sum(1 for c in controls if c["status"] == "PASS")
        warning = sum(1 for c in controls if c["status"] == "WARNING")
        failed = sum(1 for c in controls if c["status"] == "FAIL")

        overall_score = round((passed * 100.0 + warning * 50.0) / (total * 100.0) * 100.0, 1) if total > 0 else 0.0

        if overall_score >= 85.0:
            status = "compliant"
        elif overall_score >= 60.0:
            status = "needs_attention"
        else:
            status = "non_compliant"

        eval_record = ComplianceEvaluation(
            framework=fw,
            overall_score=overall_score,
            status=status,
            total_controls=total,
            passed_controls=passed,
            warning_controls=warning,
            failed_controls=failed,
            summary_json={
                "framework_name": results["name"],
                "framework_description": results["description"],
                "controls": controls,
                "evaluated_at": datetime.utcnow().isoformat(),
            },
            evaluated_by_id=evaluator.id if evaluator else None,
        )

        db.add(eval_record)
        db.commit()
        db.refresh(eval_record)
        return eval_record

    def _evaluate_soc2(self, db: Session) -> Dict[str, Any]:
        """Evaluates SOC 2 Type II Trust Services Criteria."""
        controls = []

        # 1. CC6.1 Logical Access Control
        admin_count = db.query(User).join(User.role).filter(Role.name == "admin").count()
        total_users = db.query(User).count()
        admin_ratio = (admin_count / total_users) if total_users > 0 else 0.0
        controls.append({
            "id": "CC6.1",
            "name": "Logical Access Security & RBAC",
            "description": "User access is restricted based on least privilege and role-based policies.",
            "status": "PASS" if admin_ratio <= 0.5 else "WARNING",
            "score": 100 if admin_ratio <= 0.5 else 70,
            "evidence": f"Total Users: {total_users}, Admin Users: {admin_count} (Ratio: {admin_ratio:.1%})",
        })

        # 2. CC7.2 Security Event Monitoring
        active_rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).count()
        controls.append({
            "id": "CC7.2",
            "name": "Security Anomaly & Event Monitoring",
            "description": "Active detection rules and ML engines continuously scan ingested telemetry.",
            "status": "PASS" if active_rules >= 3 else "WARNING",
            "score": 100 if active_rules >= 3 else 60,
            "evidence": f"Active Detection Rules: {active_rules}",
        })

        # 3. CC7.3 Incident Response & MTTR
        total_incidents = db.query(Incident).count()
        unresolved_critical = db.query(Incident).filter(
            Incident.severity == "critical",
            Incident.status.in_(["new", "triaged", "investigating"])
        ).count()
        controls.append({
            "id": "CC7.3",
            "name": "Incident Resolution & Containment",
            "description": "Security incidents are triaged, contained, and closed promptly.",
            "status": "PASS" if unresolved_critical == 0 else "WARNING",
            "score": 100 if unresolved_critical == 0 else 65,
            "evidence": f"Total Incidents: {total_incidents}, Open Critical: {unresolved_critical}",
        })

        # 4. CC8.1 Change Audit & Action Logging
        audit_count = db.query(AuditLog).count()
        controls.append({
            "id": "CC8.1",
            "name": "Comprehensive Audit Logging",
            "description": "Administrative actions and policy modifications generate persistent immutable audit records.",
            "status": "PASS" if audit_count >= 1 else "FAIL",
            "score": 100 if audit_count >= 1 else 0,
            "evidence": f"Audit Log Entries Recorded: {audit_count}",
        })

        return {
            "name": "SOC 2 Type II",
            "description": "Security, Availability, and Confidentiality Trust Services Criteria",
            "controls": controls,
        }

    def _evaluate_iso27001(self, db: Session) -> Dict[str, Any]:
        """Evaluates ISO/IEC 27001:2022 Information Security Controls."""
        controls = []

        # A.5.15 Access Control
        users_count = db.query(User).count()
        controls.append({
            "id": "A.5.15",
            "name": "Access Control Management",
            "description": "Access to security systems is controlled based on business and security requirements.",
            "status": "PASS" if users_count > 0 else "FAIL",
            "score": 100 if users_count > 0 else 0,
            "evidence": f"Provisioned Authorized Users: {users_count}",
        })

        # A.5.24 Incident Management
        playbooks_count = db.query(Playbook).filter(Playbook.enabled == True).count()
        controls.append({
            "id": "A.5.24",
            "name": "Information Security Incident Management Planning",
            "description": "Documented and automated response procedures exist for security events.",
            "status": "PASS" if playbooks_count > 0 else "WARNING",
            "score": 100 if playbooks_count > 0 else 50,
            "evidence": f"Active Automated Playbooks: {playbooks_count}",
        })

        # A.8.15 Logging
        audit_logs = db.query(AuditLog).count()
        controls.append({
            "id": "A.8.15",
            "name": "System Activity & Event Logging",
            "description": "Logs that record activities, exceptions, faults and other relevant events are produced.",
            "status": "PASS" if audit_logs > 0 else "FAIL",
            "score": 100 if audit_logs > 0 else 0,
            "evidence": f"Audit Logs: {audit_logs}",
        })

        # A.8.16 Monitoring Activities
        rules_count = db.query(DetectionRule).count()
        controls.append({
            "id": "A.8.16",
            "name": "Monitoring Activities",
            "description": "Networks, systems and applications are monitored for anomalous behavior.",
            "status": "PASS" if rules_count >= 1 else "FAIL",
            "score": 100 if rules_count >= 1 else 0,
            "evidence": f"Detection Rules Active: {rules_count}",
        })

        return {
            "name": "ISO/IEC 27001:2022",
            "description": "Information Security Management System (ISMS) Standard Controls",
            "controls": controls,
        }

    def _evaluate_nist_csf(self, db: Session) -> Dict[str, Any]:
        """Evaluates NIST Cybersecurity Framework 2.0."""
        controls = []

        # 1. ID.RA (Risk Assessment)
        iocs_count = db.query(ThreatIoC).filter(ThreatIoC.is_active == True).count()
        controls.append({
            "id": "ID.RA",
            "name": "Threat & Risk Intelligence Assessment",
            "description": "Threat vulnerabilities and IoC feeds are identified and prioritized.",
            "status": "PASS" if iocs_count > 0 else "WARNING",
            "score": 100 if iocs_count > 0 else 50,
            "evidence": f"Active Threat Indicators: {iocs_count}",
        })

        # 2. PR.AC (Identity Management and Access Control)
        roles = db.query(Role).count()
        controls.append({
            "id": "PR.AC",
            "name": "Identity Management and Access Control",
            "description": "Access to physical and logical assets is managed and verified.",
            "status": "PASS" if roles >= 3 else "WARNING",
            "score": 100 if roles >= 3 else 70,
            "evidence": f"Configured RBAC Roles: {roles}",
        })

        # 3. DE.CM (Continuous Monitoring)
        rules = db.query(DetectionRule).filter(DetectionRule.enabled == True).count()
        controls.append({
            "id": "DE.CM",
            "name": "Continuous Detection & Security Monitoring",
            "description": "The information system and assets are monitored to identify cybersecurity events.",
            "status": "PASS" if rules > 0 else "FAIL",
            "score": 100 if rules > 0 else 0,
            "evidence": f"Active Detection Rules: {rules}",
        })

        # 4. RS.AN (Incident Analysis & Response)
        incidents = db.query(Incident).count()
        controls.append({
            "id": "RS.AN",
            "name": "Incident Analysis and Containment",
            "description": "Analysis is performed to ensure effective response and support recovery.",
            "status": "PASS",
            "score": 100,
            "evidence": f"Incidents Tracked: {incidents}",
        })

        return {
            "name": "NIST CSF 2.0",
            "description": "National Institute of Standards and Technology Cybersecurity Framework",
            "controls": controls,
        }

    def _evaluate_pci_dss(self, db: Session) -> Dict[str, Any]:
        """Evaluates PCI-DSS 4.0 Standards."""
        controls = []

        # Requirement 10: Log and Monitor All Access
        audit_count = db.query(AuditLog).count()
        controls.append({
            "id": "Req 10.2",
            "name": "Audit Logging of System Access",
            "description": "Automated audit trails are enabled for all system components.",
            "status": "PASS" if audit_count > 0 else "FAIL",
            "score": 100 if audit_count > 0 else 0,
            "evidence": f"Audit Logs: {audit_count}",
        })

        # Requirement 12: Incident Response Plan
        playbooks = db.query(Playbook).count()
        controls.append({
            "id": "Req 12.10",
            "name": "Automated Incident Response Procedures",
            "description": "Maintain and execute an incident response plan for security incidents.",
            "status": "PASS" if playbooks > 0 else "WARNING",
            "score": 100 if playbooks > 0 else 60,
            "evidence": f"Playbooks: {playbooks}",
        })

        return {
            "name": "PCI-DSS 4.0",
            "description": "Payment Card Industry Data Security Standard",
            "controls": controls,
        }

    def _evaluate_hipaa(self, db: Session) -> Dict[str, Any]:
        """Evaluates HIPAA Security Rule Safeguards."""
        controls = []

        # 164.312(a)(1) Access Control
        users = db.query(User).count()
        controls.append({
            "id": "§164.312(a)(1)",
            "name": "Access Control Technical Safeguard",
            "description": "Technical policies that allow only authorized persons to access electronic protected data.",
            "status": "PASS" if users > 0 else "FAIL",
            "score": 100 if users > 0 else 0,
            "evidence": f"Configured Access Identities: {users}",
        })

        # 164.312(b) Audit Controls
        audit_logs = db.query(AuditLog).count()
        controls.append({
            "id": "§164.312(b)",
            "name": "Audit Controls Technical Safeguard",
            "description": "Hardware, software, and procedural mechanisms that record and examine activity in information systems.",
            "status": "PASS" if audit_logs > 0 else "FAIL",
            "score": 100 if audit_logs > 0 else 0,
            "evidence": f"Audit Entries: {audit_logs}",
        })

        return {
            "name": "HIPAA Security Rule",
            "description": "Health Insurance Portability and Accountability Act Technical Safeguards",
            "controls": controls,
        }


compliance_evaluator = ComplianceEvaluator()
