import os
import re
import pytest
from app.models.user import User, Role
from app.models.response_execution import ResponseExecution
from app.response.approval_service import approval_service
from app.security.password import get_password_hash


def test_self_approval_forbidden(db_session):
    analyst_role = db_session.query(Role).filter(Role.name == "security_analyst").first()
    if not analyst_role:
        analyst_role = Role(name="security_analyst")
        db_session.add(analyst_role)
        db_session.commit()

    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(name="admin")
        db_session.add(admin_role)
        db_session.commit()

    requester_admin = User(
        username="admin_requester",
        email="admin_req@cyberguard.local",
        hashed_password=get_password_hash("AdminPass123!"),
        role=admin_role,
        is_active=True,
    )
    db_session.add(requester_admin)
    db_session.commit()

    execution = ResponseExecution(
        execution_id="EXEC-SEC-SELF-APPR",
        status="pending_approval",
        mode="authorized_execution",
        triggered_by="admin_requester",
    )
    db_session.add(execution)
    db_session.commit()

    # Attempting self-approval should raise PermissionError
    with pytest.raises(PermissionError, match="Self-approval is strictly forbidden"):
        approval_service.approve_execution(
            db=db_session,
            execution_id=execution.execution_id,
            approver=requester_admin,
            reason="Self approving",
        )


def test_analyst_without_approve_permission_cannot_approve(db_session):
    analyst_role = db_session.query(Role).filter(Role.name == "security_analyst").first()
    analyst_user = User(
        username="analyst_bob",
        email="bob@cyberguard.local",
        hashed_password=get_password_hash("AnalystPass123!"),
        role=analyst_role,
        is_active=True,
    )
    db_session.add(analyst_user)
    db_session.commit()

    execution = ResponseExecution(
        execution_id="EXEC-SEC-ANALYST-APPR",
        status="pending_approval",
        mode="authorized_execution",
        triggered_by="system",
    )
    db_session.add(execution)
    db_session.commit()

    with pytest.raises(PermissionError, match="Approver lacks 'playbooks:approve' permission"):
        approval_service.approve_execution(
            db=db_session,
            execution_id=execution.execution_id,
            approver=analyst_user,
            reason="Analyst approving",
        )


def test_no_arbitrary_code_or_subprocess_in_response_subsystem():
    """Security audit: verify absence of eval(), exec(), subprocess, or os.system in response engine."""
    response_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "app", "response"))
    forbidden_patterns = [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"subprocess\.",
        r"os\.system\s*\(",
        r"os\.popen\s*\(",
    ]

    for root, _, files in os.walk(response_dir):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    for pat in forbidden_patterns:
                        match = re.search(pat, content)
                        assert match is None, f"Forbidden security pattern '{pat}' found in {filepath}"
