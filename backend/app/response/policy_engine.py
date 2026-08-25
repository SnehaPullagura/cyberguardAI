import logging
from typing import Dict, Any, Optional, Set, Tuple
from sqlalchemy.orm import Session
from app.models.playbook import Playbook
from app.models.response_execution import ResponseExecution
from app.models.user import User
from app.response.enums import ResponseMode, RiskLevel
from app.security.rbac import Permission, get_user_permissions

logger = logging.getLogger(__name__)


class PolicyEvaluationResult:
    def __init__(self, allowed: bool, reason: str, requires_approval: bool = False, mode: ResponseMode = ResponseMode.DRY_RUN):
        self.allowed = allowed
        self.reason = reason
        self.requires_approval = requires_approval
        self.mode = mode


class ResponsePolicyEngine:
    """Evaluates playbook execution policies and enforces pre/post-approval authorization."""

    SEVERITY_ORDER = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def evaluate_playbook_policy(
        self,
        playbook: Playbook,
        context: Dict[str, Any],
        user: Optional[User] = None,
    ) -> PolicyEvaluationResult:
        """Evaluates whether the playbook is allowed to execute given the current alert/incident context."""
        # 1. Enabled check
        if not playbook.enabled:
            return PolicyEvaluationResult(allowed=False, reason=f"Playbook '{playbook.name}' is currently disabled.")

        # 2. Risk score threshold check
        context_risk = float(context.get("risk_score", 0.0))
        if context_risk < playbook.risk_score_threshold:
            return PolicyEvaluationResult(
                allowed=False,
                reason=f"Event risk score ({context_risk}) below playbook threshold ({playbook.risk_score_threshold})."
            )

        # 3. Severity threshold check
        context_sev = str(context.get("severity", "low")).lower()
        playbook_sev = str(playbook.severity_threshold).lower()
        if self.SEVERITY_ORDER.get(context_sev, 0) < self.SEVERITY_ORDER.get(playbook_sev, 2):
            return PolicyEvaluationResult(
                allowed=False,
                reason=f"Event severity ({context_sev}) below playbook severity threshold ({playbook_sev})."
            )

        # 4. RBAC check if triggered by explicit user
        if user:
            user_perms = get_user_permissions(user)
            if Permission.PLAYBOOKS_EXECUTE not in user_perms:
                return PolicyEvaluationResult(
                    allowed=False,
                    reason="User lacks 'playbooks:execute' permission."
                )

        # 5. Resolve execution mode
        try:
            mode = ResponseMode(playbook.response_mode)
        except ValueError:
            mode = ResponseMode.DRY_RUN

        requires_approval = playbook.approval_required or (mode == ResponseMode.APPROVAL_REQUIRED)
        return PolicyEvaluationResult(
            allowed=True,
            reason="Policy validation successful.",
            requires_approval=requires_approval,
            mode=mode,
        )

    def re_validate_post_approval(
        self,
        db: Session,
        execution: ResponseExecution,
        approver: User,
    ) -> Tuple[bool, str]:
        """Re-validates authorization immediately before execution after approval is granted."""
        # 1. Verify approver has PLAYBOOKS_APPROVE permission
        approver_perms = get_user_permissions(approver)
        if Permission.PLAYBOOKS_APPROVE not in approver_perms:
            return False, "Approver lacks 'playbooks:approve' permission."

        # 2. Self-approval prevention check
        if execution.triggered_by == approver.username or execution.triggered_by == approver.id:
            # Reject if requester attempts to approve their own request
            return False, "Self-approval is strictly forbidden by policy. An independent analyst or admin must approve."

        # 3. Playbook still enabled check
        if execution.playbook:
            if not execution.playbook.enabled:
                return False, f"Playbook '{execution.playbook.name}' was disabled prior to execution."

        return True, "Post-approval re-authorization verified."


policy_engine = ResponsePolicyEngine()
