import logging
from typing import Dict, Any, Optional, Tuple, Set
from app.response.enums import RiskLevel, ResponseMode
from app.response.action_registry import action_registry, ActionDefinition
from app.security.rbac import Permission

logger = logging.getLogger(__name__)


class SafetyValidationResult:
    def __init__(self, is_safe: bool, reason: str, requires_approval: bool = False, enforced_mode: Optional[ResponseMode] = None):
        self.is_safe = is_safe
        self.reason = reason
        self.requires_approval = requires_approval
        self.enforced_mode = enforced_mode


class ActionSafetyValidator:
    """Validates action safety, risk level, response mode boundaries, and blocks dangerous commands."""

    FORBIDDEN_CONFIG_KEYS = {"command", "cmd", "shell", "script", "code", "eval", "exec", "query", "raw_sql"}

    def validate_action_safety(
        self,
        action_type: str,
        action_config: Dict[str, Any],
        requested_mode: ResponseMode,
        user_permissions: Optional[Set[Permission]] = None,
    ) -> SafetyValidationResult:
        # 1. Verify action is allowlisted
        action_def = action_registry.get(action_type)
        if not action_def:
            return SafetyValidationResult(
                is_safe=False,
                reason=f"Action '{action_type}' is NOT in the allowlisted Action Registry. Execution blocked."
            )

        # 2. Check for dangerous command/code keys in action configuration
        for k in action_config.keys():
            if k.lower() in self.FORBIDDEN_CONFIG_KEYS:
                return SafetyValidationResult(
                    is_safe=False,
                    reason=f"Dangerous parameter '{k}' detected in action config. Arbitrary code/command execution is forbidden."
                )

        # 3. RBAC permission validation if user permissions provided
        if user_permissions is not None:
            if action_def.required_permission not in user_permissions:
                return SafetyValidationResult(
                    is_safe=False,
                    reason=f"Permission denied: Missing required permission '{action_def.required_permission.value}' for action '{action_type}'."
                )

        # 4. Enforce Safety for HIGH / CRITICAL actions
        if action_def.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            if requested_mode == ResponseMode.AUTHORIZED_EXECUTION:
                # High/Critical actions require explicit approval workflow before real execution
                return SafetyValidationResult(
                    is_safe=True,
                    reason=f"Action '{action_type}' has {action_def.risk_level.value.upper()} risk and requires approval.",
                    requires_approval=True,
                    enforced_mode=ResponseMode.APPROVAL_REQUIRED,
                )
            elif requested_mode == ResponseMode.DRY_RUN:
                return SafetyValidationResult(is_safe=True, reason="Safe dry-run", enforced_mode=ResponseMode.DRY_RUN)
            else:
                # Default to simulation adapter
                return SafetyValidationResult(is_safe=True, reason="Safe simulation", enforced_mode=ResponseMode.SIMULATION)

        # 5. Low / Medium risk actions
        return SafetyValidationResult(
            is_safe=True,
            reason="Action passed safety validation.",
            requires_approval=(requested_mode == ResponseMode.APPROVAL_REQUIRED),
            enforced_mode=requested_mode
        )


action_safety_validator = ActionSafetyValidator()
