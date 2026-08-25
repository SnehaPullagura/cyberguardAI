from enum import Enum
from typing import List, Set, Union
from fastapi import Depends, HTTPException, status
from app.models.user import User
from app.security.auth import get_current_user


class Permission(str, Enum):
    EVENTS_READ = "events:read"
    EVENTS_INGEST = "events:ingest"

    ALERTS_READ = "alerts:read"
    ALERTS_UPDATE = "alerts:update"

    INCIDENTS_READ = "incidents:read"
    INCIDENTS_CREATE = "incidents:create"
    INCIDENTS_UPDATE = "incidents:update"

    RULES_READ = "rules:read"
    RULES_WRITE = "rules:write"
    RULES_DELETE = "rules:delete"

    THREAT_INTEL_READ = "threat_intel:read"
    THREAT_INTEL_WRITE = "threat_intel:write"

    ML_READ = "ml:read"
    ML_TRAIN = "ml:train"

    REPORTS_READ = "reports:read"
    REPORTS_EXPORT = "reports:export"

    AUDIT_READ = "audit:read"

    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"

    # Phase 6 Automated Playbook & Response Engine Permissions
    PLAYBOOKS_READ = "playbooks:read"
    PLAYBOOKS_WRITE = "playbooks:write"
    PLAYBOOKS_EXECUTE = "playbooks:execute"
    PLAYBOOKS_APPROVE = "playbooks:approve"
    RESPONSES_READ = "responses:read"
    RESPONSES_EXECUTE = "responses:execute"


# Role Permission Mappings
ROLE_PERMISSIONS = {
    "admin": set(Permission),
    "security_analyst": {
        Permission.EVENTS_READ,
        Permission.EVENTS_INGEST,
        Permission.ALERTS_READ,
        Permission.ALERTS_UPDATE,
        Permission.INCIDENTS_READ,
        Permission.INCIDENTS_CREATE,
        Permission.INCIDENTS_UPDATE,
        Permission.RULES_READ,
        Permission.RULES_WRITE,
        Permission.THREAT_INTEL_READ,
        Permission.THREAT_INTEL_WRITE,
        Permission.ML_READ,
        Permission.ML_TRAIN,
        Permission.REPORTS_READ,
        Permission.REPORTS_EXPORT,
        Permission.AUDIT_READ,
        Permission.USERS_READ,
        Permission.PLAYBOOKS_READ,
        Permission.PLAYBOOKS_EXECUTE,
        Permission.RESPONSES_READ,
        Permission.RESPONSES_EXECUTE,
    },
    "viewer": {
        Permission.EVENTS_READ,
        Permission.ALERTS_READ,
        Permission.INCIDENTS_READ,
        Permission.RULES_READ,
        Permission.THREAT_INTEL_READ,
        Permission.ML_READ,
        Permission.REPORTS_READ,
        Permission.PLAYBOOKS_READ,
        Permission.RESPONSES_READ,
    },
}


def get_role_permissions(role_name: str) -> Set[Permission]:
    """Get active permissions set for a given role name."""
    if not role_name:
        return ROLE_PERMISSIONS["viewer"]
    return ROLE_PERMISSIONS.get(role_name.lower(), ROLE_PERMISSIONS["viewer"])


def get_user_permissions(user: User) -> Set[Permission]:
    """Resolve active permissions for a user based on assigned roles and explicit permissions."""
    permissions: Set[Permission] = set()

    # 1. Resolve role-based permissions
    if user.role:
        role_name = user.role.name.lower()
        permissions.update(ROLE_PERMISSIONS.get(role_name, set()))

    # 2. Resolve direct user permissions if attached
    if hasattr(user, "permissions") and user.permissions:
        for perm in user.permissions:
            try:
                permissions.add(Permission(perm.name))
            except ValueError:
                pass

    return permissions


def require_permission(required_permission: Permission):
    """FastAPI dependency factory enforcing backend permission checks."""

    def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        user_perms = get_user_permissions(current_user)
        if required_permission not in user_perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied. Required permission: '{required_permission.value}'",
            )
        return current_user

    return permission_checker


def require_role(required_role: str):
    """FastAPI dependency enforcing strict role check."""

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if not current_user.role or current_user.role.name.lower() != required_role.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied. Required role: '{required_role}'",
            )
        return current_user

    return role_checker
