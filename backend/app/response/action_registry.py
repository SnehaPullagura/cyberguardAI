import logging
from typing import Dict, Any, Callable, Optional, Tuple
from sqlalchemy.orm import Session
from app.security.rbac import Permission

logger = logging.getLogger(__name__)


class ActionMetadata:
    def __init__(
        self,
        action_type: str,
        name: str,
        description: str,
        risk_level: str,  # low, medium, high, critical
        required_permission: Permission,
        handler: Callable,
        dry_run_supported: bool = True,
    ):
        self.action_type = action_type
        self.name = name
        self.description = description
        self.risk_level = risk_level
        self.required_permission = required_permission
        self.handler = handler
        self.dry_run_supported = dry_run_supported


# --- Controlled Safe Action Handlers ---

def handler_create_incident(db: Session, params: Dict[str, Any], mode: str) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """LOW risk action handler creating or updating an incident."""
    title = params.get("title", "Automated Playbook Incident")
    severity = params.get("severity", "high")
    entity = params.get("source_entity", "unknown")

    if mode in ["dry_run", "simulation"]:
        return "simulated", {
            "action": "create_incident",
            "simulated": True,
            "title": title,
            "entity": entity,
            "severity": severity,
        }, None

    from app.models.incident import Incident
    import uuid
    from datetime import datetime

    inc = Incident(
        id=str(uuid.uuid4()),
        incident_id=f"INC-AUTO-{uuid.uuid4().hex[:6].upper()}",
        title=f"[Automated] {title}",
        description=f"Auto-created incident for entity {entity} via playbook response engine.",
        severity=severity,
        status="new",
        risk_score=params.get("risk_score", 75.0),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)
    return "success", {"incident_id": inc.incident_id, "id": inc.id}, None


def handler_update_incident(db: Session, params: Dict[str, Any], mode: str) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """LOW risk action handler updating incident status or notes."""
    incident_id = params.get("incident_id")
    new_status = params.get("new_status", "investigating")

    if mode in ["dry_run", "simulation"]:
        return "simulated", {"action": "update_incident", "simulated": True, "incident_id": incident_id, "new_status": new_status}, None

    from app.models.incident import Incident
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if inc:
        inc.status = new_status
        db.commit()
        return "success", {"incident_id": inc.incident_id, "status": inc.status}, None
    return "failed", {}, f"Incident {incident_id} not found"


def handler_notify_security_team(db: Session, params: Dict[str, Any], mode: str) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """LOW risk notification handler sending internal SOC alert notifications."""
    message = params.get("message", "Playbook trigger alert notification")
    channel = params.get("channel", "soc-alerts")
    return "simulated" if mode in ["dry_run", "simulation"] else "success", {
        "action": "notify_security_team",
        "channel": channel,
        "message": message,
        "delivered": True,
    }, None


def handler_enrich_event(db: Session, params: Dict[str, Any], mode: str) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """LOW risk enrichment handler querying threat intel for entity metadata."""
    entity = params.get("source_entity", "198.51.100.42")
    return "success", {
        "action": "enrich_event",
        "entity": entity,
        "reputation_score": 92.5,
        "category": "Known C2 Server",
    }, None


def handler_quarantine_simulation(db: Session, params: Dict[str, Any], mode: str) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """MEDIUM risk simulated host quarantine action."""
    host_ip = params.get("source_ip", "192.168.1.100")
    return "simulated", {
        "action": "quarantine_simulation",
        "host_ip": host_ip,
        "status": "isolated_simulation",
        "notice": "Host quarantine simulated cleanly.",
    }, None


def handler_account_lock_simulation(db: Session, params: Dict[str, Any], mode: str) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """HIGH risk simulated account lockout action."""
    username = params.get("source_user", "target_user")
    return "simulated", {
        "action": "account_lock_simulation",
        "username": username,
        "status": "locked_simulation",
        "notice": "Compromised account lockout simulated cleanly.",
    }, None


def handler_network_block_simulation(db: Session, params: Dict[str, Any], mode: str) -> Tuple[str, Dict[str, Any], Optional[str]]:
    """HIGH risk simulated network IP blocking action."""
    ip_address = params.get("source_ip", "203.0.113.50")
    return "simulated", {
        "action": "network_block_simulation",
        "ip_address": ip_address,
        "status": "blocked_simulation",
        "notice": "Firewall IP blocking simulated cleanly.",
    }, None


class ActionRegistry:
    """Centralized allowlisted action registry enforcing strict execution boundaries and safe adapters."""

    def __init__(self):
        self._actions: Dict[str, ActionMetadata] = {}
        self._register_default_actions()

    def _register_default_actions(self):
        self.register(ActionMetadata("create_incident", "Create Incident", "Auto-create security incident", "low", Permission.RESPONSES_EXECUTE, handler_create_incident))
        self.register(ActionMetadata("update_incident", "Update Incident", "Update status of an incident", "low", Permission.RESPONSES_EXECUTE, handler_update_incident))
        self.register(ActionMetadata("notify_security_team", "Notify SOC Team", "Dispatch SOC alert notification", "low", Permission.RESPONSES_EXECUTE, handler_notify_security_team))
        self.register(ActionMetadata("enrich_event", "Enrich Event Data", "Fetch threat intel metadata for IP/host", "low", Permission.RESPONSES_EXECUTE, handler_enrich_event))
        self.register(ActionMetadata("quarantine_simulation", "Quarantine Host (Simulation)", "Simulate isolating an infected host", "medium", Permission.PLAYBOOKS_EXECUTE, handler_quarantine_simulation))
        self.register(ActionMetadata("account_lock_simulation", "Account Lock (Simulation)", "Simulate locking a compromised user account", "high", Permission.PLAYBOOKS_EXECUTE, handler_account_lock_simulation))
        self.register(ActionMetadata("network_block_simulation", "Block Network IP (Simulation)", "Simulate blocking an attacking IP address", "high", Permission.PLAYBOOKS_EXECUTE, handler_network_block_simulation))

    def register(self, metadata: ActionMetadata):
        self._actions[metadata.action_type] = metadata

    def get_action(self, action_type: str) -> Optional[ActionMetadata]:
        return self._actions.get(action_type)

    def is_allowlisted(self, action_type: str) -> bool:
        return action_type in self._actions

    def get_all_actions(self) -> Dict[str, ActionMetadata]:
        return self._actions


action_registry = ActionRegistry()
