from enum import Enum


class ResponseMode(str, Enum):
    """Execution modes for response actions and playbooks."""
    DRY_RUN = "dry_run"  # Default: evaluate and log predicted actions without execution
    SIMULATION = "simulation"  # Execute mock/simulation adapters, recording simulation results
    APPROVAL_REQUIRED = "approval_required"  # Requires human authorization before proceeding
    AUTHORIZED_EXECUTION = "authorized_execution"  # Full controlled execution after authorization


class RiskLevel(str, Enum):
    """Risk classification for actions and playbooks."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStatus(str, Enum):
    """Status lifecycle of a response execution."""
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SIMULATED = "simulated"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    COOLDOWN_SUPPRESSED = "cooldown_suppressed"


class FailurePolicy(str, Enum):
    """Failure handling behavior for multi-action playbooks."""
    STOP = "stop"  # Default: Halt execution immediately on first action failure
    CONTINUE = "continue"  # Continue executing subsequent actions despite failure


class ApprovalDecision(str, Enum):
    """Decision outcomes for human-in-the-loop approval gate."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
