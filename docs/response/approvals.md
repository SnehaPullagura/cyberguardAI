# Human-in-the-Loop Approval Gate

## Overview
High-impact actions (`HIGH` or `CRITICAL` risk) require explicit human authorization before execution.

## Approval Flow
```
High-Risk Playbook Matched
          ↓
Execution Paused (PENDING_APPROVAL)
          ↓
WebSocket Broadcast (approval_requested)
          ↓
SOC Analyst Review (Approve / Reject via REST API)
          ↓
Post-Approval Re-Authorization Check
          ↓
Execute Safe Simulation Adapter (or authorized execution)
```

## Security Invariants
1. **Self-Approval Prevention**: The user who triggered an execution cannot approve it.
2. **Explicit Decision Required**: Requests must be explicitly `APPROVED` or `REJECTED`.
3. **TTL Expiration**: Pending approval requests automatically expire after 24 hours.
4. **Audit Trail**: Every approval and rejection is immutably logged with approver identity and justification.
