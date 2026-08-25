# Security Model & Threat Boundaries

## Threat Analysis & Mitigations
1. **Threat**: Attacker creates an alert to trigger arbitrary command execution.
   - *Mitigation*: Action Registry is strictly allowlisted in source code; no shell/command execution adapters exist.
2. **Threat**: Attacker injects Python code via playbook conditions.
   - *Mitigation*: TriggerEvaluator uses allowlisted operators only (`eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `contains`, `in`); dynamic `eval()`/`exec()` is completely absent.
3. **Threat**: Privilege Escalation / Unauthorized Approval.
   - *Mitigation*: Approval gate checks `Permission.PLAYBOOKS_APPROVE`, forbids self-approval, and performs post-approval re-authorization.
4. **Threat**: Credential Leakage in Logs.
   - *Mitigation*: `AuditService` redacts all sensitive fields before persisting audit logs.
