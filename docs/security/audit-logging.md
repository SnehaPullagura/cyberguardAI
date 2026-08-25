# Security Audit Logging System

## Overview
CyberGuard AI records security-sensitive actions in an immutable `audit_logs` database table via `AuditService`.

## Audited Events
- **Authentication**: `USER_LOGIN_SUCCESS`, `USER_LOGIN_FAILED`
- **User Management**: `USER_CREATED`
- **Triage & Incidents**: `ALERT_STATUS_UPDATED`, `INCIDENT_CREATED`, `INCIDENT_UPDATED`
- **Detection & Intelligence**: `RULE_CREATED`, `RULE_UPDATED`, `IOC_CREATED`
- **Machine Learning**: `ML_MODEL_TRAINED`

## Data Sanitization & Protection
- Passwords, secret keys, JWT tokens, and refresh tokens are automatically redacted (`[REDACTED]`) before persisting audit details.
- Audit records store timestamp (UTC), actor User ID, username, IP address, resource name, action type, status (`SUCCESS`/`FAILED`), and sanitized detail JSON.
- Audit logs are accessible only to authorized users holding `AUDIT_READ` permission (`ADMIN` and `SECURITY_ANALYST` roles).
