# Role-Based Access Control (RBAC) Architecture

## Overview
CyberGuard AI implements a centralized, permission-based Role-Based Access Control (RBAC) system. Backend authorization is enforced on 100% of protected API routes via FastAPI dependencies (`require_permission`).

## Role & Permission Matrix

| Permission Code | Description | ADMIN | SECURITY_ANALYST | VIEWER |
| :--- | :--- | :---: | :---: | :---: |
| `events:read` | View security events | ✅ | ✅ | ✅ |
| `events:ingest` | Ingest security logs | ✅ | ✅ | ❌ |
| `alerts:read` | View security alerts | ✅ | ✅ | ✅ |
| `alerts:update` | Triage alert status | ✅ | ✅ | ❌ |
| `incidents:read` | View security incidents | ✅ | ✅ | ✅ |
| `incidents:create` | Create new incidents | ✅ | ✅ | ❌ |
| `incidents:update` | Update incidents & notes | ✅ | ✅ | ❌ |
| `rules:read` | View detection rules | ✅ | ✅ | ✅ |
| `rules:write` | Create & edit rules | ✅ | ✅ | ❌ |
| `rules:delete` | Delete detection rules | ✅ | ❌ | ❌ |
| `threat_intel:read` | View threat IoC feeds | ✅ | ✅ | ✅ |
| `threat_intel:write` | Add & update IoCs | ✅ | ✅ | ❌ |
| `ml:read` | View ML models & metrics | ✅ | ✅ | ✅ |
| `ml:train` | Trigger ML retraining | ✅ | ✅ | ❌ |
| `reports:read` | View report summaries | ✅ | ✅ | ✅ |
| `reports:export` | Export CSV & PDF reports | ✅ | ✅ | ❌ |
| `audit:read` | View security audit logs | ✅ | ✅ | ❌ |
| `users:read` | View user accounts | ✅ | ✅ | ❌ |
| `users:manage` | Create & manage users | ✅ | ❌ | ❌ |

## Authorization Control Flow
```
Client Request -> CorrelationIdMiddleware -> RateLimitationMiddleware -> JWT Auth (get_current_user) -> RBAC Dependency (require_permission) -> Controller Handler -> Audit Service
```
