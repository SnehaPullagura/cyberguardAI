# Event Retention & Pruning Policy

## Retention Policy
- Configured via `EVENT_RETENTION_DAYS` (default `90` days).
- Executed safely by `event_repository.prune_expired_events(db, retention_days)`.
- Prunes expired security log records without touching application tables (`users`, `alerts`, `incidents`, `audit_logs`).
