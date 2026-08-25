# Database Storage Architecture

## Overview
CyberGuard AI decouples application data access from high-volume time-series security log storage.

## Architectural Layers
```
Application Repositories (PostgreSQL)  <---> Transactional Data (Users, Rules, Alerts, Incidents, Audit Logs)
Event Repository (TimescaleDB / Range) <---> High-Volume Time-Series Security Events (events hypertable/partition)
```

## Storage Separation Strategy
- **Application Repository**: Relational PostgreSQL storing users, roles, permissions, detection rules, alert records, incident correlation, threat intel feeds, ML registries, and audit logs.
- **Event Repository**: TimescaleDB hypertable (`events` table partitioned by `timestamp`) supporting high-throughput ingestion, cursor/keyset pagination (`X-Next-Cursor`), composite time-series indexing, and automated partition-level retention pruning (`EVENT_RETENTION_DAYS`).
