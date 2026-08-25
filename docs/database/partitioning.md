# TimescaleDB & PostgreSQL Partitioning Strategy

## Partitioning Strategy
Security log events are partitioned by `timestamp` interval (7 days per chunk).

- **Primary Storage Engine**: TimescaleDB Hypertables via `SELECT create_hypertable('events', 'timestamp')`.
- **Fallback Engine**: Native PostgreSQL Range Partitioning (`PARTITION BY RANGE (timestamp)`) if TimescaleDB extension is disabled.
- **SQLite Development Fallback**: Standard relational table with composite indexes (`idx_events_keyset_pagination`) during local testing.
