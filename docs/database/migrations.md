# Alembic Migration Guide

## Configuration
Alembic is configured in `alembic.ini` and `alembic/env.py`. Database connections dynamically load settings from `app.config.settings.get_database_url()`.

## Executing Migrations
To upgrade database schemas to latest version:
```bash
cd backend
alembic upgrade head
```

To roll back the last migration:
```bash
cd backend
alembic downgrade -1
```

## Migration Versions
- `001_partitioned_events`: Creates `timescaledb` extension, composite indexes on time-series `events`, and initializes hypertable partitioning.
