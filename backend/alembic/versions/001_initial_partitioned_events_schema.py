"""Initial Partitioned Events Schema & TimescaleDB Hypertable Setup

Revision ID: 001_partitioned_events
Revises: 
Create Date: 2026-08-25 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_partitioned_events'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Enable TimescaleDB Extension if available
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")

    # 2. Add Composite Time-Series Indexes on events table
    op.create_index(
        "idx_events_timestamp_severity",
        "events",
        ["timestamp", "severity"],
        unique=False,
        if_not_exists=True,
    )
    op.create_index(
        "idx_events_timestamp_source_type",
        "events",
        ["timestamp", "source_type"],
        unique=False,
        if_not_exists=True,
    )
    op.create_index(
        "idx_events_keyset_pagination",
        "events",
        ["timestamp", "id"],
        unique=False,
        if_not_exists=True,
    )

    # 3. Enable TimescaleDB hypertable if extension exists
    op.execute(
        "SELECT create_hypertable('events', 'timestamp', if_not_exists => TRUE, migrate_data => TRUE);"
    )


def downgrade() -> None:
    op.drop_index("idx_events_keyset_pagination", table_name="events", if_exists=True)
    op.drop_index("idx_events_timestamp_source_type", table_name="events", if_exists=True)
    op.drop_index("idx_events_timestamp_severity", table_name="events", if_exists=True)
