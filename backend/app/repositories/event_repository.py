import logging
from datetime import datetime, timedelta
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import text, func

from app.config import settings
from app.models.event import SecurityEvent
from app.repositories.base import BaseRepository

logger = logging.getLogger(__name__)


class EventRepository(BaseRepository[SecurityEvent]):
    """High-volume time-series security event repository with TimescaleDB/partition support, keyset pagination, and retention pruning."""

    def __init__(self):
        super().__init__(SecurityEvent)

    def find_by_event_id(self, db: Session, event_id: str) -> Optional[SecurityEvent]:
        """Find event by unique business event_id."""
        return db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()

    def save_event(
        self, db: Session, event: SecurityEvent
    ) -> Tuple[SecurityEvent, bool]:
        """Persist security event with idempotency deduplication check. Returns (event, is_new)."""
        existing = self.find_by_event_id(db, event.event_id)
        if existing:
            logger.info(f"Deduplicated event_id {event.event_id} in database store.")
            return existing, False

        db.add(event)
        db.flush()
        return event, True

    def search_events_keyset(
        self,
        db: Session,
        cursor: Optional[str] = None,
        limit: int = 50,
        source_type: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[SecurityEvent], Optional[str]]:
        """Keyset/Cursor pagination for high-volume time-series events avoiding OFFSET degradation."""
        query = db.query(SecurityEvent)

        if source_type:
            query = query.filter(SecurityEvent.source_type == source_type)
        if category:
            query = query.filter(SecurityEvent.category == category)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)
        if source_ip:
            query = query.filter(SecurityEvent.source_ip == source_ip)
        if search:
            query = query.filter(
                (SecurityEvent.raw_payload.ilike(f"%{search}%"))
                | (SecurityEvent.action.ilike(f"%{search}%"))
            )

        # Apply Keyset / Cursor filter: format "timestamp_iso|id"
        if cursor:
            try:
                cursor_ts_str, cursor_id = cursor.split("|", 1)
                cursor_ts = datetime.fromisoformat(cursor_ts_str)
                query = query.filter(
                    (SecurityEvent.timestamp < cursor_ts)
                    | (
                        (SecurityEvent.timestamp == cursor_ts)
                        & (SecurityEvent.id < cursor_id)
                    )
                )
            except Exception as e:
                logger.warning(f"Invalid pagination cursor format '{cursor}': {e}")

        events = (
            query.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
            .limit(limit + 1)
            .all()
        )

        next_cursor = None
        if len(events) > limit:
            has_more_events = events[:limit]
            last_item = has_more_events[-1]
            next_cursor = f"{last_item.timestamp.isoformat()}|{last_item.id}"
            events = has_more_events

        return events, next_cursor

    def prune_expired_events(
        self, db: Session, retention_days: Optional[int] = None
    ) -> int:
        """Prune events older than retention_days without affecting application tables or alerts."""
        if retention_days is None:
            retention_days = settings.EVENT_RETENTION_DAYS

        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        logger.info(f"Pruning time-series events older than {cutoff_date.isoformat()} ({retention_days} days retention)...")

        deleted_count = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.timestamp < cutoff_date)
            .delete(synchronize_session=False)
        )
        db.commit()
        logger.info(f"Pruned {deleted_count} expired security events from event store.")
        return deleted_count

    def get_storage_stats(self, db: Session) -> Dict[str, Any]:
        """Retrieve event storage metrics, hypertable/partition status, and row counts."""
        total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
        min_max = db.query(
            func.min(SecurityEvent.timestamp), func.max(SecurityEvent.timestamp)
        ).first()

        oldest_event = min_max[0].isoformat() if min_max and min_max[0] else None
        newest_event = min_max[1].isoformat() if min_max and min_max[1] else None

        partition_info = "standard_table"
        try:
            result = db.execute(text("SELECT extname FROM pg_extension WHERE extname = 'timescaledb'")).first()
            if result:
                partition_info = "timescaledb_hypertable"
        except Exception:
            pass

        return {
            "total_events": total_events,
            "oldest_event_timestamp": oldest_event,
            "newest_event_timestamp": newest_event,
            "partition_mode": partition_info,
            "retention_days": settings.EVENT_RETENTION_DAYS,
        }


event_repository = EventRepository()
