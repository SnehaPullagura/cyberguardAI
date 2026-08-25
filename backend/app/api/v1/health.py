from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.repositories.event_repository import event_repository
from app.repositories.application_repository import application_repository
from app.security.rbac import require_permission, Permission
from app.models.user import User

router = APIRouter(prefix="/health", tags=["System & Database Health Checks"])


@router.get("/db")
def check_database_health(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EVENTS_READ)),
):
    """Retrieve detailed database connection status, storage partition metrics, and application entity statistics."""
    db_status = "healthy"
    error_detail = None

    try:
        db.execute(text("SELECT 1")).scalar()
    except Exception as e:
        db_status = "unhealthy"
        error_detail = str(e)

    storage_stats = event_repository.get_storage_stats(db)
    open_alerts = application_repository.get_open_alerts_count(db)
    active_incidents = application_repository.get_active_incidents_count(db)

    return {
        "database": db_status,
        "mode": storage_stats["partition_mode"],
        "error": error_detail,
        "metrics": {
            "total_events": storage_stats["total_events"],
            "oldest_event": storage_stats["oldest_event_timestamp"],
            "newest_event": storage_stats["newest_event_timestamp"],
            "retention_days": storage_stats["retention_days"],
            "open_alerts": open_alerts,
            "active_incidents": active_incidents,
        },
    }
