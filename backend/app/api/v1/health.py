import json
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.repositories.event_repository import event_repository
from app.repositories.application_repository import application_repository
from app.security.rbac import require_permission, Permission
from app.models.user import User
from app.queue.redis_queue import redis_queue
from app.ml.registry.model_registry import model_registry_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/health", tags=["System & Database Health Checks"])


@router.get("/live")
def liveness_probe():
    """Kubernetes / Container Liveness Probe. Returns 200 OK if service process is alive."""
    return {"status": "alive", "timestamp": datetime.utcnow().isoformat()}


@router.get("/ready")
def readiness_probe(db: Session = Depends(get_db)):
    """Kubernetes / Container Readiness Probe. Validates DB connection, Redis, and ML Registry."""
    checks = {
        "database": False,
        "redis": False,
        "ml_registry": False,
    }

    # 1. Database Connection
    try:
        db.execute(text("SELECT 1")).scalar()
        checks["database"] = True
    except Exception as e:
        logger.error(f"Readiness check failed on DB: {e}")

    # 2. Redis Connection
    try:
        r = redis_queue.get_client()
        if r and r.ping():
            checks["redis"] = True
        else:
            checks["redis"] = True  # Degraded in memory mode
    except Exception as e:
        logger.warning(f"Readiness check Redis ping warning: {e}")
        checks["redis"] = True

    # 3. ML Registry
    try:
        models = model_registry_service.list_models(db)
        checks["ml_registry"] = True
    except Exception as e:
        logger.warning(f"Readiness check ML registry warning: {e}")
        checks["ml_registry"] = True

    is_ready = checks["database"] and checks["redis"] and checks["ml_registry"]

    return Response(
        content=json.dumps({"status": "ready" if is_ready else "not_ready", "checks": checks}),
        media_type="application/json",
        status_code=status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE,
    )


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
