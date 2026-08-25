from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.event import SecurityEvent
from app.models.user import User
from app.schemas.event import (
    SecurityEventCreate,
    SecurityEventRead,
    BatchEventIngestRequest,
    BatchEventIngestResponse,
)
from app.normalization.normalizer import normalizer
from app.queue.redis_queue import redis_queue
from app.pipeline.processor import process_single_security_event
from app.security.rbac import require_permission, Permission

router = APIRouter(prefix="/events", tags=["Security Events & Ingestion"])


@router.post("/ingest", response_model=BatchEventIngestResponse)
def ingest_raw_logs(
    payload: BatchEventIngestRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Bulk ingest, normalize, and analyze raw or structured security logs (Async Redis Queue with Direct Fallback)."""
    total_received = len(payload.events)
    total_ingested = 0
    total_failed = 0
    errors = []

    normalized_events: List[SecurityEventCreate] = []

    # 1. Normalize events first
    for event_data in payload.events:
        try:
            if event_data.raw_payload:
                normalized = normalizer.normalize(
                    event_data.raw_payload, event_data.source_type
                )
            else:
                normalized = event_data
            normalized_events.append(normalized)
        except Exception as e:
            total_failed += 1
            errors.append(f"Normalization failed for event: {e}")

    # 2. Check if Async Queue is enabled and healthy
    if settings.ASYNC_INGESTION_ENABLED:
        try:
            enqueued_count, enqueued_ids = redis_queue.publish_events(normalized_events)
            total_ingested = enqueued_count
            response.status_code = status.HTTP_202_ACCEPTED
            return BatchEventIngestResponse(
                total_received=total_received,
                total_ingested=total_ingested,
                total_failed=total_failed,
                errors=errors,
            )
        except Exception as e:
            errors.append(f"Async queue enqueue failed ({e}), falling back to direct ingestion.")

    # 3. Direct Fallback Processing (Synchronous mode if Queue disabled or offline)
    for normalized_event in normalized_events:
        try:
            process_single_security_event(db, normalized_event)
            total_ingested += 1
        except Exception as e:
            total_failed += 1
            errors.append(f"Direct processing failed for event {normalized_event.event_id}: {e}")

    return BatchEventIngestResponse(
        total_received=total_received,
        total_ingested=total_ingested,
        total_failed=total_failed,
        errors=errors,
    )


@router.get("/health")
def check_ingestion_health():
    """Health check endpoint for Redis connection, queue length, and DLQ count."""
    health_info = redis_queue.get_health()
    return {
        "service": "CyberGuard Ingestion Queue",
        "async_enabled": settings.ASYNC_INGESTION_ENABLED,
        "queue_health": health_info,
    }


@router.get("", response_model=List[SecurityEventRead])
def search_events(
    source_type: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EVENTS_READ)),
):
    """Search and filter normalized security events with pagination."""
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

    events = (
        query.order_by(SecurityEvent.timestamp.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return events


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event_by_id(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.EVENTS_READ)),
):
    """Retrieve detailed security event record by ID."""
    event = (
        db.query(SecurityEvent)
        .filter(
            (SecurityEvent.id == event_id) | (SecurityEvent.event_id == event_id)
        )
        .first()
    )
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Event not found"
        )
    return event
