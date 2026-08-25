from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.ml_model import MLModelRegistry
from app.models.event import SecurityEvent
from app.models.user import User
from app.schemas.ml import MLModelRead, MLTrainRequest, MLTrainResponse
from app.schemas.event import SecurityEventCreate, EndpointSchema, ObserverSchema, ProcessSchema
from app.ml.pipeline import ml_pipeline_manager
from app.security.rbac import require_permission, Permission
from app.services.audit_service import audit_service

router = APIRouter(prefix="/ml", tags=["AI & Machine Learning Engine"])


@router.get("/models", response_model=List[MLModelRead])
def list_ml_models(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_READ)),
):
    """Retrieve registered AI anomaly detection models and metrics."""
    return db.query(MLModelRegistry).order_by(MLModelRegistry.trained_at.desc()).all()


@router.post("/train", response_model=MLTrainResponse)
def train_ml_model(
    payload: MLTrainRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_TRAIN)),
):
    """Trigger training pipeline for specified AI anomaly detection model."""
    try:
        db_events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(payload.sample_size).all()
        
        events: List[SecurityEventCreate] = []
        for e in db_events:
            events.append(
                SecurityEventCreate(
                    event_id=e.event_id,
                    timestamp=e.timestamp,
                    source_type=e.source_type,
                    category=e.category,
                    action=e.action,
                    severity=e.severity,
                    source=EndpointSchema(ip=e.source_ip, user=e.source_user, port=e.source_port) if e.source_ip else None,
                    destination=EndpointSchema(ip=e.destination_ip, port=e.destination_port) if e.destination_ip else None,
                    observer=ObserverSchema(hostname=e.observer_host, ip=e.observer_ip) if e.observer_host else None,
                    process=ProcessSchema(name=e.process_name, pid=e.process_pid) if e.process_name else None,
                )
            )

        if not events:
            # Fallback synthetic seed event if DB has zero events
            events = [
                SecurityEventCreate(
                    event_id="seed-1",
                    source_type="syslog",
                    category="authentication",
                    action="login_failed",
                    severity="high",
                )
            ]

        registered_model = ml_pipeline_manager.train_model(
            db=db,
            events=events,
            algorithm=payload.model_type,
        )

        audit_service.log_action(
            db=db,
            action="ML_MODEL_TRAINED",
            resource="ml",
            user_id=current_user.id,
            username=current_user.username,
            status="SUCCESS",
            details={"algorithm": payload.model_type, "sample_size": len(events)},
        )

        return MLTrainResponse(
            model_type=payload.model_type,
            status="trained",
            metrics=registered_model.metrics or {},
            message=f"Model {payload.model_type} ({registered_model.version}) successfully trained and registered.",
        )
    except Exception as e:
        audit_service.log_action(
            db=db,
            action="ML_MODEL_TRAINED",
            resource="ml",
            user_id=current_user.id,
            username=current_user.username,
            status="FAILED",
            details={"model_type": payload.model_type, "error": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model training failed: {e}",
        )
