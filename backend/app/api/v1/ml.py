from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.ml_model import MLModelRegistry
from app.models.user import User
from app.schemas.ml import MLModelRead, MLTrainRequest, MLTrainResponse
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
    return db.query(MLModelRegistry).order_by(MLModelRegistry.created_at.desc()).all()


@router.post("/train", response_model=MLTrainResponse)
def train_ml_model(
    payload: MLTrainRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.ML_TRAIN)),
):
    """Trigger training pipeline for specified AI anomaly detection model."""
    try:
        metrics = ml_pipeline_manager.train_pipeline(
            db=db,
            model_type=payload.model_type,
            sample_size=payload.sample_size,
        )

        audit_service.log_action(
            db=db,
            action="ML_MODEL_TRAINED",
            resource="ml",
            user_id=current_user.id,
            username=current_user.username,
            status="SUCCESS",
            details={"model_type": payload.model_type, "sample_size": payload.sample_size},
        )

        return MLTrainResponse(
            model_type=payload.model_type,
            status="trained",
            metrics=metrics,
            message=f"Model {payload.model_type} successfully retrained and registered.",
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
