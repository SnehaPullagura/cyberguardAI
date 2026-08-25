import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.ml_model import MLModelRegistry

logger = logging.getLogger(__name__)


class ModelRegistryService:
    """Manages ML model catalog, version tracking, and active model selection in database."""

    def register_model(
        self,
        db: Session,
        model_id: str,
        model_name: str,
        version: str,
        algorithm: str,
        artifact_path: str,
        metrics: Dict[str, Any],
        parameters: Dict[str, Any],
        training_sample_count: int,
        is_active: bool = True,
    ) -> MLModelRegistry:
        """Register a newly trained model artifact into DB registry."""
        if is_active:
            # Deactivate previous active models for this algorithm
            db.query(MLModelRegistry).filter(
                MLModelRegistry.algorithm == algorithm
            ).update({"is_active": False})

        entry = MLModelRegistry(
            id=model_id,
            model_name=model_name,
            version=version,
            algorithm=algorithm,
            artifact_path=artifact_path,
            metrics=metrics,
            parameters=parameters,
            training_sample_count=float(training_sample_count),
            is_active=is_active,
            trained_at=datetime.utcnow(),
        )

        db.add(entry)
        db.commit()
        db.refresh(entry)
        logger.info(f"Registered model {model_name} ({version}) in database registry.")
        return entry

    def get_active_model(self, db: Session, algorithm: str) -> Optional[MLModelRegistry]:
        """Fetch active model entry for a specific algorithm."""
        return (
            db.query(MLModelRegistry)
            .filter(
                MLModelRegistry.algorithm == algorithm,
                MLModelRegistry.is_active == True,
            )
            .order_by(MLModelRegistry.trained_at.desc())
            .first()
        )

    def list_models(
        self, db: Session, algorithm: Optional[str] = None
    ) -> List[MLModelRegistry]:
        """List registered ML models."""
        query = db.query(MLModelRegistry)
        if algorithm:
            query = query.filter(MLModelRegistry.algorithm == algorithm)
        return query.order_by(MLModelRegistry.trained_at.desc()).all()


model_registry_service = ModelRegistryService()
