import os
import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.config import settings
from app.schemas.event import SecurityEventCreate
from app.ml.feature_extraction import feature_extractor
from app.ml.models.isolation_forest import IsolationForestDetector
from app.ml.models.autoencoder import NeuralAutoencoderDetector
from app.ml.models.dbscan import DBSCANDetector
from app.models.ml_model import MLModelRegistry

logger = logging.getLogger(__name__)


class MLPipelineManager:
    """Manages training, artifact storage, and real-time inference for AI anomaly detection models."""

    def __init__(self):
        self.active_model = IsolationForestDetector()
        self.artifact_dir = settings.ML_MODEL_DIR
        os.makedirs(self.artifact_dir, exist_ok=True)

    def train_model(
        self,
        db: Session,
        events: List[SecurityEventCreate],
        algorithm: str = "isolation_forest",
        contamination: float = 0.05,
    ) -> MLModelRegistry:
        """Train a model on provided events and register in DB model catalog."""
        if not events:
            raise ValueError("Cannot train ML model with 0 events.")

        df_features = feature_extractor.transform_batch(events)
        version = f"v{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        model_id = str(uuid.uuid4())
        artifact_filename = f"{algorithm}_{version}_{model_id[:8]}.joblib"
        artifact_path = os.path.join(self.artifact_dir, artifact_filename)

        metrics: Dict[str, Any] = {}

        if algorithm == "isolation_forest":
            detector = IsolationForestDetector(contamination=contamination)
            metrics = detector.fit(df_features)
            detector.save(artifact_path)
            self.active_model = detector
        elif algorithm == "autoencoder":
            detector = NeuralAutoencoderDetector()
            metrics = detector.fit(df_features)
            detector.save(artifact_path)
            self.active_model = detector
        elif algorithm == "dbscan":
            detector = DBSCANDetector()
            metrics = detector.fit(df_features)
            detector.save(artifact_path)
            self.active_model = detector
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        # Deactivate previous active models in DB
        db.query(MLModelRegistry).filter(
            MLModelRegistry.algorithm == algorithm
        ).update({"is_active": False})

        registry_entry = MLModelRegistry(
            id=model_id,
            model_name=f"CyberGuard-{algorithm.upper()}",
            version=version,
            algorithm=algorithm,
            metrics=metrics,
            parameters={"contamination": contamination, "sample_count": len(events)},
            artifact_path=artifact_path,
            is_active=True,
            trained_at=datetime.utcnow(),
            training_sample_count=float(len(events)),
        )

        db.add(registry_entry)
        db.commit()
        db.refresh(registry_entry)
        return registry_entry

    def predict_event_anomaly(
        self, event: SecurityEventCreate
    ) -> Tuple[bool, float, Dict[str, float]]:
        """Run real-time anomaly inference on a single normalized event."""
        features_dict = feature_extractor.extract_features(event)
        df_features = feature_extractor.transform_batch([event])

        try:
            if hasattr(self.active_model, "is_fitted") and self.active_model.is_fitted:
                preds, scores = self.active_model.predict(df_features)
                is_anomaly = bool(preds[0] == -1)
                anomaly_score = float(scores[0])
                return is_anomaly, anomaly_score, features_dict
        except Exception as e:
            logger.warning(f"ML inference error ({e}), skipping anomaly score.")

        # Default fallback heuristic if no model trained yet
        is_anomaly = event.severity == "critical" or "attack" in event.action
        anomaly_score = 0.85 if is_anomaly else 0.1
        return is_anomaly, anomaly_score, features_dict


ml_pipeline_manager = MLPipelineManager()
