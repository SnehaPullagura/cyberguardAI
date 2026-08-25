import os
import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.config import settings
from app.schemas.event import SecurityEventCreate
from app.ml.features.extractor import feature_extractor
from app.ml.models.isolation_forest import IsolationForestDetector
from app.ml.models.autoencoder import NeuralAutoencoderDetector
from app.ml.models.dbscan import DBSCANDetector
from app.ml.inference.ensemble import EnsembleInferencePipeline
from app.ml.inference.result import MLInferenceResult
from app.ml.artifacts.storage import artifact_storage
from app.ml.registry.model_registry import model_registry_service
from app.models.ml_model import MLModelRegistry

logger = logging.getLogger(__name__)


class MLPipelineManager:
    """Unified pipeline manager coordinating model training, artifact persistence, registry tracking, and fail-safe ensemble inference."""

    def __init__(self):
        self.if_detector = IsolationForestDetector()
        self.ae_detector = NeuralAutoencoderDetector()
        self.dbscan_detector = DBSCANDetector()
        self.ensemble_pipeline = EnsembleInferencePipeline(
            if_model=self.if_detector,
            ae_model=self.ae_detector,
            dbscan_model=self.dbscan_detector,
        )

    def load_active_models(self, db: Session) -> Dict[str, bool]:
        """Load active models from DB registry into active memory detectors."""
        loaded_status = {}
        for algo, detector in [
            ("isolation_forest", self.if_detector),
            ("autoencoder", self.ae_detector),
            ("dbscan", self.dbscan_detector),
        ]:
            active_entry = model_registry_service.get_active_model(db, algo)
            if active_entry and active_entry.artifact_path and os.path.exists(active_entry.artifact_path):
                try:
                    detector.load(active_entry.artifact_path)
                    loaded_status[algo] = True
                    logger.info(f"Loaded active {algo} model version {active_entry.version} from {active_entry.artifact_path}")
                except Exception as e:
                    logger.warning(f"Failed to load active {algo} model ({e}).")
                    loaded_status[algo] = False
            else:
                loaded_status[algo] = False

        self.ensemble_pipeline = EnsembleInferencePipeline(
            if_model=self.if_detector,
            ae_model=self.ae_detector,
            dbscan_model=self.dbscan_detector,
        )
        return loaded_status

    def train_model(
        self,
        db: Session,
        events: List[SecurityEventCreate],
        algorithm: str = "isolation_forest",
        contamination: float = 0.05,
    ) -> MLModelRegistry:
        """Train a model on provided security events and register in DB catalog."""
        if not events:
            raise ValueError("Cannot train ML model with 0 events.")

        df_features = feature_extractor.transform_batch(events)
        version = f"v{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        model_id = str(uuid.uuid4())
        filename = f"{algorithm}_{version}_{model_id[:8]}.joblib"
        artifact_path = artifact_storage.get_artifact_path(filename)

        metrics: Dict[str, Any] = {}

        if algorithm == "isolation_forest":
            self.if_detector = IsolationForestDetector(contamination=contamination)
            metrics = self.if_detector.fit(df_features)
            self.if_detector.save(artifact_path)
        elif algorithm == "autoencoder":
            self.ae_detector = NeuralAutoencoderDetector()
            metrics = self.ae_detector.fit(df_features)
            self.ae_detector.save(artifact_path)
        elif algorithm == "dbscan":
            self.dbscan_detector = DBSCANDetector()
            metrics = self.dbscan_detector.fit(df_features)
            self.dbscan_detector.save(artifact_path)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        self.ensemble_pipeline = EnsembleInferencePipeline(
            if_model=self.if_detector,
            ae_model=self.ae_detector,
            dbscan_model=self.dbscan_detector,
        )

        return model_registry_service.register_model(
            db=db,
            model_id=model_id,
            model_name=f"CyberGuard-{algorithm.upper()}",
            version=version,
            algorithm=algorithm,
            artifact_path=artifact_path,
            metrics=metrics,
            parameters={"contamination": contamination, "sample_count": len(events)},
            training_sample_count=len(events),
            is_active=True,
        )

    def predict_event_anomaly(
        self, event: SecurityEventCreate
    ) -> Tuple[bool, float, Dict[str, float], Optional[MLInferenceResult]]:
        """Run fail-safe real-time ensemble anomaly inference on a single security log event."""
        features_dict = feature_extractor.extract_features(event)

        try:
            inference_result = self.ensemble_pipeline.predict(event)
            return (
                inference_result.is_anomaly,
                inference_result.ensemble_anomaly_score,
                features_dict,
                inference_result,
            )
        except Exception as e:
            logger.warning(f"Fail-safe ML inference exception ({e}), falling back to heuristic scoring.")

        is_anomaly = event.severity == "critical" or "attack" in event.action
        anomaly_score = 0.85 if is_anomaly else 0.10
        return is_anomaly, anomaly_score, features_dict, None


ml_pipeline_manager = MLPipelineManager()
