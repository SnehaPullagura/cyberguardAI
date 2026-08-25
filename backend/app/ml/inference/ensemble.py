import time
import logging
from typing import Dict, Any, Tuple, Optional
from app.schemas.event import SecurityEventCreate
from app.ml.features.extractor import feature_extractor
from app.ml.models.isolation_forest import IsolationForestDetector
from app.ml.models.autoencoder import NeuralAutoencoderDetector
from app.ml.models.dbscan import DBSCANDetector
from app.ml.inference.result import MLInferenceResult
from app.ml.config.settings import ml_config

logger = logging.getLogger(__name__)


class EnsembleInferencePipeline:
    """Combines Isolation Forest, Autoencoder, and DBSCAN anomaly scores into a unified ensemble result."""

    def __init__(
        self,
        if_model: Optional[IsolationForestDetector] = None,
        ae_model: Optional[NeuralAutoencoderDetector] = None,
        dbscan_model: Optional[DBSCANDetector] = None,
    ):
        self.if_model = if_model or IsolationForestDetector()
        self.ae_model = ae_model or NeuralAutoencoderDetector()
        self.dbscan_model = dbscan_model or DBSCANDetector()

    def predict(
        self,
        event: SecurityEventCreate,
        model_version: str = ml_config.DEFAULT_MODEL_VERSION,
    ) -> MLInferenceResult:
        """Run real-time multi-model ensemble inference on a single security log event."""
        start_time = time.time()
        features_dict = feature_extractor.extract_features(event)
        df_features = feature_extractor.transform_batch([event])

        if_score = 0.0
        if_label = 1
        if self.if_model and self.if_model.is_fitted:
            try:
                preds, scores = self.if_model.predict(df_features)
                if_label, if_score = int(preds[0]), float(scores[0])
            except Exception as e:
                logger.warning(f"Isolation Forest inference error ({e}).")

        ae_score = 0.0
        ae_label = 1
        if self.ae_model and self.ae_model.is_fitted:
            try:
                preds, scores = self.ae_model.predict(df_features)
                ae_label, ae_score = int(preds[0]), float(scores[0])
            except Exception as e:
                logger.warning(f"Autoencoder inference error ({e}).")

        dbscan_score = 0.0
        cluster_id = -1
        if self.dbscan_model and self.dbscan_model.is_fitted:
            try:
                preds, scores = self.dbscan_model.predict(df_features)
                cluster_id, dbscan_score = int(preds[0]), float(scores[0])
            except Exception as e:
                logger.warning(f"DBSCAN inference error ({e}).")

        # Weighted Ensemble Aggregation
        w_if = ml_config.WEIGHT_ISOLATION_FOREST
        w_ae = ml_config.WEIGHT_AUTOENCODER
        w_db = ml_config.WEIGHT_DBSCAN

        ensemble_score = float(
            np_clip(
                (if_score * w_if) + (ae_score * w_ae) + (dbscan_score * w_db),
                0.0,
                1.0,
            )
        )

        # Flag as anomaly if ensemble score > 0.5 or IF/AE strongly flag anomaly
        is_anomaly = (
            ensemble_score > 0.5
            or (if_label == -1 and if_score > 0.7)
            or (ae_label == -1 and ae_score > 0.7)
        )

        latency_ms = (time.time() - start_time) * 1000.0

        return MLInferenceResult(
            event_id=event.event_id or "unknown",
            is_anomaly=is_anomaly,
            ensemble_anomaly_score=round(ensemble_score, 4),
            isolation_forest_score=round(if_score, 4),
            autoencoder_score=round(ae_score, 4),
            dbscan_score=round(dbscan_score, 4),
            dbscan_cluster_id=cluster_id,
            model_version=model_version,
            feature_version=ml_config.FEATURE_SCHEMA_VERSION,
            inference_latency_ms=round(latency_ms, 2),
            features_used=features_dict,
            metadata={
                "if_label": if_label,
                "ae_label": ae_label,
                "cluster_id": cluster_id,
            },
        )


def np_clip(val: float, min_val: float, max_val: float) -> float:
    return max(min_val, min(val, max_val))
