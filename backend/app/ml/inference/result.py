from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class MLInferenceResult(BaseModel):
    """Standardized multi-model ML inference result schema."""

    event_id: str
    is_anomaly: bool
    ensemble_anomaly_score: float = Field(..., ge=0.0, le=1.0)
    isolation_forest_score: float = Field(..., ge=0.0, le=1.0)
    autoencoder_score: float = Field(..., ge=0.0, le=1.0)
    dbscan_score: float = Field(..., ge=0.0, le=1.0)
    dbscan_cluster_id: int = -1
    model_version: str = "1.0.0"
    feature_version: str = "1.0"
    inference_latency_ms: float = 0.0
    inference_timestamp: datetime = Field(default_factory=datetime.utcnow)
    features_used: Dict[str, float] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
