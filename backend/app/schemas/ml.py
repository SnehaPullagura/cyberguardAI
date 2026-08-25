from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict


class MLModelRead(BaseModel):
    id: str
    model_name: str
    version: str
    algorithm: str
    metrics: Optional[Dict[str, Any]] = None
    parameters: Optional[Dict[str, Any]] = None
    is_active: bool
    trained_at: datetime
    training_sample_count: Optional[float] = None

    model_config = ConfigDict(from_attributes=True)


class MLTrainRequest(BaseModel):
    model_type: str = "isolation_forest"  # isolation_forest, autoencoder, dbscan
    sample_size: int = 1000
    contamination: float = 0.05
    n_estimators: int = 100
    sample_hours: int = 24


class MLTrainResponse(BaseModel):
    model_type: str
    status: str
    metrics: Optional[Dict[str, Any]] = None
    message: str


class AnomalyResultRead(BaseModel):
    event_id: str
    anomaly_score: float
    is_anomaly: bool
    algorithm: str
    features: Dict[str, float]
    timestamp: datetime
