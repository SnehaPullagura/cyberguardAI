import os
from pydantic import BaseModel


class MLConfig(BaseModel):
    """Machine learning pipeline hyperparameter and storage settings."""

    # Schema & Versioning
    FEATURE_SCHEMA_VERSION: str = "1.0"
    DEFAULT_MODEL_VERSION: str = "1.0.0"

    # Isolation Forest Settings
    IF_CONTAMINATION: float = 0.05
    IF_N_ESTIMATORS: int = 100
    IF_RANDOM_STATE: int = 42

    # PyTorch Autoencoder Settings
    AE_EPOCHS: int = 20
    AE_BATCH_SIZE: int = 32
    AE_LEARNING_RATE: float = 0.001
    AE_LATENT_DIM: int = 8
    AE_PERCENTILE_THRESHOLD: float = 95.0

    # DBSCAN Clustering Settings
    DBSCAN_EPS: float = 0.5
    DBSCAN_MIN_SAMPLES: int = 5

    # Ensemble Scoring Weights
    WEIGHT_ISOLATION_FOREST: float = 0.40
    WEIGHT_AUTOENCODER: float = 0.40
    WEIGHT_DBSCAN: float = 0.20


ml_config = MLConfig()
