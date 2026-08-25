import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, JSON, Boolean
from app.database import Base


class MLModelRegistry(Base):
    __tablename__ = "ml_models"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    model_name = Column(String(100), nullable=False, index=True)
    version = Column(String(50), nullable=False)
    algorithm = Column(String(50), nullable=False)  # isolation_forest, autoencoder, dbscan
    
    metrics = Column(JSON, nullable=True)           # f1_score, precision, recall, roc_auc, loss
    parameters = Column(JSON, nullable=True)        # hyperparameters used
    artifact_path = Column(String(255), nullable=False)
    
    is_active = Column(Boolean, default=False, nullable=False, index=True)
    trained_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    training_sample_count = Column(Float, nullable=True)
