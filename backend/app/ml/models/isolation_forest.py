import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.ml.models.base import BaseAnomalyDetector
from app.ml.config.settings import ml_config


class IsolationForestDetector(BaseAnomalyDetector):
    """Production-grade Isolation Forest unsupervised anomaly detector."""

    def __init__(
        self,
        contamination: float = ml_config.IF_CONTAMINATION,
        n_estimators: int = ml_config.IF_N_ESTIMATORS,
        random_state: int = ml_config.IF_RANDOM_STATE,
    ):
        super().__init__("isolation_forest")
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit(self, X: pd.DataFrame) -> Dict[str, Any]:
        """Fit scaler and Isolation Forest model on numerical feature matrix."""
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True

        raw_scores = self.model.decision_function(X_scaled)
        return {
            "algorithm": "isolation_forest",
            "mean_decision_score": float(np.mean(raw_scores)),
            "std_decision_score": float(np.std(raw_scores)),
            "sample_count": len(X),
            "contamination": self.contamination,
            "n_estimators": self.n_estimators,
        }

    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomaly labels (-1 anomaly, 1 normal) and normalized anomaly scores [0.0, 1.0]."""
        if not self.is_fitted:
            raise RuntimeError("IsolationForest model is not fitted yet.")

        X_scaled = self.scaler.transform(X)
        preds = self.model.predict(X_scaled)  # -1 = anomaly, 1 = normal
        raw_scores = self.model.decision_function(X_scaled)

        # Calibrated Sigmoid transform: raw decision_function > 0 is normal, < 0 is anomaly
        # Anomaly score scaled smoothly in [0.0, 1.0] where 1.0 = high anomaly
        anomaly_scores = 1.0 / (1.0 + np.exp(raw_scores * 5.0))
        return preds, anomaly_scores

    def save(self, filepath: str) -> None:
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "is_fitted": self.is_fitted,
            },
            filepath,
        )

    def load(self, filepath: str) -> None:
        data = joblib.load(filepath)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.contamination = data.get("contamination", self.contamination)
        self.n_estimators = data.get("n_estimators", self.n_estimators)
        self.is_fitted = data["is_fitted"]
