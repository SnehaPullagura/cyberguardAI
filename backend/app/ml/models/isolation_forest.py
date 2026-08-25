import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class IsolationForestDetector:
    """Isolation Forest unsupervised anomaly detector."""

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=42,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit(self, X: pd.DataFrame) -> Dict[str, Any]:
        """Fit scaler and Isolation Forest model on numerical feature matrix."""
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True

        scores = self.model.decision_function(X_scaled)
        return {
            "mean_score": float(np.mean(scores)),
            "std_score": float(np.std(scores)),
            "sample_count": len(X),
        }

    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomaly labels (-1 anomaly, 1 normal) and anomaly scores."""
        if not self.is_fitted:
            raise RuntimeError("IsolationForest model is not fitted yet.")

        X_scaled = self.scaler.transform(X)
        preds = self.model.predict(X_scaled)  # -1 = anomaly, 1 = normal
        raw_scores = self.model.decision_function(X_scaled)

        # Convert decision function (higher is normal) to anomaly score (0.0 to 1.0, higher is more anomalous)
        anomaly_scores = 1.0 - (
            (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-6)
        )
        return preds, anomaly_scores

    def save(self, filepath: str):
        joblib.dump({"model": self.model, "scaler": self.scaler, "is_fitted": self.is_fitted}, filepath)

    def load(self, filepath: str):
        data = joblib.load(filepath)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.is_fitted = data["is_fitted"]
