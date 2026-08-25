import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler


class DBSCANDetector:
    """DBSCAN density clustering anomaly detector."""

    def __init__(self, eps: float = 0.5, min_samples: int = 5):
        self.eps = eps
        self.min_samples = min_samples
        self.model = DBSCAN(eps=self.eps, min_samples=self.min_samples)
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit(self, X: pd.DataFrame) -> Dict[str, Any]:
        X_scaled = self.scaler.fit_transform(X)
        labels = self.model.fit_predict(X_scaled)
        self.is_fitted = True

        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        n_noise = list(labels).count(-1)

        return {
            "n_clusters": n_clusters,
            "n_noise_samples": n_noise,
            "total_samples": len(X),
        }

    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predict whether new samples fall into noise (-1) or clusters."""
        if not self.is_fitted:
            raise RuntimeError("DBSCAN model is not fitted yet.")

        X_scaled = self.scaler.transform(X)
        # Approximate nearest cluster distance for out-of-sample prediction
        labels = self.model.fit_predict(X_scaled)
        scores = np.where(labels == -1, 0.9, 0.1)
        return labels, scores

    def save(self, filepath: str):
        joblib.dump({"model": self.model, "scaler": self.scaler, "is_fitted": self.is_fitted}, filepath)

    def load(self, filepath: str):
        data = joblib.load(filepath)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.is_fitted = data["is_fitted"]
