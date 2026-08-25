import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from app.ml.models.base import BaseAnomalyDetector
from app.ml.config.settings import ml_config


class DBSCANDetector(BaseAnomalyDetector):
    """DBSCAN density clustering detector with out-of-sample nearest-centroid distance inference."""

    def __init__(
        self,
        eps: float = ml_config.DBSCAN_EPS,
        min_samples: int = ml_config.DBSCAN_MIN_SAMPLES,
    ):
        super().__init__("dbscan")
        self.eps = eps
        self.min_samples = min_samples
        self.model = DBSCAN(eps=self.eps, min_samples=self.min_samples)
        self.scaler = StandardScaler()
        self.cluster_centroids: Dict[int, np.ndarray] = {}
        self.cluster_radii: Dict[int, float] = {}
        self.is_fitted = False

    def fit(self, X: pd.DataFrame) -> Dict[str, Any]:
        """Fit scaler and DBSCAN model, then compute cluster centroids and intra-cluster radii."""
        X_scaled = self.scaler.fit_transform(X)
        labels = self.model.fit_predict(X_scaled)
        self.is_fitted = True

        unique_labels = set(labels)
        self.cluster_centroids = {}
        self.cluster_radii = {}

        for cluster_id in unique_labels:
            if cluster_id == -1:
                continue
            cluster_points = X_scaled[labels == cluster_id]
            centroid = np.mean(cluster_points, axis=0)
            distances = np.linalg.norm(cluster_points - centroid, axis=1)
            radius = float(np.percentile(distances, 95)) if len(distances) > 0 else float(self.eps)
            self.cluster_centroids[int(cluster_id)] = centroid
            self.cluster_radii[int(cluster_id)] = max(radius, 1e-4)

        n_clusters = len(self.cluster_centroids)
        n_noise = list(labels).count(-1)

        return {
            "algorithm": "dbscan",
            "n_clusters": n_clusters,
            "n_noise_samples": n_noise,
            "total_samples": len(X),
            "eps": self.eps,
            "min_samples": self.min_samples,
        }

    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Out-of-sample prediction using nearest-cluster centroid distance (avoids fit_predict re-clustering)."""
        if not self.is_fitted:
            raise RuntimeError("DBSCAN model is not fitted yet.")

        X_scaled = self.scaler.transform(X)
        n_samples = len(X)

        if not self.cluster_centroids:
            # If no dense clusters were formed during fit, all points are treated as noise/outliers
            preds = np.full(n_samples, -1)
            scores = np.full(n_samples, 0.85)
            return preds, scores

        preds = []
        scores = []

        for i in range(n_samples):
            point = X_scaled[i]
            min_dist = float("inf")
            assigned_cluster = -1

            for cluster_id, centroid in self.cluster_centroids.items():
                dist = float(np.linalg.norm(point - centroid))
                radius = self.cluster_radii.get(cluster_id, self.eps)
                if dist <= radius * 1.5 and dist < min_dist:
                    min_dist = dist
                    assigned_cluster = cluster_id

            if assigned_cluster != -1:
                preds.append(assigned_cluster)
                # In-cluster normalized score
                norm_score = min_dist / (self.cluster_radii[assigned_cluster] * 2.0 + 1e-6)
                scores.append(float(np.clip(norm_score * 0.4, 0.0, 0.4)))
            else:
                preds.append(-1)  # Outlier / noise
                # Out-of-cluster distance score
                closest_centroid_dist = min(
                    np.linalg.norm(point - c) for c in self.cluster_centroids.values()
                )
                norm_score = min(0.5 + (closest_centroid_dist / (self.eps * 4.0 + 1e-6)), 1.0)
                scores.append(float(norm_score))

        return np.array(preds), np.array(scores)

    def save(self, filepath: str) -> None:
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "cluster_centroids": self.cluster_centroids,
                "cluster_radii": self.cluster_radii,
                "eps": self.eps,
                "min_samples": self.min_samples,
                "is_fitted": self.is_fitted,
            },
            filepath,
        )

    def load(self, filepath: str) -> None:
        data = joblib.load(filepath)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.cluster_centroids = data.get("cluster_centroids", {})
        self.cluster_radii = data.get("cluster_radii", {})
        self.eps = data.get("eps", self.eps)
        self.min_samples = data.get("min_samples", self.min_samples)
        self.is_fitted = data["is_fitted"]
