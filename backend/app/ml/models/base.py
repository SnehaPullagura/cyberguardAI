from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple
import numpy as np
import pandas as pd


class BaseAnomalyDetector(ABC):
    """Abstract base class for unsupervised security anomaly detectors."""

    def __init__(self, name: str):
        self.name = name
        self.is_fitted = False

    @abstractmethod
    def fit(self, X: pd.DataFrame) -> Dict[str, Any]:
        """Fit model on feature matrix X."""
        pass

    @abstractmethod
    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomaly labels (-1 anomaly, 1 normal) and normalized anomaly scores [0.0, 1.0]."""
        pass

    @abstractmethod
    def save(self, filepath: str) -> None:
        """Serialize model artifact to disk."""
        pass

    @abstractmethod
    def load(self, filepath: str) -> None:
        """Deserialize model artifact from disk."""
        pass
