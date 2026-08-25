import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.preprocessing import StandardScaler

from app.ml.models.base import BaseAnomalyDetector
from app.ml.config.settings import ml_config

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


if HAS_TORCH:
    class PyTorchAutoencoderNet(nn.Module):
        def __init__(self, input_dim: int, latent_dim: int = 8):
            super().__init__()
            hidden_dim = max(latent_dim * 2, 16)
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, latent_dim),
                nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, input_dim),
            )

        def forward(self, x):
            latent = self.encoder(x)
            reconstructed = self.decoder(latent)
            return reconstructed


class NeuralAutoencoderDetector(BaseAnomalyDetector):
    """PyTorch Neural Autoencoder for feature reconstruction anomaly detection."""

    def __init__(
        self,
        epochs: int = ml_config.AE_EPOCHS,
        batch_size: int = ml_config.AE_BATCH_SIZE,
        learning_rate: float = ml_config.AE_LEARNING_RATE,
        latent_dim: int = ml_config.AE_LATENT_DIM,
    ):
        super().__init__("autoencoder")
        self.epochs = epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.latent_dim = latent_dim
        self.scaler = StandardScaler()
        self.model = None
        self.input_dim = 11
        self.is_fitted = False
        self.threshold = 0.5

    def fit(self, X: pd.DataFrame) -> Dict[str, Any]:
        X_scaled = self.scaler.fit_transform(X)
        self.input_dim = X_scaled.shape[1]

        if HAS_TORCH:
            torch.manual_seed(42)
            self.model = PyTorchAutoencoderNet(self.input_dim, self.latent_dim)
            optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)
            criterion = nn.MSELoss()

            tensor_data = torch.FloatTensor(X_scaled)
            dataset = torch.utils.data.TensorDataset(tensor_data)
            loader = torch.utils.data.DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

            self.model.train()
            final_loss = 0.0
            for epoch in range(self.epochs):
                for batch in loader:
                    inputs = batch[0]
                    optimizer.zero_grad()
                    outputs = self.model(inputs)
                    loss = criterion(outputs, inputs)
                    loss.backward()
                    optimizer.step()
                    final_loss = loss.item()

            self.model.eval()
            with torch.no_grad():
                reconstructed = self.model(tensor_data)
                mse = torch.mean((reconstructed - tensor_data) ** 2, dim=1).numpy()
                self.threshold = float(np.percentile(mse, ml_config.AE_PERCENTILE_THRESHOLD))

            self.is_fitted = True
            return {
                "algorithm": "autoencoder",
                "final_loss": float(final_loss),
                "reconstruction_threshold": float(self.threshold),
                "sample_count": len(X),
            }
        else:
            self.is_fitted = True
            self.threshold = 0.5
            return {"status": "fallback_fitted", "threshold": self.threshold}

    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        if not self.is_fitted:
            raise RuntimeError("Autoencoder is not fitted yet.")

        X_scaled = self.scaler.transform(X)

        if HAS_TORCH and self.model:
            self.model.eval()
            with torch.no_grad():
                tensor_data = torch.FloatTensor(X_scaled)
                reconstructed = self.model(tensor_data)
                mse = torch.mean((reconstructed - tensor_data) ** 2, dim=1).numpy()

            preds = np.where(mse > self.threshold, -1, 1)
            scores = np.clip(mse / (self.threshold * 2.0 + 1e-6), 0.0, 1.0)
            return preds, scores
        else:
            scores = np.zeros(len(X))
            preds = np.ones(len(X))
            return preds, scores

    def save(self, filepath: str) -> None:
        joblib.dump(
            {
                "model_state": self.model.state_dict() if (HAS_TORCH and self.model) else None,
                "scaler": self.scaler,
                "input_dim": self.input_dim,
                "latent_dim": self.latent_dim,
                "threshold": self.threshold,
                "is_fitted": self.is_fitted,
            },
            filepath,
        )

    def load(self, filepath: str) -> None:
        data = joblib.load(filepath)
        self.scaler = data["scaler"]
        self.input_dim = data.get("input_dim", 11)
        self.latent_dim = data.get("latent_dim", self.latent_dim)
        self.threshold = data["threshold"]
        self.is_fitted = data["is_fitted"]

        if HAS_TORCH and data["model_state"]:
            self.model = PyTorchAutoencoderNet(self.input_dim, self.latent_dim)
            self.model.load_state_dict(data["model_state"])
            self.model.eval()
