import numpy as np
from typing import Dict, Any, Tuple
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score


class MLEvaluator:
    """Evaluates ML model performance on ground-truth labeled validation datasets."""

    @staticmethod
    def evaluate(
        y_true: np.ndarray, y_pred: np.ndarray, y_scores: np.ndarray
    ) -> Dict[str, float]:
        """Compute standard classification & anomaly metrics."""
        # Convert -1 (anomaly) and 1 (normal) labels to binary 1 (anomaly) and 0 (normal)
        binary_true = np.where(y_true == -1, 1, 0)
        binary_pred = np.where(y_pred == -1, 1, 0)

        precision = float(precision_score(binary_true, binary_pred, zero_division=0))
        recall = float(recall_score(binary_true, binary_pred, zero_division=0))
        f1 = float(f1_score(binary_true, binary_pred, zero_division=0))

        try:
            auc = float(roc_auc_score(binary_true, y_scores))
        except Exception:
            auc = 0.5

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
        }
