import numpy as np
from typing import Dict, Any, Tuple, Optional
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix


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

        # Calculate False Positive Rate (FPR) and True Negative Rate (TNR)
        try:
            tn, fp, fn, tp = confusion_matrix(binary_true, binary_pred).ravel()
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            tnr = float(tn / (tn + fp)) if (tn + fp) > 0 else 1.0
        except Exception:
            fpr = 0.0
            tnr = 1.0

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "false_positive_rate": round(fpr, 4),
            "true_negative_rate": round(tnr, 4),
        }

    @staticmethod
    def compute_population_stability_index(
        reference: np.ndarray, current: np.ndarray, buckets: int = 10
    ) -> float:
        """Computes Population Stability Index (PSI) to detect feature distribution shift."""
        if len(reference) == 0 or len(current) == 0:
            return 0.0

        percentiles = np.linspace(0, 100, buckets + 1)
        breakpoints = np.percentile(reference, percentiles)
        breakpoints[0] = -np.inf
        breakpoints[-1] = np.inf

        ref_counts = np.histogram(reference, bins=breakpoints)[0]
        cur_counts = np.histogram(current, bins=breakpoints)[0]

        ref_pct = (ref_counts + 1e-6) / (len(reference) + 1e-6 * buckets)
        cur_pct = (cur_counts + 1e-6) / (len(current) + 1e-6 * buckets)

        psi = np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct))
        return round(float(psi), 4)

    @staticmethod
    def calibrate_anomaly_probabilities(
        raw_scores: np.ndarray, temperature: float = 1.0
    ) -> np.ndarray:
        """Calibrates raw decision scores into probability range [0.0, 1.0] using logistic scaling."""
        z = -raw_scores / max(1e-4, temperature)
        probs = 1.0 / (1.0 + np.exp(np.clip(z, -20.0, 20.0)))
        return np.round(probs, 4)
