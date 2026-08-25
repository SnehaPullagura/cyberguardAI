import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
from app.ml.features.schema import FEATURE_NAMES

logger = logging.getLogger(__name__)


class FeatureValidator:
    """Validates numerical feature matrices, cleans missing/NaN/Inf values, and guarantees schema shape."""

    def validate_and_clean_df(self, df: pd.DataFrame) -> pd.DataFrame:
        """Validate dataframe columns, handle NaNs/Infs, and enforce column ordering."""
        # Enforce column schema
        for col in FEATURE_NAMES:
            if col not in df.columns:
                df[col] = 0.0

        # Select exact schema columns in order
        df = df[FEATURE_NAMES].copy()

        # Replace infinite values with NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)

        # Fill NaNs with 0.0
        df.fillna(0.0, inplace=True)

        # Cast to float64
        return df.astype(np.float64)

    def validate_features_dict(self, features: Dict[str, float]) -> Dict[str, float]:
        """Sanitize a dictionary of numerical features."""
        clean_features = {}
        for name in FEATURE_NAMES:
            val = features.get(name, 0.0)
            if val is None or np.isnan(val) or np.isinf(val):
                val = 0.0
            clean_features[name] = float(val)
        return clean_features


feature_validator = FeatureValidator()
