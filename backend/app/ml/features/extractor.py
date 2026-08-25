import math
import numpy as np
import pandas as pd
from typing import List, Dict, Any
from app.schemas.event import SecurityEventCreate
from app.ml.features.schema import FEATURE_NAMES, SEVERITY_MAP, FEATURE_SCHEMA_VERSION
from app.ml.features.validator import feature_validator


class EventFeatureExtractor:
    """Extracts standardized numerical feature vectors from security events for ML models."""

    def __init__(self):
        self.schema_version = FEATURE_SCHEMA_VERSION
        self.feature_names = FEATURE_NAMES

    def extract_features(self, event: SecurityEventCreate) -> Dict[str, float]:
        """Extract a dict of numerical features for a single event."""
        dt = event.timestamp
        hour = dt.hour if dt else 0
        hour_sin = math.sin(2 * math.pi * hour / 24.0)
        hour_cos = math.cos(2 * math.pi * hour / 24.0)
        day_of_week = float(dt.weekday()) if dt else 0.0

        sev = event.severity.lower() if event.severity else "info"
        sev_weight = SEVERITY_MAP.get(sev, 1.0)

        cat = event.category.lower() if event.category else ""
        is_auth = 1.0 if cat == "authentication" else 0.0
        is_proc = 1.0 if cat == "process" else 0.0
        is_net = 1.0 if cat == "network" else 0.0

        act = event.action.lower() if event.action else ""
        is_failed = 1.0 if "fail" in act or "unauthorized" in act or "denied" in act else 0.0

        src_ip = event.source.ip if event.source else None
        has_src_ip = 1.0 if src_ip else 0.0
        is_private_src = 0.0
        if src_ip:
            if src_ip.startswith("10.") or src_ip.startswith("192.168.") or src_ip.startswith("172.16."):
                is_private_src = 1.0

        dest_port = float(event.destination.port) if (event.destination and event.destination.port) else 0.0

        raw_features = {
            "severity_weight": sev_weight,
            "hour_sin": hour_sin,
            "hour_cos": hour_cos,
            "day_of_week": day_of_week,
            "is_auth_category": is_auth,
            "is_process_category": is_proc,
            "is_network_category": is_net,
            "is_failed_action": is_failed,
            "has_source_ip": has_src_ip,
            "is_private_source_ip": is_private_src,
            "dest_port": dest_port,
        }

        return feature_validator.validate_features_dict(raw_features)

    def transform_batch(self, events: List[SecurityEventCreate]) -> pd.DataFrame:
        """Convert a list of SecurityEvents into a validated pandas DataFrame."""
        if not events:
            df_empty = pd.DataFrame(columns=self.feature_names)
            return feature_validator.validate_and_clean_df(df_empty)

        rows = [self.extract_features(ev) for ev in events]
        df = pd.DataFrame(rows, columns=self.feature_names)
        return feature_validator.validate_and_clean_df(df)


feature_extractor = EventFeatureExtractor()
