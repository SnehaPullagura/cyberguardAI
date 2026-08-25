import math
import numpy as np
import pandas as pd
from typing import List, Dict, Any
from app.schemas.event import SecurityEventCreate


class EventFeatureExtractor:
    """Extracts numerical feature vectors from security events for ML models."""

    FEATURE_NAMES = [
        "severity_weight",
        "hour_sin",
        "hour_cos",
        "day_of_week",
        "is_auth_category",
        "is_process_category",
        "is_network_category",
        "is_failed_action",
        "has_source_ip",
        "is_private_source_ip",
        "dest_port",
    ]

    SEVERITY_MAP = {
        "info": 1.0,
        "low": 2.0,
        "medium": 4.0,
        "high": 7.0,
        "critical": 10.0,
    }

    def extract_features(self, event: SecurityEventCreate) -> Dict[str, float]:
        """Extract a dict of numerical features for a single event."""
        dt = event.timestamp
        hour = dt.hour
        hour_sin = math.sin(2 * math.pi * hour / 24.0)
        hour_cos = math.cos(2 * math.pi * hour / 24.0)
        day_of_week = float(dt.weekday())

        sev_weight = self.SEVERITY_MAP.get(event.severity.lower(), 1.0)

        cat = event.category.lower()
        is_auth = 1.0 if cat == "authentication" else 0.0
        is_proc = 1.0 if cat == "process" else 0.0
        is_net = 1.0 if cat == "network" else 0.0

        act = event.action.lower()
        is_failed = 1.0 if "fail" in act or "unauthorized" in act or "denied" in act else 0.0

        src_ip = event.source.ip if event.source else None
        has_src_ip = 1.0 if src_ip else 0.0
        is_private_src = 0.0
        if src_ip:
            if src_ip.startswith("10.") or src_ip.startswith("192.168.") or src_ip.startswith("172.16."):
                is_private_src = 1.0

        dest_port = float(event.destination.port) if (event.destination and event.destination.port) else 0.0

        return {
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

    def transform_batch(self, events: List[SecurityEventCreate]) -> pd.DataFrame:
        """Convert a list of SecurityEvents into a structured pandas DataFrame."""
        rows = [self.extract_features(ev) for ev in events]
        df = pd.DataFrame(rows, columns=self.FEATURE_NAMES)
        return df


feature_extractor = EventFeatureExtractor()
