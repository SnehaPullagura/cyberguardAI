from typing import List

FEATURE_SCHEMA_VERSION = "1.0"

FEATURE_NAMES: List[str] = [
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
