import time
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class MetricsRegistry:
    """Production Prometheus / OpenTelemetry In-Memory Metric Exporter."""

    def __init__(self):
        self._counters: Dict[str, float] = {
            "cyberguard_events_ingested_total": 0.0,
            "cyberguard_events_processed_total": 0.0,
            "cyberguard_events_failed_total": 0.0,
            "cyberguard_ml_inferences_total": 0.0,
            "cyberguard_alerts_created_total": 0.0,
            "cyberguard_incidents_created_total": 0.0,
            "cyberguard_playbook_executions_total": 0.0,
            "cyberguard_compliance_evaluations_total": 0.0,
        }
        self._gauges: Dict[str, float] = {
            "cyberguard_websocket_connections_active": 0.0,
            "cyberguard_system_memory_usage_ratio": 0.35,
            "cyberguard_system_cpu_usage_ratio": 0.20,
        }
        self._histograms: Dict[str, List[float]] = {
            "cyberguard_ml_inference_duration_seconds": [],
            "cyberguard_ingestion_latency_seconds": [],
            "cyberguard_rule_evaluation_duration_seconds": [],
        }

    def increment_counter(self, name: str, value: float = 1.0):
        if name in self._counters:
            self._counters[name] += value
        else:
            self._counters[name] = value

    def set_gauge(self, name: str, value: float):
        self._gauges[name] = value

    def record_histogram(self, name: str, value: float):
        if name not in self._histograms:
            self._histograms[name] = []
        self._histograms[name].append(value)
        # Keep last 1000 samples
        if len(self._histograms[name]) > 1000:
            self._histograms[name].pop(0)

    def generate_prometheus_exposition(self) -> str:
        """Generates standard text format output for Prometheus scrapers."""
        lines = []

        # 1. Counters
        for name, val in self._counters.items():
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {val}")

        # 2. Gauges
        for name, val in self._gauges.items():
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {val}")

        # 3. Histograms (Summary count and sum)
        for name, samples in self._histograms.items():
            lines.append(f"# TYPE {name} summary")
            count = len(samples)
            total_sum = sum(samples) if count > 0 else 0.0
            lines.append(f"{name}_count {count}")
            lines.append(f"{name}_sum {total_sum:.6f}")

        return "\n".join(lines) + "\n"


metrics = MetricsRegistry()
