import pytest
from app.observability.metrics import MetricsRegistry, metrics


def test_metrics_counter_increment():
    reg = MetricsRegistry()
    reg.increment_counter("cyberguard_events_ingested_total", 5.0)
    assert reg._counters["cyberguard_events_ingested_total"] == 5.0

    reg.increment_counter("cyberguard_events_ingested_total", 2.0)
    assert reg._counters["cyberguard_events_ingested_total"] == 7.0


def test_metrics_gauge_set():
    reg = MetricsRegistry()
    reg.set_gauge("cyberguard_websocket_connections_active", 42.0)
    assert reg._gauges["cyberguard_websocket_connections_active"] == 42.0


def test_metrics_histogram_recording():
    reg = MetricsRegistry()
    reg.record_histogram("cyberguard_ml_inference_duration_seconds", 0.015)
    reg.record_histogram("cyberguard_ml_inference_duration_seconds", 0.025)
    assert len(reg._histograms["cyberguard_ml_inference_duration_seconds"]) == 2


def test_prometheus_exposition_format():
    reg = MetricsRegistry()
    reg.increment_counter("cyberguard_alerts_created_total", 10.0)
    reg.set_gauge("cyberguard_websocket_connections_active", 5.0)
    reg.record_histogram("cyberguard_ml_inference_duration_seconds", 0.012)

    expo = reg.generate_prometheus_exposition()
    assert "# TYPE cyberguard_alerts_created_total counter" in expo
    assert "cyberguard_alerts_created_total 10.0" in expo
    assert "# TYPE cyberguard_websocket_connections_active gauge" in expo
    assert "cyberguard_websocket_connections_active 5.0" in expo
    assert "# TYPE cyberguard_ml_inference_duration_seconds summary" in expo
    assert "cyberguard_ml_inference_duration_seconds_count 1" in expo


def test_metrics_histogram_bounds_capping():
    reg = MetricsRegistry()
    for i in range(1200):
        reg.record_histogram("cyberguard_test_hist", float(i))
    # Must cap at max 1000 samples
    assert len(reg._histograms["cyberguard_test_hist"]) == 1000


def test_metrics_dynamic_new_counter_creation():
    reg = MetricsRegistry()
    reg.increment_counter("cyberguard_custom_security_counter", 3.0)
    assert reg._counters["cyberguard_custom_security_counter"] == 3.0


def test_metrics_gauge_zero_and_negative():
    reg = MetricsRegistry()
    reg.set_gauge("cyberguard_websocket_connections_active", 0.0)
    assert reg._gauges["cyberguard_websocket_connections_active"] == 0.0


def test_global_singleton_metrics_access():
    metrics.increment_counter("cyberguard_events_processed_total", 1.0)
    assert metrics._counters["cyberguard_events_processed_total"] >= 1.0
