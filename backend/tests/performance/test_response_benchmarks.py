import time
import pytest
from app.response.trigger_evaluator import trigger_evaluator
from app.response.loop_guard import loop_guard


def test_trigger_evaluation_latency_benchmark():
    conditions = [
        {"field": "risk_score", "operator": "gte", "value": 75.0},
        {"field": "severity", "operator": "in", "value": ["high", "critical"]},
        {"field": "source_ip", "operator": "contains", "value": "192.168"},
        {"field": "category", "operator": "eq", "value": "Authentication"},
    ]

    context = {
        "risk_score": 88.0,
        "severity": "critical",
        "source_ip": "192.168.1.105",
        "category": "Authentication",
    }

    start = time.time()
    iterations = 2000
    for _ in range(iterations):
        res = trigger_evaluator.evaluate_all(conditions, context)
        assert res is True
    total_time_ms = (time.time() - start) * 1000.0
    avg_latency_us = (total_time_ms / iterations) * 1000.0

    print(f"\n[BENCHMARK] 2000 Trigger evaluations: {total_time_ms:.2f}ms (Avg: {avg_latency_us:.2f}µs/eval)")
    assert avg_latency_us < 500.0  # Must be under 0.5ms per evaluation


def test_cooldown_lock_lookup_benchmark():
    start = time.time()
    iterations = 100
    for i in range(iterations):
        loop_guard.acquire_execution_lock("PB-BENCH", f"entity-{i}", cooldown_seconds=10)
    total_time_ms = (time.time() - start) * 1000.0
    avg_time_us = (total_time_ms / iterations) * 1000.0

    print(f"\n[BENCHMARK] 100 Cooldown lock acquisitions: {total_time_ms:.2f}ms (Avg: {avg_time_us:.2f}µs/op)")
    assert avg_time_us < 5000.0  # Must be under 5ms per lock op
