import pytest
from app.response.trigger_evaluator import trigger_evaluator


def test_trigger_evaluator_operators():
    context = {
        "risk_score": 88.5,
        "severity": "critical",
        "category": "Authentication",
        "source_ip": "10.0.4.15",
        "nested": {"entity": "host-alpha", "tag_list": ["c2", "malware"]},
    }

    # Test gte
    assert trigger_evaluator.evaluate_single_condition({"field": "risk_score", "operator": "gte", "value": 80.0}, context)
    assert not trigger_evaluator.evaluate_single_condition({"field": "risk_score", "operator": "gte", "value": 95.0}, context)

    # Test eq
    assert trigger_evaluator.evaluate_single_condition({"field": "severity", "operator": "eq", "value": "critical"}, context)
    assert not trigger_evaluator.evaluate_single_condition({"field": "severity", "operator": "eq", "value": "low"}, context)

    # Test ne
    assert trigger_evaluator.evaluate_single_condition({"field": "severity", "operator": "ne", "value": "low"}, context)

    # Test contains
    assert trigger_evaluator.evaluate_single_condition({"field": "category", "operator": "contains", "value": "auth"}, context)

    # Test in
    assert trigger_evaluator.evaluate_single_condition({"field": "severity", "operator": "in", "value": ["high", "critical"]}, context)

    # Test nested dot notation
    assert trigger_evaluator.evaluate_single_condition({"field": "nested.entity", "operator": "eq", "value": "host-alpha"}, context)
    assert trigger_evaluator.evaluate_single_condition({"field": "nested.tag_list", "operator": "contains", "value": "c2"}, context)


def test_trigger_evaluator_all_conditions():
    context = {"risk_score": 90.0, "severity": "critical"}
    conditions = [
        {"field": "risk_score", "operator": "gte", "value": 85.0},
        {"field": "severity", "operator": "eq", "value": "critical"},
    ]
    assert trigger_evaluator.evaluate_all(conditions, context)

    conditions_failing = [
        {"field": "risk_score", "operator": "gte", "value": 85.0},
        {"field": "severity", "operator": "eq", "value": "low"},
    ]
    assert not trigger_evaluator.evaluate_all(conditions_failing, context)


def test_invalid_conditions_handling():
    context = {"risk_score": 50.0}
    # Unsupported operator
    assert not trigger_evaluator.evaluate_single_condition({"field": "risk_score", "operator": "exec_python", "value": "test"}, context)
    # Non-existent field
    assert not trigger_evaluator.evaluate_single_condition({"field": "unknown_field", "operator": "eq", "value": 123}, context)
