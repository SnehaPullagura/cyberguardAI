from app.engines.rule_engine import rule_engine
from app.schemas.event import SecurityEventCreate, EndpointSchema, ProcessSchema


def test_rule_engine_match_all():
    event = SecurityEventCreate(
        source_type="syslog",
        category="authentication",
        action="login_failed",
        severity="high",
        source=EndpointSchema(ip="1.2.3.4", user="admin"),
    )

    condition = {
        "category": "authentication",
        "match_all": {"action": "login_failed", "source.user": "admin"},
    }

    assert rule_engine.evaluate_event(event, condition) is True

    condition_mismatch = {
        "category": "authentication",
        "match_all": {"action": "login_failed", "source.user": "guest"},
    }

    assert rule_engine.evaluate_event(event, condition_mismatch) is False


def test_rule_engine_regex_match():
    event = SecurityEventCreate(
        source_type="winevent",
        category="process",
        action="process_created",
        severity="critical",
        process=ProcessSchema(name="powershell.exe", command_line="powershell -EncodedCommand AAAA=="),
    )

    condition = {
        "category": "process",
        "match_any": {"process.command_line": "regex:.*-encodedcommand.*"},
    }

    assert rule_engine.evaluate_event(event, condition) is True
