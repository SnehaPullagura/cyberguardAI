import pytest
from app.edr.agent_telemetry import edr_sensor, PROCESS_INJECTION_TECHNIQUES
from app.identity.itdr_engine import itdr_engine, ITDR_DETECTION_PATTERNS


def test_edr_process_injection_catalog():
    assert len(PROCESS_INJECTION_TECHNIQUES) >= 50
    t1 = PROCESS_INJECTION_TECHNIQUES[0]
    assert t1["technique_id"] == "INJ-001"
    assert t1["severity"] == "CRITICAL"


def test_edr_sensor_office_spawn_detection():
    res = edr_sensor.analyze_process_event({
        "parent_process": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c powershell.exe -enc aW52b2tl",
    })
    assert res["anomalous"] is True
    assert res["highest_severity"] == "CRITICAL"
    assert any(d["rule"] == "EDR-MAL-001" for d in res["detected_techniques"])


def test_itdr_patterns_catalog():
    assert len(ITDR_DETECTION_PATTERNS) >= 50
    p1 = ITDR_DETECTION_PATTERNS[0]
    assert p1["pattern_id"] == "ITDR-001"
    assert p1["mitre_id"] == "T1606.002"


def test_itdr_mfa_fatigue_detection():
    res = itdr_engine.analyze_auth_event({
        "username": "victim_user@corp.local",
        "auth_protocol": "RADIUS",
        "status": "success",
        "mfa_prompts_count": 6,
    })
    assert res["threat_detected"] is True
    assert res["highest_severity"] == "HIGH"
    assert any(a["rule"] == "ITDR-MFA-001" for a in res["detected_anomalies"])
