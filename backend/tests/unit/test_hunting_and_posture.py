import pytest
from app.hunting.kql_translator import kql_translator, spl_translator
from app.hunting.hunting_playbooks import THREAT_HUNTING_PLAYBOOKS, get_hunting_playbook_by_id
from app.hunting.hunting_engine import hunting_engine
from app.posture.vuln_scanner import vuln_scanner, CISA_KNOWN_EXPLOITED_VULNERABILITIES
from app.posture.asset_discovery import get_asset_inventory, get_asset_by_id
from app.posture.remediation_advisor import remediation_advisor


def test_kql_translator_basic_and_pipe_queries():
    kql = "SecurityEvent | where Category == 'network' and Action contains 'login' | project Timestamp, SourceIP, Action | take 25"
    sql = kql_translator.translate(kql)
    assert "SELECT" in sql
    assert "FROM events" in sql
    assert "category = 'network'" in sql
    assert "action ILIKE '%login%'" in sql
    assert "LIMIT 25" in sql


def test_kql_translator_summarize_aggregation():
    kql = "SecurityEvent | where Category == 'auth' | summarize count() by SourceIP, Action | order by count desc"
    sql = kql_translator.translate(kql)
    assert "COUNT(*) AS count" in sql
    assert "GROUP BY source_ip, action" in sql
    assert "ORDER BY count DESC" in sql


def test_spl_translator_queries():
    spl = "search category=network action=*login* | head 50"
    sql = spl_translator.translate(spl)
    assert "SELECT * FROM events" in sql
    assert "category = 'network'" in sql
    assert "action ILIKE '%login%'" in sql
    assert "LIMIT 50" in sql


def test_threat_hunting_playbooks_catalog():
    assert len(THREAT_HUNTING_PLAYBOOKS) >= 50
    pb1 = get_hunting_playbook_by_id("HUNT-001")
    assert pb1 is not None
    assert pb1["severity"] == "CRITICAL"
    assert "kql_query" in pb1
    assert "analysis_steps" in pb1


def test_threat_hunting_engine_execution(db_session):
    res = hunting_engine.execute_hunt_query(
        db=db_session,
        query="SecurityEvent | where Category == 'authentication' | take 10",
        query_type="kql",
    )
    assert res["status"] == "success"
    assert "sql_executed" in res
    assert "execution_time_ms" in res


def test_vulnerability_scanner_and_cisa_catalog():
    assert len(CISA_KNOWN_EXPLOITED_VULNERABILITIES) >= 40
    scan = vuln_scanner.scan_asset_vulnerabilities([
        {"name": "Apache Log4j", "version": "2.14.1"},
        {"name": "OpenSSH Server", "version": "8.9"},
    ])
    assert scan["total_vulnerabilities"] >= 1
    assert scan["critical_count"] >= 1
    assert scan["overall_asset_risk_score"] > 0


def test_asset_discovery_inventory():
    assets = get_asset_inventory()
    assert len(assets) >= 20
    a1 = get_asset_by_id("AST-DC-01")
    assert a1 is not None
    assert a1["criticality"] == "TIER-0 (Crown Jewel)"


def test_remediation_advisor_generation():
    plan = remediation_advisor.generate_remediation_plan()
    assert plan["total_assets_evaluated"] >= 20
    assert plan["total_remediations_required"] >= 1
    assert "recommended_actions" in plan
    assert len(plan["recommended_actions"]) > 0
