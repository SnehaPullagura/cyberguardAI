import pytest
from app.rules.catalog.windows_rules import WINDOWS_DETECTION_RULES, get_windows_rule_by_id
from app.rules.catalog.linux_rules import LINUX_DETECTION_RULES, get_linux_rule_by_id
from app.rules.catalog.cloud_rules import CLOUD_DETECTION_RULES
from app.rules.catalog.network_rules import NETWORK_DETECTION_RULES
from app.rules.catalog.container_rules import CONTAINER_DETECTION_RULES
from app.rules.catalog.sigma_engine import sigma_compiler
from app.threat_intel.knowledgebase.apt_campaigns import APT_ADVERSARY_KNOWLEDGEBASE
from app.threat_intel.knowledgebase.cve_signatures import CVE_KNOWLEDGEBASE
from app.threat_intel.knowledgebase.yara_rules import YARA_RULE_CATALOG
from app.response.playbooks.catalog.soar_catalog import SOAR_PLAYBOOK_CATALOG
from app.compliance.cis_benchmarks import CIS_BENCHMARK_CONTROLS
from app.datasets.waf_attack_corpora import WAF_ATTACK_RECORDS
from app.datasets.auth_telemetry_corpora import AUTH_TELEMETRY_RECORDS


def test_windows_rules_catalog():
    assert len(WINDOWS_DETECTION_RULES) >= 300
    r1 = get_windows_rule_by_id("RULE-WIN-0001")
    assert r1 is not None
    assert r1["category"] == "windows_event"
    assert "mitre_attack_id" in r1


def test_linux_rules_catalog():
    assert len(LINUX_DETECTION_RULES) >= 200
    r1 = get_linux_rule_by_id("RULE-LNX-0001")
    assert r1 is not None
    assert r1["category"] == "linux_auditd"


def test_cloud_and_network_rules():
    assert len(CLOUD_DETECTION_RULES) >= 150
    assert len(NETWORK_DETECTION_RULES) >= 150
    assert len(CONTAINER_DETECTION_RULES) >= 100


def test_sigma_compiler_engine():
    rule = {
        "condition": {
            "EventID": 4688,
            "CommandLine|contains": "-enc",
        }
    }
    matcher = sigma_compiler.compile_rule(rule)
    assert matcher({"EventID": 4688, "CommandLine": "powershell.exe -enc aW52b2tl"}) is True
    assert matcher({"EventID": 4688, "CommandLine": "calc.exe"}) is False


def test_threat_intel_knowledgebase():
    assert len(APT_ADVERSARY_KNOWLEDGEBASE) >= 150
    assert len(CVE_KNOWLEDGEBASE) >= 200
    assert len(YARA_RULE_CATALOG) >= 150


def test_soar_playbook_catalog():
    assert len(SOAR_PLAYBOOK_CATALOG) >= 50
    assert all("playbook_id" in p for p in SOAR_PLAYBOOK_CATALOG)


def test_cis_benchmarks_and_datasets():
    assert len(CIS_BENCHMARK_CONTROLS) >= 100
    assert len(WAF_ATTACK_RECORDS) >= 500
    assert len(AUTH_TELEMETRY_RECORDS) >= 500
