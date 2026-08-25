import pytest
from app.threat_intel.stix_parser import stix_parser
from app.threat_intel.taxii_client import taxii_client


def test_stix_parser_bundle_indicators():
    mock_bundle = {
        "type": "bundle",
        "id": "bundle--11111111-2222-3333-4444-555555555555",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--aaa-111",
                "name": "C2 Server",
                "pattern": "[ipv4-addr:value = '198.51.100.99']",
                "confidence": 90,
                "labels": ["apt28"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1071"}
                ],
            },
            {
                "type": "indicator",
                "id": "indicator--bbb-222",
                "name": "Phishing Domain",
                "pattern": "[domain-name:value = 'malicious-portal.com']",
                "confidence": 85,
            },
            {
                "type": "indicator",
                "id": "indicator--ccc-333",
                "name": "Malware Hash",
                "pattern": "[file:hashes.'SHA-256' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
                "confidence": 95,
            },
            {
                "type": "indicator",
                "id": "indicator--url-444",
                "name": "Malicious URL",
                "pattern": "[url:value = 'http://badactor.xyz/payload.exe']",
                "confidence": 80,
            },
            {
                "type": "indicator",
                "id": "indicator--md5-555",
                "name": "MD5 Hash",
                "pattern": "[file:hashes.'MD5' = '1234567890abcdef1234567890abcdef']",
                "confidence": 75,
            },
            {
                "type": "malware",
                "id": "malware--ddd-444",
                "name": "Emotet",
                "is_family": True,
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--att-1",
                "name": "PowerShell Execution",
            },
            {
                "type": "tool",
                "id": "tool--tool-1",
                "name": "Mimikatz",
            },
            {
                "type": "campaign",
                "id": "campaign--camp-1",
                "name": "Operation Ghost",
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--apt-29",
                "name": "Cozy Bear",
            },
            {
                "type": "relationship",
                "id": "relationship--eee-555",
                "source_ref": "indicator--aaa-111",
                "target_ref": "malware--ddd-444",
                "relationship_type": "indicates",
            },
        ],
    }

    parsed = stix_parser.parse_bundle(mock_bundle)
    assert len(parsed.indicators) == 5
    assert len(parsed.malware) == 1
    assert len(parsed.attack_patterns) == 1
    assert len(parsed.tools) == 1
    assert len(parsed.campaigns) == 1
    assert len(parsed.intrusion_sets) == 1
    assert len(parsed.relationships) == 1

    # Check IP extraction
    ip_ind = next(i for i in parsed.indicators if i["ioc_type"] == "ip")
    assert ip_ind["value"] == "198.51.100.99"
    assert ip_ind["confidence"] == 0.90
    assert ip_ind["mitre_attack_id"] == "T1071"

    # Check Domain extraction
    dom_ind = next(i for i in parsed.indicators if i["ioc_type"] == "domain")
    assert dom_ind["value"] == "malicious-portal.com"

    # Check URL extraction
    url_ind = next(i for i in parsed.indicators if i["ioc_type"] == "url")
    assert url_ind["value"] == "http://badactor.xyz/payload.exe"

    # Check MD5 extraction
    md5_ind = next(i for i in parsed.indicators if i["ioc_type"] == "md5")
    assert md5_ind["value"] == "1234567890abcdef1234567890abcdef"


def test_stix_parser_graceful_fallbacks():
    # Empty or invalid bundle
    res_none = stix_parser.parse_bundle(None)
    assert len(res_none.indicators) == 0

    res_empty = stix_parser.parse_bundle({})
    assert len(res_empty.indicators) == 0

    # Single object without objects list
    single_obj = {
        "type": "indicator",
        "id": "indicator--single-1",
        "name": "Single Indicator",
        "pattern": "[ipv4-addr:value = '10.10.10.10']",
    }
    res_single = stix_parser.parse_bundle(single_obj)
    assert len(res_single.indicators) == 1


def test_taxii_client_mock_bundle():
    bundle_data = taxii_client.generate_mock_taxii_bundle("Test-TAXII-Feed")
    parsed = stix_parser.parse_bundle(bundle_data)
    assert len(parsed.indicators) >= 2
    assert any(ind["value"] == "198.51.100.220" for ind in parsed.indicators)
    assert len(parsed.relationships) >= 1


def test_taxii_client_offline_fallback():
    # Unreachable local URL
    bundle = taxii_client.poll_collection("http://127.0.0.1:59999/taxii2/collections/bad")
    assert len(bundle.indicators) == 0


def test_stix_parser_pattern_edge_cases():
    # Indicator with custom name fallback
    custom_ind = {
        "type": "indicator",
        "id": "indicator--custom-999",
        "name": "Suspicious-Domain.biz",
        "pattern": "[custom-type:val = '123']",
    }
    parsed = stix_parser.parse_bundle(custom_ind)
    assert len(parsed.indicators) == 1
    assert parsed.indicators[0]["value"] == "Suspicious-Domain.biz"


def test_stix_parser_indicator_without_name_or_pattern():
    bad_ind = {"type": "indicator", "id": "indicator--bad"}
    parsed = stix_parser.parse_bundle(bad_ind)
    assert len(parsed.indicators) == 0
