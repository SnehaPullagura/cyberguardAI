import uuid
from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.models.threat_intel import ThreatIoC
from app.models.threat_feed import ThreatFeed
from app.threat_intel.feed_scheduler import feed_scheduler
from app.threat_intel.historical_correlator import historical_correlator


def test_threat_feed_sync_and_deduplication(db_session: Session):
    feed = ThreatFeed(
        feed_id=f"TEST-FEED-{uuid.uuid4()}",
        name="Unit Test Threat Feed",
        feed_type="mock_stix",
        url="http://mock.taxii.local/taxii2/collections/123/objects",
        enabled=True,
        confidence_weight=0.9,
    )
    db_session.add(feed)
    db_session.commit()

    # Initial sync
    res1 = feed_scheduler.sync_feed(db_session, feed)
    assert res1["status"] == "healthy"
    assert res1["new_iocs"] >= 2

    # Second sync -> should deduplicate and update existing IoCs
    res2 = feed_scheduler.sync_feed(db_session, feed)
    assert res2["status"] == "healthy"
    assert res2["updated_iocs"] >= 2


def test_historical_ioc_correlation_ip(db_session: Session):
    malicious_ip = "198.51.100.77"

    # Create a historical event
    event = SecurityEvent(
        event_id=f"evt-{uuid.uuid4()}",
        source_type="firewall",
        category="network",
        action="blocked_conn",
        severity="high",
        source_ip=malicious_ip,
        destination_ip="10.0.0.5",
        timestamp=datetime.utcnow() - timedelta(days=2),
        raw_payload='{"action": "blocked_conn"}',
    )
    db_session.add(event)
    db_session.commit()

    # Correlate
    ioc = ThreatIoC(
        value=malicious_ip,
        ioc_type="ip",
        threat_type="C2",
    )
    matches = historical_correlator.correlate_ioc(db_session, ioc, lookback_days=7)
    assert len(matches) >= 1
    assert matches[0]["source_ip"] == malicious_ip


def test_historical_ioc_correlation_domain_and_hash(db_session: Session):
    malicious_domain = "c2-domain-evil.org"

    event = SecurityEvent(
        event_id=f"evt-{uuid.uuid4()}",
        source_type="dns_server",
        category="network",
        action="dns_query",
        severity="medium",
        source_ip="192.168.1.50",
        destination_ip="8.8.8.8",
        timestamp=datetime.utcnow() - timedelta(days=1),
        raw_payload=f'{{"query": "{malicious_domain}"}}',
    )
    db_session.add(event)
    db_session.commit()

    ioc = ThreatIoC(
        value=malicious_domain,
        ioc_type="domain",
        threat_type="malware",
    )
    matches = historical_correlator.correlate_ioc(db_session, ioc, lookback_days=7)
    assert len(matches) >= 1
    assert matches[0]["action"] == "dns_query"


def test_feed_prune_expired_iocs(db_session: Session):
    # Add an old IoC past expiry
    old_ioc = ThreatIoC(
        ioc_type="ip",
        value="203.0.113.199",
        threat_type="scanner",
        confidence=0.5,
        source="test",
        is_active=True,
        last_seen=datetime.utcnow() - timedelta(days=100),
        expires_at=datetime.utcnow() - timedelta(days=1),
    )
    db_session.add(old_ioc)
    db_session.commit()

    pruned = feed_scheduler.prune_expired_iocs(db_session)
    assert pruned >= 1
    db_session.refresh(old_ioc)
    assert old_ioc.is_active is False


def test_threat_intel_rest_api(client: TestClient, admin_headers: dict, viewer_headers: dict):
    # 1. STIX 2.1 Bundle Import as Admin
    bundle_payload = {
        "bundle": {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{uuid.uuid4()}",
                    "pattern": "[ipv4-addr:value = '203.0.113.88']",
                    "confidence": 92,
                    "indicator_types": ["c2"],
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1071.001"}
                    ],
                }
            ],
        }
    }

    import_res = client.post("/api/v1/threat-intel/stix/import", json=bundle_payload, headers=admin_headers)
    assert import_res.status_code == 200
    assert import_res.json()["indicators_ingested"] == 1

    # 2. STIX Export as Viewer
    export_res = client.get("/api/v1/threat-intel/stix/export", headers=viewer_headers)
    assert export_res.status_code == 200
    bundle_data = export_res.json()
    assert bundle_data["type"] == "bundle"
    assert len(bundle_data["objects"]) >= 1

    # 3. Create Threat Feed
    feed_payload = {
        "feed_id": f"FEED-{uuid.uuid4()}",
        "name": "Integration Test TAXII Feed",
        "feed_type": "taxii21",
        "url": "https://taxii.example.org/taxii2/collections/1/objects",
        "poll_interval_minutes": 120,
    }
    create_feed_res = client.post("/api/v1/threat-intel/feeds", json=feed_payload, headers=admin_headers)
    assert create_feed_res.status_code == 201

    # 4. Trigger Feed Sync via REST API
    sync_res = client.post(f"/api/v1/threat-intel/feeds/{feed_payload['feed_id']}/sync", headers=admin_headers)
    assert sync_res.status_code == 200

    # 5. Viewer RBAC Restriction on Feed Creation
    forbidden_res = client.post("/api/v1/threat-intel/feeds", json=feed_payload, headers=viewer_headers)
    assert forbidden_res.status_code == 403
