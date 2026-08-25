import logging
from typing import Dict, Any, List, Optional
import httpx

from app.threat_intel.stix_parser import stix_parser, ParsedSTIXBundle

logger = logging.getLogger(__name__)


class TAXII21Client:
    """Client for TAXII 2.1 Discovery, Collections, and STIX Object Polling."""

    TAXII21_MEDIA_TYPE = "application/taxii+json;version=2.1"
    STIX21_MEDIA_TYPE = "application/stix+json;version=2.1"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def poll_collection(
        self,
        collection_url: str,
        api_key: Optional[str] = None,
        added_after: Optional[str] = None,
    ) -> ParsedSTIXBundle:
        """Polls a TAXII 2.1 collection URL for STIX 2.1 bundles."""
        headers = {
            "Accept": f"{self.TAXII21_MEDIA_TYPE}, {self.STIX21_MEDIA_TYPE}, application/json",
            "User-Agent": "CyberGuard-AI-TAXII-Client/1.0",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        params = {}
        if added_after:
            params["added_after"] = added_after

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(collection_url, headers=headers, params=params)
                if resp.status_code == 200:
                    bundle_data = resp.json()
                    return stix_parser.parse_bundle(bundle_data)
                else:
                    logger.warning(f"TAXII poll error {resp.status_code} from {collection_url}: {resp.text[:200]}")
        except Exception as e:
            logger.info(f"TAXII endpoint {collection_url} unreachable ({e}). Returning empty parsed bundle.")

        return ParsedSTIXBundle()

    def generate_mock_taxii_bundle(self, feed_name: str = "CyberGuard-Threat-Feed") -> Dict[str, Any]:
        """Generates a realistic STIX 2.1 bundle for offline testing and demonstration."""
        return {
            "type": "bundle",
            "id": "bundle--5d0b9229-4b68-4560-b883-9b2f67643cf3",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "created": "2026-08-25T00:00:00.000Z",
                    "modified": "2026-08-25T00:00:00.000Z",
                    "name": "Cobalt Strike C2 Beacon IP",
                    "description": "Known Cobalt Strike Team Server detected in the wild.",
                    "indicator_types": ["malicious-activity", "c2"],
                    "pattern": "[ipv4-addr:value = '198.51.100.220']",
                    "pattern_type": "stix",
                    "valid_from": "2026-08-01T00:00:00.000Z",
                    "confidence": 95,
                    "labels": ["apt29", "c2", "cobalt-strike"],
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1071.001"}
                    ],
                },
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--9f3f3e3c-28e5-5dcf-049a-09ff57c4de4a",
                    "created": "2026-08-25T00:00:00.000Z",
                    "modified": "2026-08-25T00:00:00.000Z",
                    "name": "LockBit Ransomware Dropper SHA256",
                    "description": "Payload hash associated with LockBit 3.0 campaigns.",
                    "indicator_types": ["malware"],
                    "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
                    "pattern_type": "stix",
                    "confidence": 90,
                    "labels": ["ransomware", "lockbit"],
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1486"}
                    ],
                },
                {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": "malware--a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
                    "name": "Cobalt Strike",
                    "is_family": True,
                    "malware_types": ["remote-access-trojan"],
                    "description": "Adversary emulation software frequently abused by threat actors.",
                },
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": "attack-pattern--b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e",
                    "name": "Application Layer Protocol: Web Protocols",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1071.001"}
                    ],
                },
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f",
                    "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "target_ref": "malware--a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
                    "relationship_type": "indicates",
                },
            ],
        }


taxii_client = TAXII21Client()
