import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class ParsedSTIXBundle:
    def __init__(self):
        self.indicators: List[Dict[str, Any]] = []
        self.malware: List[Dict[str, Any]] = []
        self.intrusion_sets: List[Dict[str, Any]] = []
        self.attack_patterns: List[Dict[str, Any]] = []
        self.tools: List[Dict[str, Any]] = []
        self.campaigns: List[Dict[str, Any]] = []
        self.relationships: List[Dict[str, Any]] = []
        self.raw_objects: List[Dict[str, Any]] = []


class STIX21Parser:
    """Parser for STIX 2.1 Bundles and Domain Objects (SDOs / SROs)."""

    # Regex patterns to extract IoCs from STIX 2.1 pattern strings
    IP_PATTERN = re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'", re.IGNORECASE)
    DOMAIN_PATTERN = re.compile(r"domain-name:value\s*=\s*'([^']+)'", re.IGNORECASE)
    URL_PATTERN = re.compile(r"url:value\s*=\s*'([^']+)'", re.IGNORECASE)
    MD5_PATTERN = re.compile(r"file:hashes\.(?:MD5|'MD5')\s*=\s*'([a-fA-F0-9]{32})'", re.IGNORECASE)
    SHA256_PATTERN = re.compile(r"file:hashes\.(?:SHA-256|'SHA-256')\s*=\s*'([a-fA-F0-9]{64})'", re.IGNORECASE)

    def parse_bundle(self, bundle_dict: Dict[str, Any]) -> ParsedSTIXBundle:
        """Parses a STIX 2.1 JSON dictionary bundle."""
        result = ParsedSTIXBundle()

        if not isinstance(bundle_dict, dict):
            logger.warning("Invalid STIX bundle payload (not a dict).")
            return result

        objects = bundle_dict.get("objects", [])
        if not objects and "type" in bundle_dict:
            # Single object wrapped as dict
            objects = [bundle_dict]

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_type = obj.get("type")
            result.raw_objects.append(obj)

            if obj_type == "indicator":
                parsed_ioc = self._parse_indicator(obj)
                if parsed_ioc:
                    result.indicators.append(parsed_ioc)
            elif obj_type == "malware":
                result.malware.append(obj)
            elif obj_type == "intrusion-set":
                result.intrusion_sets.append(obj)
            elif obj_type == "attack-pattern":
                result.attack_patterns.append(obj)
            elif obj_type == "tool":
                result.tools.append(obj)
            elif obj_type == "campaign":
                result.campaigns.append(obj)
            elif obj_type == "relationship":
                result.relationships.append(obj)

        return result

    def _parse_indicator(self, ind: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extracts normalized IoC metadata from a STIX indicator object."""
        pattern = ind.get("pattern", "")
        ioc_type = None
        ioc_value = None

        ip_match = self.IP_PATTERN.search(pattern)
        if ip_match:
            ioc_type = "ip"
            ioc_value = ip_match.group(1)
        else:
            domain_match = self.DOMAIN_PATTERN.search(pattern)
            if domain_match:
                ioc_type = "domain"
                ioc_value = domain_match.group(1)
            else:
                url_match = self.URL_PATTERN.search(pattern)
                if url_match:
                    ioc_type = "url"
                    ioc_value = url_match.group(1)
                else:
                    sha_match = self.SHA256_PATTERN.search(pattern)
                    if sha_match:
                        ioc_type = "sha256"
                        ioc_value = sha_match.group(1)
                    else:
                        md5_match = self.MD5_PATTERN.search(pattern)
                        if md5_match:
                            ioc_type = "md5"
                            ioc_value = md5_match.group(1)

        if not ioc_type or not ioc_value:
            # Fallback if pattern is simple value
            if "name" in ind and ind["name"]:
                ioc_value = ind["name"]
                ioc_type = "indicator"
            else:
                return None

        # Extract MITRE ATT&CK reference if present
        mitre_id = None
        for ref in ind.get("external_references", []):
            if ref.get("source_name") in ["mitre-attack", "mitre-enterprise", "capec"]:
                mitre_id = ref.get("external_id")
                break

        # Confidence: STIX confidence is 0-100, normalize to 0.0-1.0
        stix_confidence = ind.get("confidence", 80)
        confidence = float(stix_confidence) / 100.0 if stix_confidence > 1.0 else float(stix_confidence)

        return {
            "stix_id": ind.get("id"),
            "ioc_type": ioc_type,
            "value": ioc_value,
            "threat_type": (ind.get("indicator_types") or ["malware"])[0] if ind.get("indicator_types") else "malware",
            "confidence": confidence,
            "description": ind.get("description") or ind.get("name"),
            "mitre_attack_id": mitre_id,
            "valid_from": ind.get("valid_from"),
            "valid_until": ind.get("valid_until"),
            "tags": ind.get("labels", []),
        }


stix_parser = STIX21Parser()
