import ipaddress
from typing import Dict, Any


class GeoIPEnricher:
    """Enriches IP addresses with RFC1918 internal classification and mock/real GeoIP attributes."""

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return False

    def enrich(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        source_ip = event_dict.get("source_ip")
        destination_ip = event_dict.get("destination_ip")

        enrichment: Dict[str, Any] = {}

        if source_ip:
            is_src_private = self.is_private_ip(source_ip)
            enrichment["source_network_type"] = "internal" if is_src_private else "external"
            if not is_src_private:
                enrichment["source_geo"] = {"country": "US", "city": "San Francisco", "asn": "AS15169"}

        if destination_ip:
            is_dst_private = self.is_private_ip(destination_ip)
            enrichment["destination_network_type"] = "internal" if is_dst_private else "external"

        return enrichment
