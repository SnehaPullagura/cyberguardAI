"""Enterprise Asset Discovery and Exposure Surface Inventory."""

from typing import List, Dict, Any, Optional

DEFAULT_ENTERPRISE_ASSETS: List[Dict[str, Any]] = [
    {
        "asset_id": "AST-DC-01",
        "hostname": "DC-PRIMARY.CORP.LOCAL",
        "ip_address": "10.0.1.10",
        "os": "Windows Server 2022 Datacenter",
        "asset_type": "Domain Controller",
        "criticality": "TIER-0 (Crown Jewel)",
        "exposure": "Internal Only",
        "software": [
            {"name": "Active Directory Domain Services", "version": "10.0.20348"},
            {"name": "Microsoft DNS Server", "version": "10.0.20348"},
            {"name": "Windows Defender Antivirus", "version": "4.18.23110"},
        ],
        "compliance_score": 94.5,
    },
    {
        "asset_id": "AST-WAF-01",
        "hostname": "EDGE-WAF-01.DMZ.LOCAL",
        "ip_address": "198.51.100.10",
        "os": "Ubuntu 22.04 LTS",
        "asset_type": "Security Gateway",
        "criticality": "TIER-1 (High)",
        "exposure": "Internet Facing",
        "software": [
            {"name": "Nginx Web Server", "version": "1.24.0"},
            {"name": "ModSecurity WAF Engine", "version": "3.0.12"},
            {"name": "OpenSSL Library", "version": "3.0.2"},
        ],
        "compliance_score": 88.0,
    },
    {
        "asset_id": "AST-APP-01",
        "hostname": "PROD-API-CLUSTER-01",
        "ip_address": "10.0.2.20",
        "os": "Red Hat Enterprise Linux 9",
        "asset_type": "Application Server",
        "criticality": "TIER-1 (High)",
        "exposure": "Internal API Gateway",
        "software": [
            {"name": "Python FastAPI Runtime", "version": "0.110.0"},
            {"name": "Uvicorn ASGI Server", "version": "0.28.0"},
            {"name": "Apache Log4j", "version": "2.14.1"},  # Vulnerable for demo/testing
        ],
        "compliance_score": 76.5,
    },
    {
        "asset_id": "AST-DB-01",
        "hostname": "TIMESCALEDB-PRIMARY",
        "ip_address": "10.0.3.50",
        "os": "Debian 12 Bookworm",
        "asset_type": "Database Cluster",
        "criticality": "TIER-0 (Crown Jewel)",
        "exposure": "Isolated Subnet",
        "software": [
            {"name": "PostgreSQL Database Server", "version": "16.2"},
            {"name": "TimescaleDB Extension", "version": "2.14.2"},
            {"name": "PgBouncer Connection Pooler", "version": "1.22.0"},
        ],
        "compliance_score": 96.0,
    },
]

# Generate additional mock assets to represent full enterprise infrastructure
ROLES = [
    ("WORKSTATION", "Windows 11 Enterprise", "Internal User Endpoint", "TIER-3"),
    ("K8S-NODE", "Ubuntu Core 22.04", "Container Worker Node", "TIER-2"),
    ("VPN-GATEWAY", "FortiOS FortiGate", "Perimeter VPN Gateway", "TIER-1"),
    ("FILE-SERVER", "Windows Server 2019", "Enterprise File Share", "TIER-2"),
    ("BACKUP-SRV", "Rocky Linux 9", "Immutable Backup Server", "TIER-0"),
]

for idx in range(5, 51):
    role_info = ROLES[idx % len(ROLES)]
    DEFAULT_ENTERPRISE_ASSETS.append({
        "asset_id": f"AST-ENT-{idx:03d}",
        "hostname": f"SRV-{role_info[0].lower()}-{idx:02d}.corp.local",
        "ip_address": f"10.{(idx % 10) + 1}.{(idx % 50) + 1}.{(idx % 240) + 10}",
        "os": role_info[1],
        "asset_type": role_info[0],
        "criticality": role_info[3],
        "exposure": role_info[2],
        "software": [
            {"name": f"{role_info[0]} Base Agent", "version": "2.4.1"},
            {"name": "OpenSSH Server", "version": "8.9p1"},
        ],
        "compliance_score": round(80.0 + (idx % 18) * 1.1, 1),
    })


def get_asset_inventory() -> List[Dict[str, Any]]:
    """Returns complete enterprise asset inventory."""
    return DEFAULT_ENTERPRISE_ASSETS


def get_asset_by_id(asset_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve single asset by unique identifier."""
    return next((a for a in DEFAULT_ENTERPRISE_ASSETS if a["asset_id"] == asset_id), None)
