"""Vulnerability & Security Posture REST API Router."""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.posture.vuln_scanner import vuln_scanner
from app.posture.asset_discovery import get_asset_inventory, get_asset_by_id
from app.posture.remediation_advisor import remediation_advisor
from app.security.auth import get_current_active_user
from app.models.user import User

router = APIRouter(prefix="/posture", tags=["Vulnerability & Posture Management"])


@router.get("/cisa-kev")
def get_cisa_kev_catalog(
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    current_user: User = Depends(get_current_active_user),
):
    """Retrieve CISA Known Exploited Vulnerabilities catalog with EPSS ratings."""
    return vuln_scanner.list_cisa_kev(vendor=vendor)


@router.get("/assets")
def get_assets(
    current_user: User = Depends(get_current_active_user),
):
    """Retrieve enterprise asset inventory with exposure classifications."""
    return get_asset_inventory()


@router.get("/assets/{asset_id}/scan")
def scan_single_asset(
    asset_id: str,
    current_user: User = Depends(get_current_active_user),
):
    """Run vulnerability & posture scan on a specific enterprise asset."""
    asset = get_asset_by_id(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found.")

    scan_result = vuln_scanner.scan_asset_vulnerabilities(asset.get("software", []))
    return {
        "asset": asset,
        "scan_result": scan_result,
    }


@router.get("/remediation-plan")
def get_remediation_plan(
    current_user: User = Depends(get_current_active_user),
):
    """Generate prioritized vulnerability remediation plan and SLA compliance overview."""
    return remediation_advisor.generate_remediation_plan()
