import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.threat_intel import ThreatIoC
from app.models.threat_feed import ThreatFeed
from app.models.stix_object import STIXObject
from app.models.user import User
from app.schemas.threat_intel import (
    ThreatIoCRead,
    ThreatIoCCreate,
    ThreatFeedRead,
    ThreatFeedCreate,
    STIXBundleImportRequest,
    HistoricalCorrelationRequest,
)
from app.security.rbac import require_permission, Permission
from app.services.audit_service import audit_service
from app.threat_intel.stix_parser import stix_parser
from app.threat_intel.feed_scheduler import feed_scheduler
from app.threat_intel.historical_correlator import historical_correlator
from app.threat_intel.ioc_scorer import ioc_scorer
from app.websockets.pubsub import publish_realtime_event
from app.schemas.websocket import RealtimeEventEnvelope

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence Feed"])


# --- IoC Endpoints ---

@router.get("/iocs", response_model=List[ThreatIoCRead])
def list_iocs(
    ioc_type: Optional[str] = Query(None),
    threat_type: Optional[str] = Query(None),
    active_only: bool = Query(True),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_READ)),
):
    """Retrieve threat intelligence IoC records."""
    query = db.query(ThreatIoC)
    if ioc_type:
        query = query.filter(ThreatIoC.ioc_type == ioc_type)
    if threat_type:
        query = query.filter(ThreatIoC.threat_type == threat_type)
    if active_only:
        query = query.filter(ThreatIoC.is_active == True)

    return query.order_by(ThreatIoC.created_at.desc()).all()


@router.post("/iocs", response_model=ThreatIoCRead, status_code=status.HTTP_201_CREATED)
def add_ioc(
    payload: ThreatIoCCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_WRITE)),
):
    """Add a new Indicator of Compromise (IoC) to threat intel database."""
    existing = db.query(ThreatIoC).filter(
        ThreatIoC.value == payload.value,
        ThreatIoC.ioc_type == payload.ioc_type,
    ).first()

    comp_confidence = ioc_scorer.compute_composite_confidence(
        base_confidence=payload.confidence,
        source=payload.source,
    )

    if existing:
        existing.sightings_count += 1
        existing.last_seen = datetime.utcnow()
        existing.confidence = max(existing.confidence, comp_confidence)
        existing.decay_score = 1.0
        existing.is_active = True
        db.commit()
        db.refresh(existing)
        return existing

    ioc = ThreatIoC(
        id=str(uuid.uuid4()),
        ioc_type=payload.ioc_type,
        value=payload.value,
        threat_type=payload.threat_type,
        confidence=comp_confidence,
        source=payload.source,
        description=payload.description,
        stix_id=payload.stix_id,
        mitre_attack_id=payload.mitre_attack_id,
        tags=payload.tags or [],
        is_active=True,
        sightings_count=1,
        expires_at=payload.expires_at,
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)

    audit_service.log_action(
        db=db,
        action="IOC_CREATED",
        resource="threat_intel",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"ioc_value": ioc.value, "ioc_type": ioc.ioc_type, "mitre_id": ioc.mitre_attack_id},
    )

    publish_realtime_event(
        RealtimeEventEnvelope(
            type="ioc_created",
            data={"ioc_id": ioc.id, "value": ioc.value, "ioc_type": ioc.ioc_type, "threat_type": ioc.threat_type},
        )
    )

    return ioc


# --- STIX 2.1 Import / Export ---

@router.post("/stix/import", status_code=status.HTTP_200_OK)
def import_stix_bundle(
    payload: STIXBundleImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_WRITE)),
):
    """Imports a STIX 2.1 Bundle and extracts Indicators, Malware, and Attack Patterns."""
    parsed_bundle = stix_parser.parse_bundle(payload.bundle)
    
    ingested_iocs = 0
    for ind in parsed_bundle.indicators:
        val = ind["value"]
        ioc_type = ind["ioc_type"]
        existing = db.query(ThreatIoC).filter(
            ThreatIoC.value == val,
            ThreatIoC.ioc_type == ioc_type,
        ).first()

        if not existing:
            new_ioc = ThreatIoC(
                ioc_type=ioc_type,
                value=val,
                threat_type=ind["threat_type"],
                confidence=ind["confidence"],
                source="stix_import",
                description=ind.get("description"),
                stix_id=ind.get("stix_id"),
                mitre_attack_id=ind.get("mitre_attack_id"),
                tags=ind.get("tags", []),
                is_active=True,
                sightings_count=1,
            )
            db.add(new_ioc)
            ingested_iocs += 1

    db.commit()

    audit_service.log_action(
        db=db,
        action="STIX_BUNDLE_IMPORTED",
        resource="threat_intel",
        user_id=current_user.id,
        username=current_user.username,
        status="SUCCESS",
        details={"indicators_imported": ingested_iocs, "raw_objects": len(parsed_bundle.raw_objects)},
    )

    return {
        "status": "success",
        "indicators_ingested": ingested_iocs,
        "malware_objects": len(parsed_bundle.malware),
        "attack_patterns": len(parsed_bundle.attack_patterns),
        "relationships": len(parsed_bundle.relationships),
    }


@router.get("/stix/export")
def export_stix_bundle(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_READ)),
):
    """Exports active threat intelligence as a STIX 2.1 JSON Bundle."""
    iocs = db.query(ThreatIoC).filter(ThreatIoC.is_active == True).limit(500).all()
    
    stix_objects = []
    for ioc in iocs:
        stix_id = ioc.stix_id or f"indicator--{uuid.uuid4()}"
        pattern_val = f"[ipv4-addr:value = '{ioc.value}']" if ioc.ioc_type == "ip" else f"[domain-name:value = '{ioc.value}']"
        
        stix_ind = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": stix_id,
            "created": ioc.created_at.isoformat() if ioc.created_at else datetime.utcnow().isoformat(),
            "modified": ioc.created_at.isoformat() if ioc.created_at else datetime.utcnow().isoformat(),
            "name": f"{ioc.threat_type.upper()} Indicator: {ioc.value}",
            "description": ioc.description or f"CyberGuard detected {ioc.threat_type} IoC",
            "indicator_types": [ioc.threat_type],
            "pattern": pattern_val,
            "pattern_type": "stix",
            "confidence": int(ioc.confidence * 100),
            "labels": ioc.tags or [],
        }
        if ioc.mitre_attack_id:
            stix_ind["external_references"] = [
                {"source_name": "mitre-attack", "external_id": ioc.mitre_attack_id}
            ]
        stix_objects.append(stix_ind)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": stix_objects,
    }
    return bundle


# --- Threat Feed Management ---

@router.get("/feeds", response_model=List[ThreatFeedRead])
def list_threat_feeds(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_READ)),
):
    """List all registered threat intelligence feeds."""
    return db.query(ThreatFeed).order_by(ThreatFeed.created_at.desc()).all()


@router.post("/feeds", response_model=ThreatFeedRead, status_code=status.HTTP_201_CREATED)
def create_threat_feed(
    payload: ThreatFeedCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_WRITE)),
):
    """Register a new TAXII 2.1 or STIX threat feed."""
    existing = db.query(ThreatFeed).filter(ThreatFeed.feed_id == payload.feed_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Feed ID '{payload.feed_id}' already exists")

    feed = ThreatFeed(
        feed_id=payload.feed_id,
        name=payload.name,
        feed_type=payload.feed_type,
        url=payload.url,
        api_key=payload.api_key,
        collection_id=payload.collection_id,
        poll_interval_minutes=payload.poll_interval_minutes,
        enabled=payload.enabled,
        confidence_weight=payload.confidence_weight,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    return feed


@router.post("/feeds/{feed_id}/sync")
def sync_threat_feed_endpoint(
    feed_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_WRITE)),
):
    """Triggers on-demand synchronization for a threat feed."""
    feed = db.query(ThreatFeed).filter(ThreatFeed.feed_id == feed_id).first()
    if not feed:
        raise HTTPException(status_code=404, detail=f"Feed '{feed_id}' not found")

    result = feed_scheduler.sync_feed(db=db, feed=feed)
    return result


# --- Historical Correlation & Maintenance ---

@router.post("/correlate-historical")
def correlate_historical_events(
    payload: HistoricalCorrelationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_READ)),
):
    """Retroactively correlates an IoC against historical events in TimescaleDB."""
    mock_ioc = ThreatIoC(
        value=payload.ioc_value,
        ioc_type=payload.ioc_type,
        threat_type="investigation",
    )
    matches = historical_correlator.correlate_ioc(
        db=db,
        ioc=mock_ioc,
        lookback_days=payload.lookback_days,
    )
    return {
        "ioc_value": payload.ioc_value,
        "ioc_type": payload.ioc_type,
        "matched_events_count": len(matches),
        "matches": matches,
    }


@router.post("/prune")
def prune_expired_iocs_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.THREAT_INTEL_WRITE)),
):
    """Prunes or deactivates decayed and expired threat IoCs."""
    pruned = feed_scheduler.prune_expired_iocs(db=db)
    return {"status": "success", "pruned_iocs": pruned}
