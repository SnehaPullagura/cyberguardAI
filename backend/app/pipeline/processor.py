import logging
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.models.rule import DetectionRule
from app.schemas.event import SecurityEventCreate
from app.normalization.normalizer import normalizer
from app.engines.rule_engine import rule_engine
from app.engines.threat_intel_matcher import threat_intel_matcher
from app.engines.risk_engine import risk_scoring_engine
from app.services.alert_service import alert_service
from app.ml.pipeline import ml_pipeline_manager

logger = logging.getLogger(__name__)


def process_single_security_event(
    db: Session, event_data: SecurityEventCreate
) -> SecurityEvent:
    """Process a single SecurityEventCreate through normalization, DB persistence, rule evaluation, IoC matching, ML anomaly detection, alert creation, and incident correlation."""
    # 1. Normalize if raw payload provided
    if event_data.raw_payload:
        normalized_event = normalizer.normalize(
            event_data.raw_payload, event_data.source_type
        )
        if event_data.event_id:
            normalized_event.event_id = event_data.event_id
    else:
        normalized_event = event_data

    # 2. Persist to Event Store
    db_event = SecurityEvent(
        event_id=normalized_event.event_id,
        timestamp=normalized_event.timestamp or datetime.utcnow(),
        source_type=normalized_event.source_type,
        category=normalized_event.category,
        action=normalized_event.action,
        severity=normalized_event.severity,
        observer_host=(
            normalized_event.observer.hostname
            if normalized_event.observer
            else None
        ),
        observer_ip=(
            normalized_event.observer.ip
            if normalized_event.observer
            else None
        ),
        source_ip=(
            normalized_event.source.ip if normalized_event.source else None
        ),
        source_port=(
            normalized_event.source.port if normalized_event.source else None
        ),
        source_user=(
            normalized_event.source.user if normalized_event.source else None
        ),
        destination_ip=(
            normalized_event.destination.ip
            if normalized_event.destination
            else None
        ),
        destination_port=(
            normalized_event.destination.port
            if normalized_event.destination
            else None
        ),
        destination_host=(
            normalized_event.destination.host
            if normalized_event.destination
            else None
        ),
        process_name=(
            normalized_event.process.name
            if normalized_event.process
            else None
        ),
        process_pid=(
            normalized_event.process.pid
            if normalized_event.process
            else None
        ),
        process_command_line=(
            normalized_event.process.command_line
            if normalized_event.process
            else None
        ),
        process_hash=(
            normalized_event.process.hash
            if normalized_event.process
            else None
        ),
        raw_payload=normalized_event.raw_payload,
        normalized_payload=normalized_event.normalized_payload,
    )
    db.add(db_event)
    db.flush()

    # 3. Rule-Based Detection Engine Evaluation
    active_rules = (
        db.query(DetectionRule).filter(DetectionRule.enabled == True).all()
    )
    for rule in active_rules:
        if rule_engine.evaluate_event(normalized_event, rule.condition):
            alert_service.create_alert(
                db=db,
                title=f"Rule Triggered: {rule.title}",
                severity=rule.severity,
                risk_score=(
                    75.0
                    if rule.severity == "high"
                    else 90.0 if rule.severity == "critical" else 40.0
                ),
                detection_source="rule",
                rule_id=rule.id,
                source_entity=(
                    normalized_event.source.ip
                    if normalized_event.source and normalized_event.source.ip
                    else normalized_event.observer.hostname
                    if normalized_event.observer
                    else "unknown"
                ),
                target_entity=(
                    normalized_event.destination.ip
                    if normalized_event.destination
                    else None
                ),
                description=rule.description,
                event_details={
                    "event_id": normalized_event.event_id,
                    "rule_id": rule.rule_id,
                    "action": normalized_event.action,
                },
            )

    # 4. Threat Intelligence Matching
    ioc_matches = threat_intel_matcher.check_event(db, normalized_event)
    for ioc, match_details in ioc_matches:
        alert_service.create_alert(
            db=db,
            title=f"Threat Intelligence IoC Match: {ioc.value}",
            severity="high" if ioc.threat_type in ["C2", "malware"] else "medium",
            risk_score=85.0,
            detection_source="threat_intel",
            ioc_id=ioc.id,
            source_entity=(
                normalized_event.source.ip
                if normalized_event.source
                else None
            ),
            description=f"{match_details} ({ioc.threat_type} from {ioc.source})",
        )

    # 5. AI Anomaly Detection Inference
    is_anomaly, anomaly_score, features = (
        ml_pipeline_manager.predict_event_anomaly(normalized_event)
    )
    if is_anomaly and anomaly_score > 0.7:
        alert_service.create_alert(
            db=db,
            title=f"AI Anomaly Detected (Score: {anomaly_score:.2f})",
            severity="high" if anomaly_score > 0.85 else "medium",
            risk_score=anomaly_score * 100.0,
            detection_source="ml_anomaly",
            source_entity=(
                normalized_event.source.ip
                if normalized_event.source
                else "unknown"
            ),
            description=f"Behavioral anomaly score {anomaly_score:.2f} calculated by AI models.",
            event_details={
                "event_id": normalized_event.event_id,
                "features": features,
            },
        )

    db.commit()
    db.refresh(db_event)
    return db_event
