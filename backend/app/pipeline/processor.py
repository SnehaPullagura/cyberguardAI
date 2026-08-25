import logging
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.models.rule import DetectionRule
from app.schemas.event import SecurityEventCreate
from app.schemas.websocket import RealtimeEventEnvelope
from app.normalization.normalizer import normalizer
from app.engines.rule_engine import rule_engine
from app.engines.threat_intel_matcher import threat_intel_matcher
from app.engines.risk_engine import risk_scoring_engine
from app.services.alert_service import alert_service
from app.ml.pipeline import ml_pipeline_manager
from app.repositories.event_repository import event_repository
from app.websockets.pubsub import publish_realtime_event
from app.response.executor import playbook_executor

logger = logging.getLogger(__name__)


def process_single_security_event(
    db: Session, event_data: SecurityEventCreate
) -> SecurityEvent:
    """Process a single SecurityEventCreate through normalization, EventRepository persistence, rule evaluation, IoC matching, ML anomaly detection, alert creation, incident correlation, real-time WebSockets, and Playbook Response Execution."""
    # 1. Normalize if raw payload provided
    if event_data.raw_payload:
        normalized_event = normalizer.normalize(
            event_data.raw_payload, event_data.source_type
        )
        if event_data.event_id:
            normalized_event.event_id = event_data.event_id
    else:
        normalized_event = event_data

    # 2. Compute AI Anomaly Detection Inference (Fail-safe)
    is_anomaly, anomaly_score, features, ml_result = (
        ml_pipeline_manager.predict_event_anomaly(normalized_event)
    )

    # Calculate initial event risk score using RiskScoringEngine
    calculated_risk = risk_scoring_engine.calculate_event_risk_score(
        severity=normalized_event.severity,
        ml_result=ml_result,
    )

    # 3. Create SecurityEvent model object
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
        risk_score=calculated_risk,
        anomaly_score=anomaly_score,
        raw_payload=normalized_event.raw_payload,
        normalized_payload=normalized_event.normalized_payload,
    )

    # 4. Save to Event Storage Layer (TimescaleDB / Partitioned EventRepository)
    persisted_event, is_new = event_repository.save_event(db, db_event)
    if not is_new:
        return persisted_event

    # Publish real-time event envelope to Redis Pub/Sub after persistence
    publish_realtime_event(
        RealtimeEventEnvelope(
            type="security_event",
            data={
                "id": persisted_event.id,
                "event_id": persisted_event.event_id,
                "timestamp": persisted_event.timestamp.isoformat(),
                "source_type": persisted_event.source_type,
                "category": persisted_event.category,
                "action": persisted_event.action,
                "severity": persisted_event.severity,
                "source_ip": persisted_event.source_ip,
                "risk_score": persisted_event.risk_score,
                "anomaly_score": persisted_event.anomaly_score,
            },
        )
    )

    generated_alerts = []

    # 5. Rule-Based Detection Engine Evaluation
    active_rules = (
        db.query(DetectionRule).filter(DetectionRule.enabled == True).all()
    )
    for rule in active_rules:
        if rule_engine.evaluate_event(normalized_event, rule.condition):
            alert = alert_service.create_alert(
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
            generated_alerts.append(alert)
            publish_realtime_event(
                RealtimeEventEnvelope(
                    type="alert_created",
                    data={
                        "id": alert.id,
                        "title": alert.title,
                        "severity": alert.severity,
                        "risk_score": alert.risk_score,
                        "source_entity": alert.source_entity,
                    },
                )
            )

    # 6. Threat Intelligence Matching
    ioc_matches = threat_intel_matcher.check_event(db, normalized_event)
    for ioc, match_details in ioc_matches:
        alert = alert_service.create_alert(
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
        generated_alerts.append(alert)
        publish_realtime_event(
            RealtimeEventEnvelope(
                type="alert_created",
                data={
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "source_entity": alert.source_entity,
                },
            )
        )

    # 7. AI Anomaly Detection Alert Creation
    if is_anomaly and anomaly_score > 0.7:
        alert = alert_service.create_alert(
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
                "ml_details": ml_result.dict() if ml_result else {},
            },
        )
        generated_alerts.append(alert)
        publish_realtime_event(
            RealtimeEventEnvelope(
                type="alert_created",
                data={
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "source_entity": alert.source_entity,
                },
            )
        )

    # 8. Trigger Automated Playbook & Response Engine
    for alert in generated_alerts:
        response_context = {
            "alert_id": alert.id,
            "event_id": normalized_event.event_id,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "source_entity": alert.source_entity,
            "action": normalized_event.action,
            "category": normalized_event.category,
        }
        playbook_executor.evaluate_and_execute_playbooks(db, response_context)

    db.commit()
    db.refresh(persisted_event)
    return persisted_event
