from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.alert import Alert
from app.ml.inference.result import MLInferenceResult


class RiskScoringEngine:
    """Calculates risk scores for security events and entities based on severity, detection rules, and ML ensemble inference results."""

    SEVERITY_WEIGHTS = {
        "critical": 40.0,
        "high": 25.0,
        "medium": 10.0,
        "low": 5.0,
        "info": 1.0,
    }

    def calculate_event_risk_score(
        self,
        severity: str,
        rule_score: float = 0.0,
        ml_result: Optional[MLInferenceResult] = None,
    ) -> float:
        """Calculate dynamic event risk score (0 to 100) combining severity weight, rule detection score, and ML ensemble anomaly score."""
        base_score = 0.0
        sev = severity.lower() if severity else "info"
        if sev == "critical":
            base_score = 90.0
        elif sev == "high":
            base_score = 75.0
        elif sev == "medium":
            base_score = 50.0
        elif sev == "low":
            base_score = 25.0

        ml_score = (ml_result.ensemble_anomaly_score * 100.0) if ml_result else 0.0

        raw_score = max(base_score, rule_score, ml_score)
        return min(100.0, round(raw_score, 1))

    def calculate_entity_risk(self, db: Session, entity_name: str) -> float:
        """Calculate dynamic risk score (0 to 100) for a given entity."""
        alerts = (
            db.query(Alert)
            .filter(
                (Alert.source_entity == entity_name)
                | (Alert.target_entity == entity_name),
                Alert.status.in_(["open", "in_review", "new", "investigating"]),
            )
            .all()
        )

        if not alerts:
            return 0.0

        raw_score = 0.0
        for alert in alerts:
            weight = self.SEVERITY_WEIGHTS.get(alert.severity.lower(), 5.0)
            raw_score += weight * (1.0 + (alert.risk_score / 100.0))

        final_score = min(100.0, round(raw_score, 1))
        return final_score

    def get_top_high_risk_entities(
        self, db: Session, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get ranking of highest risk entities across the network."""
        entities = (
            db.query(Alert.source_entity, func.count(Alert.id).label("alert_count"))
            .filter(Alert.source_entity.isnot(None), Alert.status.in_(["open", "in_review", "new", "investigating"]))
            .group_by(Alert.source_entity)
            .order_by(func.count(Alert.id).desc())
            .limit(limit)
            .all()
        )

        result = []
        for entity_name, count in entities:
            score = self.calculate_entity_risk(db, entity_name)
            result.append(
                {
                    "entity_name": entity_name,
                    "entity_type": "IP_or_Host",
                    "risk_score": score,
                    "alert_count": count,
                }
            )

        result.sort(key=lambda x: x["risk_score"], reverse=True)
        return result


risk_scoring_engine = RiskScoringEngine()
