from datetime import datetime
from app.schemas.event import SecurityEventCreate, EndpointSchema, ProcessSchema
from app.ml.feature_extraction import feature_extractor
from app.ml.models.isolation_forest import IsolationForestDetector


def test_feature_extraction():
    event = SecurityEventCreate(
        timestamp=datetime.utcnow(),
        source_type="syslog",
        category="authentication",
        action="login_failed",
        severity="high",
        source=EndpointSchema(ip="10.0.0.1", user="admin"),
    )

    features = feature_extractor.extract_features(event)
    assert features["severity_weight"] == 7.0
    assert features["is_auth_category"] == 1.0
    assert features["is_failed_action"] == 1.0
    assert features["is_private_source_ip"] == 1.0


def test_isolation_forest_model_fit_predict():
    events = [
        SecurityEventCreate(
            timestamp=datetime.utcnow(),
            source_type="syslog",
            category="authentication",
            action="login_success" if i % 10 != 0 else "login_failed",
            severity="info" if i % 10 != 0 else "critical",
            source=EndpointSchema(ip="192.168.1.10" if i % 10 != 0 else "203.0.113.5"),
        )
        for i in range(50)
    ]

    df_features = feature_extractor.transform_batch(events)
    detector = IsolationForestDetector(contamination=0.1)
    fit_metrics = detector.fit(df_features)

    assert detector.is_fitted is True
    assert fit_metrics["sample_count"] == 50

    preds, scores = detector.predict(df_features)
    assert len(preds) == 50
    assert len(scores) == 50
