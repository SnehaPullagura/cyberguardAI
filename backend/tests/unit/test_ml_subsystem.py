import os
import pytest
from datetime import datetime
from app.schemas.event import SecurityEventCreate
from app.ml.features.extractor import feature_extractor
from app.ml.features.validator import feature_validator
from app.ml.models.isolation_forest import IsolationForestDetector
from app.ml.models.autoencoder import NeuralAutoencoderDetector
from app.ml.models.dbscan import DBSCANDetector
from app.ml.inference.ensemble import EnsembleInferencePipeline


def create_sample_event(severity="high", category="authentication", action="login_failed"):
    return SecurityEventCreate(
        event_id=f"test-evt-{datetime.utcnow().timestamp()}",
        timestamp=datetime.utcnow(),
        source_type="syslog",
        category=category,
        action=action,
        severity=severity,
    )


def test_feature_extraction_and_validation():
    event = create_sample_event()
    features = feature_extractor.extract_features(event)
    assert "severity_weight" in features
    assert "hour_sin" in features
    assert "hour_cos" in features
    assert features["severity_weight"] == 7.0

    df_batch = feature_extractor.transform_batch([event])
    assert len(df_batch) == 1
    assert not df_batch.isnull().values.any()


def test_isolation_forest_detector(tmp_path):
    events = [create_sample_event() for _ in range(20)]
    df = feature_extractor.transform_batch(events)

    detector = IsolationForestDetector()
    metrics = detector.fit(df)
    assert detector.is_fitted is True
    assert "sample_count" in metrics

    preds, scores = detector.predict(df)
    assert len(preds) == 20
    assert len(scores) == 20
    assert 0.0 <= scores[0] <= 1.0

    # Serialization test
    save_path = os.path.join(tmp_path, "if_model.joblib")
    detector.save(save_path)
    loaded_detector = IsolationForestDetector()
    loaded_detector.load(save_path)
    assert loaded_detector.is_fitted is True


def test_autoencoder_detector(tmp_path):
    events = [create_sample_event() for _ in range(20)]
    df = feature_extractor.transform_batch(events)

    detector = NeuralAutoencoderDetector(epochs=2, batch_size=4)
    metrics = detector.fit(df)
    assert detector.is_fitted is True

    preds, scores = detector.predict(df)
    assert len(preds) == 20
    assert len(scores) == 20

    # Serialization test
    save_path = os.path.join(tmp_path, "ae_model.joblib")
    detector.save(save_path)
    loaded_detector = NeuralAutoencoderDetector()
    loaded_detector.load(save_path)
    assert loaded_detector.is_fitted is True


def test_dbscan_out_of_sample_inference(tmp_path):
    events = [create_sample_event() for _ in range(20)]
    df = feature_extractor.transform_batch(events)

    detector = DBSCANDetector(eps=1.5, min_samples=2)
    metrics = detector.fit(df)
    assert detector.is_fitted is True

    preds, scores = detector.predict(df)
    assert len(preds) == 20
    assert len(scores) == 20

    # Serialization test
    save_path = os.path.join(tmp_path, "dbscan_model.joblib")
    detector.save(save_path)
    loaded_detector = DBSCANDetector()
    loaded_detector.load(save_path)
    assert loaded_detector.is_fitted is True


def test_ensemble_pipeline():
    events = [create_sample_event() for _ in range(10)]
    df = feature_extractor.transform_batch(events)

    if_model = IsolationForestDetector()
    if_model.fit(df)

    ensemble = EnsembleInferencePipeline(if_model=if_model)
    result = ensemble.predict(events[0])
    assert result.event_id == events[0].event_id
    assert 0.0 <= result.ensemble_anomaly_score <= 1.0
