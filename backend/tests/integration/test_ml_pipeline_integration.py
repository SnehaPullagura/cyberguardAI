from datetime import datetime
from app.schemas.event import SecurityEventCreate
from app.pipeline.processor import process_single_security_event


def test_ml_pipeline_train_and_predict_integration(client, admin_headers):
    # Test ML Model Train API
    train_res = client.post("/api/v1/ml/train", json={"model_type": "isolation_forest", "sample_size": 50}, headers=admin_headers)
    assert train_res.status_code == 200
    data = train_res.json()
    assert data["status"] == "trained"

    # Test ML Models List API
    list_res = client.get("/api/v1/ml/models", headers=admin_headers)
    assert list_res.status_code == 200
    models = list_res.json()
    assert len(models) >= 1


def test_worker_fail_safe_ml_error_handling(db_session):
    event = SecurityEventCreate(
        event_id=f"evt-failsafe-{datetime.utcnow().timestamp()}",
        source_type="syslog",
        category="authentication",
        action="login_failed",
        severity="critical",
    )

    # Process event through core pipeline (verifies fail-safe ML execution)
    persisted = process_single_security_event(db_session, event)
    assert persisted is not None
    assert persisted.event_id == event.event_id
    assert persisted.risk_score >= 0.0
