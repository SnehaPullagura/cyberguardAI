import time
from datetime import datetime
from app.schemas.event import SecurityEventCreate
from app.ml.features.extractor import feature_extractor
from app.ml.models.isolation_forest import IsolationForestDetector
from app.ml.models.autoencoder import NeuralAutoencoderDetector
from app.ml.models.dbscan import DBSCANDetector
from app.ml.inference.ensemble import EnsembleInferencePipeline


def test_ml_performance_benchmarks():
    """Benchmark feature extraction, Isolation Forest, Autoencoder, DBSCAN, and Ensemble inference latency."""
    events = [
        SecurityEventCreate(
            event_id=f"bm-{i}",
            timestamp=datetime.utcnow(),
            source_type="syslog",
            category="authentication",
            action="login_failed",
            severity="high",
        )
        for i in range(100)
    ]

    # 1. Feature Extraction Latency
    start = time.time()
    df_features = feature_extractor.transform_batch(events)
    feat_latency = (time.time() - start) * 1000.0

    # 2. Isolation Forest Latency
    if_model = IsolationForestDetector()
    if_model.fit(df_features)
    start = time.time()
    if_model.predict(df_features)
    if_latency = (time.time() - start) * 1000.0

    # 3. Autoencoder Latency
    ae_model = NeuralAutoencoderDetector(epochs=2)
    ae_model.fit(df_features)
    start = time.time()
    ae_model.predict(df_features)
    ae_latency = (time.time() - start) * 1000.0

    # 4. DBSCAN Out-of-Sample Latency
    dbscan_model = DBSCANDetector()
    dbscan_model.fit(df_features)
    start = time.time()
    dbscan_model.predict(df_features)
    dbscan_latency = (time.time() - start) * 1000.0

    # 5. Ensemble Latency
    ensemble = EnsembleInferencePipeline(if_model=if_model, ae_model=ae_model, dbscan_model=dbscan_model)
    start = time.time()
    for ev in events[:10]:
        ensemble.predict(ev)
    ensemble_latency = (time.time() - start) * 1000.0

    print(
        f"\n[ML BENCHMARK 100 Events] FeatureExt={feat_latency:.2f}ms | IsolationForest={if_latency:.2f}ms | Autoencoder={ae_latency:.2f}ms | DBSCAN={dbscan_latency:.2f}ms | Ensemble(10x)={ensemble_latency:.2f}ms"
    )
