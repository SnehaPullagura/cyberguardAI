# Machine Learning Subsystem Architecture

## Overview
CyberGuard AI implements a modular, production-grade unsupervised anomaly detection subsystem for real-time security log events.

## Components
```
features/   ---> Feature extraction, validation, schema versioning (v1.0)
models/     ---> Isolation Forest, PyTorch Autoencoder, DBSCAN Cluster Profiler
inference/  ---> Multi-model Ensemble Pipeline (MLInferenceResult)
registry/   ---> Model catalog & version tracking in database
artifacts/  ---> Safe artifact serialization and file path storage
```
