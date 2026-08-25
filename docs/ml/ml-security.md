# ML Security & Access Controls

- **RBAC Enforcement**: Model training (`POST /api/v1/ml/train`) requires `ML_TRAIN` permission (`ADMIN` or authorized role). Model listing (`GET /api/v1/ml/models`) requires `ML_READ` permission.
- **Fail-Safe Worker Boundary**: ML inference errors during background worker execution are caught gracefully, logging warnings without crashing the worker process or losing security log events.
