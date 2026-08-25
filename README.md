# CyberGuard AI

CyberGuard AI is an enterprise-grade AI-powered cybersecurity monitoring, threat detection, and response platform.

## Architecture & Features

- **Asynchronous Queue Ingestion**: High-throughput non-blocking log ingestion powered by Redis Queue, Dead Letter Queue (DLQ), exponential backoff retries, and worker background architecture.
- **Normalized Event Engine**: Normalizes Syslog, Windows Event Logs, Web Server Logs (Nginx/Apache), and AWS CloudTrail logs into ECS-aligned security events.
- **Rule Detection Engine**: Real-time evaluation of Sigma-like detection rules matching behavioral patterns and suspicious activity.
- **Threat Intelligence Matching**: Instant IP, Domain, and File Hash IoC matching against threat feeds.
- **AI Anomaly Detection Pipeline**: Multi-model behavioral anomaly detection leveraging Isolation Forests, PyTorch Neural Autoencoders, and DBSCAN clustering.
- **Risk Scoring & Incident Correlation**: Real-time risk scoring and alert clustering into correlated security incidents.
- **Security Hardening & Centralized RBAC**: Universal backend authorization using FastAPI permission dependencies across ADMIN, SECURITY_ANALYST, and VIEWER roles.
- **Security Audit Logging**: Immutable security audit trail with automatic credential redaction (`[REDACTED]`).
- **Security Middleware**: Correlation ID tracking (`X-Correlation-ID`), security HTTP headers, rate limiting, and generic safe exception handling.

## Directory Structure

```
CyberGuardAI/
├── backend/
│   ├── app/
│   │   ├── api/v1/         # API controllers & router endpoints
│   │   ├── engines/        # Rule, Threat Intel, Risk, Correlation engines
│   │   ├── middleware/     # Correlation ID, Security Headers, Rate Limiters
│   │   ├── ml/             # Isolation Forest, Autoencoder, DBSCAN models
│   │   ├── models/         # SQLAlchemy ORM database models
│   │   ├── normalization/  # Event parsers & GeoIP enrichers
│   │   ├── pipeline/       # Core event processing pipeline
│   │   ├── queue/          # Redis Queue manager & DLQ routing
│   │   ├── schemas/        # Pydantic v2 schemas
│   │   ├── security/       # Auth JWT, Bcrypt, and Centralized RBAC
│   │   ├── services/       # Alert & Audit services
│   │   └── workers/        # Standalone Redis queue event worker
│   └── tests/              # Unit, Integration, and Security test suites
├── frontend/               # React + TypeScript + Tailwind CSS UI
├── docker/                 # Docker Compose & Dockerfile specifications
├── docs/security/          # Comprehensive security architecture & threat model docs
└── rules_repo/             # Detection rules repository
```
