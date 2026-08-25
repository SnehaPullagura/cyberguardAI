# CyberGuard AI

CyberGuard AI is an enterprise-grade, AI-powered cybersecurity monitoring, threat detection, and incident response platform. It normalizes security events across heterogenous infrastructure (Syslog, Windows Event Logs, Web Server Logs, AWS CloudTrail), analyzes them using rule-based detection and machine-learning models, calculates real-time risk scores, correlates related alerts into security incidents, and provides a modern SOC dashboard for security analyst investigation and reporting.

---

## 🌟 Core Architecture & Key Modules

1. **Async Ingestion Pipeline & Redis Queue (Phase 1)**:
   - High-throughput asynchronous event ingestion (`POST /api/v1/events/ingest`) returning HTTP `202 Accepted`.
   - Redis List event queue (`cyberguard:events:queue`) with Dead Letter Queue (`cyberguard:events:dlq`) fallback.
   - Standalone background event worker process (`python -m app.workers.event_worker`) with exponential backoff retries and graceful signal handling (`SIGTERM`/`SIGINT`).
   - Idempotent event deduplication via Redis `SETNX` (24h TTL).

2. **Universal Security & RBAC Engine (Phase 2)**:
   - Centralized Role-Based Access Control (RBAC) with granular permissions (`events:read`, `alerts:update`, `incidents:create`, `rules:write`, `threat_intel:write`, `ml:train`, `reports:export`, `audit:read`, `users:manage`).
   - Standardized system roles: `ADMIN`, `SECURITY_ANALYST`, `VIEWER`.
   - Security Middleware: `CorrelationIdMiddleware` (`X-Correlation-ID`), `SecurityHeadersMiddleware`, rate limiting (`RateLimitationMiddleware`), and global safe exception handling.
   - Immutable security audit logging (`AuditService`) with automatic credential redaction (`[REDACTED]`).

3. **Detection Engines & Threat Intelligence**:
   - **Sigma Rule Engine**: Evaluates structured event conditions against active YAML detection rules.
   - **Threat Intel IoC Matcher**: Matches source/destination entities against active Threat Intelligence feeds (IP, Domain, File Hash, C2 servers).
   - **AI Anomaly Detection Models**: Scikit-Learn Isolation Forest, Neural Autoencoder, and DBSCAN clustering detectors for behavioral anomaly scoring.
   - **Risk Scoring & Incident Correlation**: Aggregates risk scores and groups related alerts into security incidents within configurable time windows.

4. **SOC Analyst Dashboard & Management API**:
   - FastAPI REST API documentation (`/api/v1/docs`).
   - React 18 + TypeScript + Tailwind CSS Frontend SOC Analyst Dashboard.
   - Report export capability (CSV incident summary and executive summary reporting).

---

## 🛠️ Getting Started & Local Setup

### Prerequisites
- Python 3.11 / 3.13
- PostgreSQL 16+
- Redis 7+
- Node.js 18+ & npm

### Quickstart with Docker Compose

To launch the complete platform (PostgreSQL, Redis, FastAPI Backend, Background Worker, React Frontend):

```bash
docker-compose -f docker/docker-compose.yml up --build
```

### Running Backend Locally

```bash
cd backend
python -m venv .venv
# On Windows
.venv\Scripts\activate
# On Linux/macOS
source .venv/bin/activate

pip install -r pyproject.toml
pytest backend/tests
uvicorn app.main:app --reload --port 8000
```

### Running Background Worker Locally

```bash
cd backend
python -m app.workers.event_worker
```

---

## 🧪 Testing & Verification

The project contains a comprehensive automated test suite covering unit, integration, queue/worker, and security/RBAC testing:

```bash
pytest backend/tests
```

---

## 🔒 Security & Compliance

For details on security boundaries, threat modeling, RBAC permission matrices, and security controls, refer to the documentation in `docs/security/`:
- [`docs/security/authentication.md`](docs/security/authentication.md)
- [`docs/security/rbac.md`](docs/security/rbac.md)
- [`docs/security/audit-logging.md`](docs/security/audit-logging.md)
- [`docs/security/api-security.md`](docs/security/api-security.md)
- [`docs/security/threat-model.md`](docs/security/threat-model.md)
