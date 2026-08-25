# API Security & Hardening Controls

## Middleware & Headers
- **Correlation ID (`X-Correlation-ID`)**: Injected into every request state and returned in response headers for request tracing.
- **Security Headers**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- **Rate Limiting**: Sliding window rate limiting enforced on `/api/v1/auth/login` (10 req/min) and `/api/v1/events/ingest` (100 req/min). Returns HTTP `429 Too Many Requests`.
- **Global Exception Sanitization**: Unhandled server exceptions are caught by global exception handlers, logged internally with Correlation ID, and sanitized into safe HTTP 500 error envelopes without exposing internal stack traces or database errors.

## Input Validation & Data Handling
- Pydantic v2 schemas strictly validate request payloads.
- Pagination bounds (`skip >= 0`, `limit <= 500`) prevent memory exhaustion via high limit parameter tampering.
