import time
import uuid
import logging
from typing import Dict, Tuple
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from app.config import settings

logger = logging.getLogger(__name__)

# Sliding Window Rate Limit Tracking (In-memory fallback)
_RATE_LIMIT_STORE: Dict[str, Tuple[float, int]] = {}


def reset_rate_limits():
    """Reset rate limiting store between test runs."""
    _RATE_LIMIT_STORE.clear()


import re

SAFE_CORRELATION_ID_REGEX = re.compile(r"^[a-zA-Z0-9\-_]{1,64}$")


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Middleware injecting validated unique X-Correlation-ID into request context and response headers."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        incoming_id = request.headers.get("X-Correlation-ID", "")
        if incoming_id and SAFE_CORRELATION_ID_REGEX.match(incoming_id):
            correlation_id = incoming_id
        else:
            correlation_id = str(uuid.uuid4())

        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing standard HTTP security headers across all responses."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


class RateLimitationMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware for authentication and ingestion endpoints."""

    def __init__(self, app: FastAPI):
        super().__init__(app)
        # Limits: (max_requests, window_seconds)
        self.route_limits = {
            "/api/v1/auth/login": (10, 60),      # 10 req/min for login
            "/api/v1/events/ingest": (100, 60),  # 100 req/min for ingestion
        }

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path
        if path in self.route_limits:
            max_reqs, window_sec = self.route_limits[path]
            client_ip = request.client.host if request.client else "unknown"
            key = f"{client_ip}:{path}"
            now = time.time()

            start_time, count = _RATE_LIMIT_STORE.get(key, (now, 0))
            if now - start_time > window_sec:
                _RATE_LIMIT_STORE[key] = (now, 1)
                current_count = 1
            else:
                if count >= max_reqs:
                    logger.warning(f"Rate limit exceeded for client {client_ip} on route {path}")
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Too many requests. Please try again later."},
                        headers={
                            "Retry-After": str(int(window_sec - (now - start_time))),
                            "X-RateLimit-Limit": str(max_reqs),
                            "X-RateLimit-Remaining": "0"
                        },
                    )
                current_count = count + 1
                _RATE_LIMIT_STORE[key] = (start_time, current_count)

            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(max_reqs)
            response.headers["X-RateLimit-Remaining"] = str(max(0, max_reqs - current_count))
            return response

        return await call_next(request)


def setup_security_exception_handlers(app: FastAPI):
    """Register safe global exception handlers to prevent sensitive stack trace leaks."""

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        logger.error(
            f"Unhandled server exception [CorrelationID: {correlation_id}]: {exc}",
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An unexpected error occurred. Please contact system administrator.",
                "correlation_id": correlation_id,
            },
        )
