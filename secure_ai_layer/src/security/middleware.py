from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.config.config_loader import get_policy_config


def apply_security_headers(response: Response) -> Response:
    """Keep security headers consistent across success and short-circuit responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "connect-src 'self' ws: wss: http: https:; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds baseline browser-facing security headers for API responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        return apply_security_headers(response)


class PayloadSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects oversized request bodies before they reach the application."""

    async def dispatch(self, request: Request, call_next):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return await call_next(request)

        config = get_policy_config()
        security_config = config.get("security", {})
        max_body_bytes = int(security_config.get("max_body_bytes", 65536))
        exempt_paths = set(security_config.get("exempt_paths", []))

        if max_body_bytes <= 0 or request.url.path in exempt_paths:
            return await call_next(request)

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = 0

            if declared_size > max_body_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "message": "Request body exceeded the configured Secure AI Interaction Layer limit.",
                        "max_body_bytes": max_body_bytes,
                    },
                )
                return apply_security_headers(response)

        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory sliding window rate limiter for hackathon deployments."""

    def __init__(self, app):
        super().__init__(app)
        self._requests: Dict[str, Deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        config = get_policy_config()
        rate_limit_config = config.get("rate_limit", {})

        if request.method == "OPTIONS":
            return await call_next(request)
        if not rate_limit_config.get("enabled", True):
            return await call_next(request)

        exempt_paths = set(rate_limit_config.get("exempt_paths", []))
        if request.url.path in exempt_paths:
            return await call_next(request)

        window_seconds = int(rate_limit_config.get("window_seconds", 60))
        requests_per_window = int(rate_limit_config.get("requests_per_window", 120))
        client_identifier = self._client_identifier(request)
        now = time.time()

        recent_requests = self._requests[client_identifier]
        while recent_requests and now - recent_requests[0] > window_seconds:
            recent_requests.popleft()

        if len(recent_requests) >= requests_per_window:
            retry_after = max(1, int(window_seconds - (now - recent_requests[0])))
            response = JSONResponse(
                status_code=429,
                content={
                    "message": "Rate limit exceeded by Secure AI Interaction Layer.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )
            return apply_security_headers(response)

        recent_requests.append(now)
        return await call_next(request)

    def _client_identifier(self, request: Request) -> str:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "anonymous"
