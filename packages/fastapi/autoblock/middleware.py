"""Starlette middleware — works with FastAPI and bare Starlette apps."""
from __future__ import annotations

import asyncio
import base64
import json

import redis.asyncio as aioredis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from .rate_limiter import RateLimiter
from .types import AutoBlockConfig, RequestContext


class AutoBlockMiddleware(BaseHTTPMiddleware):
    """Drop-in Starlette/FastAPI middleware.

    Usage::

        app.add_middleware(
            AutoBlockMiddleware,
            redis=aioredis.from_url("redis://localhost:6379"),
            config=AutoBlockConfig(tenant="acme", rules=[...]),
        )
    """

    def __init__(self, app: ASGIApp, *, redis: aioredis.Redis, config: AutoBlockConfig) -> None:
        super().__init__(app)
        self.limiter = RateLimiter(redis, config)
        self._config = config

    async def dispatch(self, request: Request, call_next) -> Response:
        ip = self._extract_ip(request)
        user_id = self._extract_user_id(request)

        ctx = RequestContext(
            ip=ip,
            user_id=user_id,
            endpoint=request.url.path,
            method=request.method,
        )

        decision = await self.limiter.check(ctx)

        # Build IETF + legacy rate-limit headers
        has_limit = decision.limit != float("inf")
        rl_headers: dict[str, str] = {}
        if has_limit:
            limit     = str(int(decision.limit))
            remaining = str(max(0, int(decision.remaining)))
            reset     = str(decision.retry_after_seconds or 60)
            # IETF draft-ietf-httpapi-ratelimit-headers
            rl_headers["RateLimit-Limit"]     = limit
            rl_headers["RateLimit-Remaining"] = remaining
            rl_headers["RateLimit-Reset"]     = reset
            # Legacy X- prefix for backward compatibility
            rl_headers["X-RateLimit-Limit"]     = limit
            rl_headers["X-RateLimit-Remaining"] = remaining
            rl_headers["X-RateLimit-State"]     = decision.state

        if not decision.allowed:
            deny_headers: dict[str, str] = dict(rl_headers)
            if decision.retry_after_seconds is not None:
                deny_headers["Retry-After"] = str(decision.retry_after_seconds)
            return JSONResponse(
                content={
                    "error": "Forbidden" if decision.status_code == 403 else "Too Many Requests",
                    "state": decision.state,
                    "retry_after": decision.retry_after_seconds,
                },
                status_code=decision.status_code or 429,
                headers=deny_headers,
            )

        if decision.delay_ms and decision.delay_ms > 0:
            await asyncio.sleep(decision.delay_ms / 1000)

        response = await call_next(request)

        for name, value in rl_headers.items():
            response.headers[name] = value

        return response

    def _extract_ip(self, request: Request) -> str:
        mw = self._config.middleware
        if mw.trust_proxy:
            xff = request.headers.get(mw.ip_header or "x-forwarded-for", "")
            if xff:
                ips = [ip.strip() for ip in xff.split(",")]
                depth = mw.trusted_proxy_depth
                idx = max(0, len(ips) - depth)
                ip = ips[idx] if idx < len(ips) else ips[0]
                return ip.replace("::ffff:", "")

            x_real = request.headers.get("x-real-ip", "")
            if x_real:
                return x_real.strip()

        client = request.client
        return client.host if client else "127.0.0.1"

    def _extract_user_id(self, request: Request) -> str | None:
        mw = self._config.middleware

        if mw.user_id_extractor == "jwt_sub":
            return _jwt_sub(request.headers.get("authorization", ""))

        if mw.user_id_extractor == "header" and mw.user_id_header:
            return request.headers.get(mw.user_id_header.lower())

        return None


def _jwt_sub(authorization: str) -> str | None:
    """Decode JWT payload without verification — only for rate limiting, not auth."""
    if not authorization.startswith("Bearer "):
        return None
    token = authorization[7:]
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        # Add padding for base64url decoding
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return payload.get("sub")
    except Exception:
        return None
