import pytest
import redis.asyncio as aioredis
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from autoblock import (
    AutoBlockConfig,
    AutoBlockMiddleware,
    LimitsConfig,
    PenaltyConfig,
    PenaltyStepConfig,
    RuleConfig,
)


def make_config(requests: int = 3) -> AutoBlockConfig:
    return AutoBlockConfig(
        tenant="test",
        rules=[
            RuleConfig(
                id="test-rule",
                endpoint_pattern=r"^/api/login$",
                dimensions=["ip"],
                algorithm="sliding_window",
                methods=["POST"],
                limits=LimitsConfig(requests=requests, window_seconds=60),
                penalties=PenaltyConfig(
                    warn=PenaltyStepConfig(score_threshold=1),
                    slow=PenaltyStepConfig(score_threshold=2, delay_ms=100),
                    block=PenaltyStepConfig(score_threshold=3, duration_seconds=60),
                    blacklist=PenaltyStepConfig(score_threshold=5),
                ),
            )
        ],
    )


async def make_app(redis_client, config=None) -> tuple[FastAPI, AsyncClient]:
    app = FastAPI()
    app.add_middleware(AutoBlockMiddleware, redis=redis_client, config=config or make_config())

    @app.post("/api/login")
    async def login():
        return {"status": "ok"}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    return app, client


async def test_allows_requests_under_limit(redis_client):
    _, client = await make_app(redis_client)
    async with client:
        headers = {"X-Forwarded-For": "10.1.0.1"}
        resp = await client.post("/api/login", headers=headers)
        assert resp.status_code == 200


async def test_skips_health_path(redis_client):
    _, client = await make_app(redis_client)
    async with client:
        # Exhaust limit on /api/login does not affect /health
        for _ in range(10):
            await client.post("/api/login", headers={"X-Forwarded-For": "10.1.1.1"})
        resp = await client.get("/health")
        assert resp.status_code == 200


async def test_blocks_after_limit(redis_client):
    _, client = await make_app(redis_client)
    async with client:
        ip_headers = {"X-Forwarded-For": "10.2.0.1"}
        # Exhaust rate limit (3 requests)
        for _ in range(3):
            await client.post("/api/login", headers=ip_headers)

        # Next request triggers penalty and gets blocked
        blocked = await client.post("/api/login", headers=ip_headers)
        assert blocked.status_code in (429, 403)


async def test_ratelimit_headers_set(redis_client):
    _, client = await make_app(redis_client, make_config(requests=10))
    async with client:
        resp = await client.post("/api/login", headers={"X-Forwarded-For": "10.3.0.1"})
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers
        assert "X-RateLimit-State" in resp.headers


async def test_whitelist_bypasses_limit(redis_client):
    app, client = await make_app(redis_client)
    middleware = next(m for m in app.middleware_stack.__dict__.get("app", app).__dict__.values()
                      if isinstance(m, AutoBlockMiddleware) if hasattr(m, "limiter"))
    # Fallback: access via app state — just test directly via limiter
    _, client = await make_app(redis_client, make_config(requests=1))

    from autoblock import RateLimiter
    cfg = make_config(requests=1)
    limiter = RateLimiter(redis_client, cfg)
    ip = "192.168.100.1"
    await limiter.add_to_whitelist(ip)

    # Even with limit=1, whitelisted IP is always allowed
    from autoblock import RequestContext
    for _ in range(5):
        d = await limiter.check(RequestContext(ip=ip, endpoint="/api/login", method="POST"))
        assert d.allowed
        assert d.limit == float("inf")
