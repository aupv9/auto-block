# autoblock (Python / FastAPI)

Starlette/FastAPI middleware for [AutoBlock](../../) adaptive rate limiting. Works with FastAPI, Starlette, and any ASGI framework.

## Installation

```bash
pip install autoblock
# or with hiredis for faster Redis parsing:
pip install "autoblock[hiredis]"
```

## Quick Start

```python
import redis.asyncio as aioredis
from fastapi import FastAPI
from autoblock import AutoBlockMiddleware, AutoBlockConfig, RuleConfig, LimitsConfig, PenaltyConfig, PenaltyStepConfig

app = FastAPI()
redis = aioredis.from_url("redis://localhost:6379")

app.add_middleware(
    AutoBlockMiddleware,
    redis=redis,
    config=AutoBlockConfig(
        tenant="my-api",
        rules=[
            RuleConfig(
                id="login-limit",
                endpoint_pattern=r"^/api/auth/login$",
                dimensions=["ip"],
                algorithm="hybrid",
                methods=["POST"],
                limits=LimitsConfig(requests=10, window_seconds=60, burst=15),
                penalties=PenaltyConfig(
                    warn=PenaltyStepConfig(score_threshold=3),
                    slow=PenaltyStepConfig(score_threshold=6, delay_ms=2000),
                    block=PenaltyStepConfig(score_threshold=10, duration_seconds=300),
                    blacklist=PenaltyStepConfig(score_threshold=15),
                ),
            ),
        ],
    ),
)

@app.post("/api/auth/login")
async def login():
    return {"token": "example"}
```

## Configuration Reference

### `AutoBlockConfig`

| Field        | Type              | Required | Description                                     |
|--------------|-------------------|----------|-------------------------------------------------|
| `tenant`     | `str`             | Yes      | Namespaces all Redis keys.                      |
| `rules`      | `list[RuleConfig]`| Yes      | Rate-limit rules evaluated in order.            |
| `middleware` | `MiddlewareConfig`| No       | Proxy trust, user ID extraction, skip paths.    |

### `RuleConfig`

| Field              | Type                                         | Default     | Description                               |
|--------------------|----------------------------------------------|-------------|-------------------------------------------|
| `id`               | `str`                                        | —           | Unique rule identifier.                   |
| `enabled`          | `bool`                                       | `True`      | Disable without removing.                 |
| `dimensions`       | `list[str]`                                  | `["ip"]`    | `"ip"`, `"user_id"`, or `"endpoint"`.    |
| `endpoint_pattern` | `str` (regex)                                | —           | Regex matched against the request path.   |
| `methods`          | `list[str]`                                  | `["*"]`     | HTTP methods. `*` matches all.            |
| `algorithm`        | `"sliding_window" \| "token_bucket" \| "hybrid"` | `"hybrid"` | Algorithm selection.               |
| `limits`           | `LimitsConfig`                               | —           | `requests`, `window_seconds`, `burst`.    |
| `penalties`        | `PenaltyConfig`                              | —           | Per-state penalty thresholds.             |

### `MiddlewareConfig`

| Field                | Default       | Description                                              |
|----------------------|---------------|----------------------------------------------------------|
| `fail_open`          | `True`        | Allow requests when Redis is unavailable.                |
| `skip_paths`         | `[]`          | Path prefixes exempt from rate limiting.                 |
| `trust_proxy`        | `False`       | Trust `X-Forwarded-For`.                                 |
| `trusted_proxy_depth`| `1`           | Number of trusted proxy hops.                            |
| `ip_header`          | `x-forwarded-for` | Header for client IP.                               |
| `user_id_extractor`  | `None`        | `"jwt_sub"` or `"header"` for per-user limiting.        |
| `user_id_header`     | `None`        | Header name when `user_id_extractor = "header"`.        |

## User ID Extraction

### JWT sub (no verification)

```python
from autoblock import MiddlewareConfig

AutoBlockConfig(
    tenant="my-api",
    rules=[...],
    middleware=MiddlewareConfig(user_id_extractor="jwt_sub"),
)
```

### Custom header

```python
MiddlewareConfig(user_id_extractor="header", user_id_header="x-user-id")
```

## Hot-Reload Rules

```python
from autoblock import RulesWatcher

async with RulesWatcher(redis, limiter, interval_seconds=30):
    await serve(app)
```

Or manually:

```python
watcher = RulesWatcher(redis, limiter, interval_seconds=30,
                        on_reload=lambda rules: print(f"Loaded {len(rules)} rules"))
await watcher.start()
# ...
await watcher.stop()
```

## Score Decay

Without the AutoBlock engine, run a `DecayWorker` so IPs cool down:

```python
from autoblock import DecayWorker

async with DecayWorker(redis, tenant="my-api",
                        half_life_ms=10 * 60 * 1000,    # halves every 10 min
                        interval_seconds=60):
    await serve(app)
```

## Response Headers

| Header                | Description                          |
|-----------------------|--------------------------------------|
| `RateLimit-Limit`     | Configured limit for matched rule    |
| `RateLimit-Remaining` | Remaining requests (IETF draft)      |
| `RateLimit-Reset`     | Seconds until window resets          |
| `X-RateLimit-State`   | `CLEAN`, `WARN`, `SLOW`, `BLOCK`, `BLACKLIST` |

On denial:

```json
{ "error": "Too Many Requests", "state": "BLOCK", "retry_after": 60 }
```

## Lifespan Integration (FastAPI)

```python
from contextlib import asynccontextmanager
from autoblock import DecayWorker, RulesWatcher

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with (
        DecayWorker(redis, "my-api", interval_seconds=60),
        RulesWatcher(redis, limiter, interval_seconds=30),
    ):
        yield

app = FastAPI(lifespan=lifespan)
```

## Requirements

- Python 3.11+
- `redis-py` 5.0+ with `asyncio` support
- Redis 7+
