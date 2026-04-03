"""Integration tests for RulesWatcher."""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from autoblock import AutoBlockConfig, LimitsConfig, PenaltyConfig, RuleConfig
from autoblock.rate_limiter import RateLimiter
from autoblock.rules_watcher import RulesWatcher


def make_config() -> AutoBlockConfig:
    return AutoBlockConfig(
        tenant="watcher-test",
        rules=[
            RuleConfig(
                id="static-rule",
                endpoint_pattern=r"^/static$",
                dimensions=["ip"],
                algorithm="sliding_window",
                methods=["GET"],
                limits=LimitsConfig(requests=100, window_seconds=60),
                penalties=PenaltyConfig(),
            )
        ],
    )


async def test_poll_empty_hash(redis_client):
    """Empty Redis hash → empty dynamic rules, no error."""
    await redis_client.flushdb()
    config = make_config()
    limiter = RateLimiter(redis_client, config)
    watcher = RulesWatcher(redis_client, limiter)

    rules = await watcher.poll()
    assert rules == []


async def test_poll_loads_single_rule(redis_client):
    """A valid JSON entry in the rules hash is parsed into a RuleConfig."""
    await redis_client.flushdb()
    config = make_config()
    limiter = RateLimiter(redis_client, config)

    rules_key = "ab:watcher-test:rules:endpoint"
    rule_json = json.dumps({
        "id": "login-limit",
        "path": "/api/auth/login",
        "limit": 5,
        "window_seconds": 60,
        "algorithm": "hybrid",
        "enabled": True,
    })
    await redis_client.hset(rules_key, "login-limit", rule_json)

    watcher = RulesWatcher(redis_client, limiter)
    rules = await watcher.poll()

    assert len(rules) == 1
    assert rules[0].id == "login-limit"
    assert rules[0].limits.requests == 5
    assert rules[0].algorithm == "hybrid"


async def test_poll_skips_disabled_rules(redis_client):
    """Rules with enabled=false are excluded."""
    await redis_client.flushdb()
    config = make_config()
    limiter = RateLimiter(redis_client, config)

    rules_key = "ab:watcher-test:rules:endpoint"
    await redis_client.hset(rules_key,
        "active", json.dumps({"id": "active", "path": "/on", "limit": 10, "window_seconds": 60, "enabled": True}),
        "disabled", json.dumps({"id": "disabled", "path": "/off", "limit": 10, "window_seconds": 60, "enabled": False}),
    )

    watcher = RulesWatcher(redis_client, limiter)
    rules = await watcher.poll()

    assert len(rules) == 1
    assert rules[0].id == "active"


async def test_poll_skips_malformed_json(redis_client):
    """Malformed JSON entries are silently skipped."""
    await redis_client.flushdb()
    config = make_config()
    limiter = RateLimiter(redis_client, config)

    rules_key = "ab:watcher-test:rules:endpoint"
    await redis_client.hset(rules_key,
        "good", json.dumps({"id": "good", "path": "/good", "limit": 5, "window_seconds": 60, "enabled": True}),
        "bad", "{not-valid-json",
    )

    watcher = RulesWatcher(redis_client, limiter)
    rules = await watcher.poll()

    assert len(rules) == 1
    assert rules[0].id == "good"


async def test_poll_calls_on_reload_callback(redis_client):
    """on_reload callback is invoked with the parsed rules after each poll."""
    await redis_client.flushdb()
    config = make_config()
    limiter = RateLimiter(redis_client, config)

    rules_key = "ab:watcher-test:rules:endpoint"
    await redis_client.hset(rules_key,
        "r1", json.dumps({"id": "r1", "path": "/api/v1", "limit": 10, "window_seconds": 60, "enabled": True}),
    )

    reloaded: list = []
    watcher = RulesWatcher(redis_client, limiter, on_reload=lambda r: reloaded.extend(r))
    await watcher.poll()

    assert len(reloaded) == 1
    assert reloaded[0].id == "r1"


async def test_poll_merges_with_static_rules(redis_client):
    """Dynamic rules are merged with static config rules — static rules survive."""
    await redis_client.flushdb()
    config = make_config()  # has /static rule
    limiter = RateLimiter(redis_client, config)

    rules_key = "ab:watcher-test:rules:endpoint"
    await redis_client.hset(rules_key,
        "dyn", json.dumps({"id": "dyn", "path": "/dynamic", "limit": 20, "window_seconds": 30, "enabled": True}),
    )

    watcher = RulesWatcher(redis_client, limiter)
    await watcher.poll()

    # Static /static should still match (it has a different endpoint)
    from autoblock import RequestContext
    d = await limiter.check(RequestContext(ip="1.2.3.4", endpoint="/static", method="GET"))
    assert d.allowed
    assert d.limit != float("inf")  # matched a rule, not passthrough


async def test_start_stop_lifecycle(redis_client):
    """start()/stop() cycle completes without error."""
    await redis_client.flushdb()
    config = make_config()
    limiter = RateLimiter(redis_client, config)

    watcher = RulesWatcher(redis_client, limiter, interval_seconds=1)
    await watcher.start()
    await asyncio.sleep(0.1)
    await watcher.stop()

    # Second stop is safe
    await watcher.stop()


async def test_start_is_idempotent(redis_client):
    """Calling start() twice does not create two tasks."""
    await redis_client.flushdb()
    config = make_config()
    limiter = RateLimiter(redis_client, config)

    reload_count = 0

    def on_reload(_):
        nonlocal reload_count
        reload_count += 1

    watcher = RulesWatcher(redis_client, limiter, interval_seconds=10, on_reload=on_reload)
    await watcher.start()
    await watcher.start()  # second call is no-op
    await asyncio.sleep(0.1)
    await watcher.stop()

    # Only 1 immediate poll should have fired
    assert reload_count == 1


async def test_context_manager(redis_client):
    """RulesWatcher works as an async context manager."""
    await redis_client.flushdb()
    config = make_config()
    limiter = RateLimiter(redis_client, config)

    async with RulesWatcher(redis_client, limiter, interval_seconds=10):
        pass  # should start and stop cleanly
