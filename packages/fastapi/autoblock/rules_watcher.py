"""RulesWatcher — hot-reloads dynamic rules from Redis into RateLimiter."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Callable

import redis.asyncio as aioredis

from .key_builder import KeyBuilder
from .types import RuleConfig, LimitsConfig, PenaltyConfig, PenaltyThresholds

log = logging.getLogger(__name__)

_DEFAULT_INTERVAL = 30  # seconds


class RulesWatcher:
    """
    Polls ``ab:{tenant}:rules:endpoint`` (Redis hash) every *interval_seconds*
    and hot-reloads rules into the associated :class:`~autoblock.RateLimiter`.

    Usage::

        watcher = RulesWatcher(redis, limiter)
        await watcher.start()        # fires once immediately, then every 30 s
        # later…
        await watcher.stop()

    Or as an async context manager::

        async with RulesWatcher(redis, limiter):
            await app()
    """

    def __init__(
        self,
        redis: aioredis.Redis,
        limiter,  # RateLimiter (avoid circular import)
        *,
        interval_seconds: int = _DEFAULT_INTERVAL,
        on_reload: Callable[[list[RuleConfig]], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        self._redis = redis
        self._limiter = limiter
        self._interval = interval_seconds
        self._on_reload = on_reload
        self._on_error = on_error
        self._keys = KeyBuilder(limiter._config.tenant)
        self._task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start background polling (idempotent)."""
        if self._task is not None:
            return
        await self.poll()  # immediate first load
        self._task = asyncio.create_task(self._loop(), name="autoblock-rules-watcher")

    async def stop(self) -> None:
        """Cancel background polling."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def __aenter__(self) -> "RulesWatcher":
        await self.start()
        return self

    async def __aexit__(self, *_) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # Core poll
    # ------------------------------------------------------------------

    async def poll(self) -> list[RuleConfig]:
        """Single poll cycle — callable directly in tests."""
        raw: dict[str, str] = await self._redis.hgetall(self._keys.rules())
        dynamic = _parse_dynamic_rules(raw)
        self._limiter.merge_rules(dynamic)
        if self._on_reload:
            self._on_reload(dynamic)
        return dynamic

    # ------------------------------------------------------------------
    # Background loop (ticker + pub/sub push)
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        # Subscribe for push-based invalidation from the engine.
        push_task = asyncio.create_task(
            self._subscribe_push(), name="autoblock-rules-push"
        )
        try:
            while True:
                await asyncio.sleep(self._interval)
                try:
                    await self.poll()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.warning("autoblock RulesWatcher poll error: %s", exc)
                    if self._on_error:
                        self._on_error(exc)
        finally:
            push_task.cancel()
            try:
                await push_task
            except (asyncio.CancelledError, Exception):
                pass

    async def _subscribe_push(self) -> None:
        """Subscribe to ab:{tenant}:rules:changed and reload immediately on message."""
        try:
            async with self._redis.pubsub() as pubsub:
                await pubsub.subscribe(self._keys.rules_changed())
                async for message in pubsub.listen():
                    if message.get("type") == "message":
                        log.debug("autoblock RulesWatcher: push notification received")
                        try:
                            await self.poll()
                        except Exception as exc:
                            log.warning("autoblock RulesWatcher push-reload error: %s", exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Pub/sub unavailable — ticker-only fallback is still running.
            log.debug("autoblock RulesWatcher: pub/sub unavailable (%s), poll-only mode", exc)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_dynamic_rules(raw: dict[str, str]) -> list[RuleConfig]:
    rules: list[RuleConfig] = []
    for json_str in raw.values():
        try:
            r = json.loads(json_str)
            if r.get("enabled") is False:
                continue
            rules.append(_map_redis_rule(r))
        except Exception:
            pass  # skip malformed entries
    return rules


def _map_redis_rule(r: dict) -> RuleConfig:
    return RuleConfig(
        id=r.get("id", ""),
        enabled=r.get("enabled", True),
        description=r.get("description", ""),
        dimensions=r.get("dimensions", ["ip"]),
        endpoint_pattern=r.get("path") or r.get("endpoint_pattern", ""),
        methods=r.get("methods", ["*"]),
        algorithm=r.get("algorithm", "hybrid"),
        limits=LimitsConfig(
            requests=r.get("limit", 100),
            window_seconds=r.get("window_seconds", 60),
            burst=r.get("burst") or r.get("limit", 100),
        ),
        penalties=_map_penalties(r.get("penalties", {})),
    )


def _map_penalties(p: dict) -> PenaltyConfig:
    if not p:
        return PenaltyConfig()
    raw_thresholds = p.get("thresholds")
    thresholds = (
        PenaltyThresholds(**raw_thresholds)
        if isinstance(raw_thresholds, dict)
        else PenaltyThresholds()
    )
    return PenaltyConfig(
        warn=p.get("warn"),
        slow=p.get("slow"),
        block=p.get("block"),
        blacklist=p.get("blacklist"),
        thresholds=thresholds,
        ttl_seconds=p.get("ttl_seconds", 86400),
    )
