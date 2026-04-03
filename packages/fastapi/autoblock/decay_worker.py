"""DecayWorker — standalone exponential score decay (no engine required)."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Callable

import redis.asyncio as aioredis

from .key_builder import KeyBuilder
from .types import PenaltyThresholds

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lua script — identical to engine/internal/store/decay.go scoreDecayLua
# ---------------------------------------------------------------------------
_LUA_DECAY = """
local score_key    = KEYS[1]
local state_key    = KEYS[2]
local decay_ts_key = KEYS[3]
local now          = tonumber(ARGV[1])
local half_life_ms = tonumber(ARGV[2])
local warn_t       = tonumber(ARGV[3])
local slow_t       = tonumber(ARGV[4])
local block_t      = tonumber(ARGV[5])
local blacklist_t  = tonumber(ARGV[6])

local raw = redis.call('GET', score_key)
if not raw then return {0, 'CLEAN', 0} end
local score = tonumber(raw)
if score <= 0 then return {0, 'CLEAN', 0} end

local last_decay = tonumber(redis.call('GET', decay_ts_key) or tostring(now))
local elapsed = now - last_decay
if elapsed <= 0 then
  return {score, redis.call('GET', state_key) or 'CLEAN', 0}
end

local factor    = math.exp(-0.693147 * elapsed / half_life_ms)
local new_score = math.floor(score * factor)
if new_score < 0 then new_score = 0 end
local decrement = score - new_score

redis.call('SET', decay_ts_key, now)

if decrement <= 0 then
  return {score, redis.call('GET', state_key) or 'CLEAN', 0}
end

redis.call('SET', score_key, new_score)

local state
if     new_score >= blacklist_t then state = 'BLACKLIST'
elseif new_score >= block_t     then state = 'BLOCK'
elseif new_score >= slow_t      then state = 'SLOW'
elseif new_score >= warn_t      then state = 'WARN'
else                                  state = 'CLEAN'
end

redis.call('SET', state_key, state)
return {new_score, state, decrement}
"""

_DEFAULT_HALF_LIFE_MS = 10 * 60 * 1000  # 10 minutes
_DEFAULT_INTERVAL_S   = 60               # 1 minute


@dataclass
class DecayResult:
    ip: str
    new_score: int
    new_state: str
    decrement: int


class DecayWorker:
    """
    Periodically scans penalty score keys in Redis and applies exponential
    half-life decay so IPs "cool down" over time without needing the Go engine.

    Usage::

        worker = DecayWorker(redis, tenant="my-app")
        await worker.start()
        # on shutdown:
        await worker.stop()

    Or as an async context manager::

        async with DecayWorker(redis, tenant="my-app"):
            await run_app()
    """

    def __init__(
        self,
        redis: aioredis.Redis,
        tenant: str,
        *,
        half_life_ms: int = _DEFAULT_HALF_LIFE_MS,
        interval_seconds: int = _DEFAULT_INTERVAL_S,
        thresholds: PenaltyThresholds | None = None,
        on_decay: Callable[[list[DecayResult]], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        self._redis = redis
        self._keys = KeyBuilder(tenant)
        self._half_life_ms = half_life_ms
        self._interval = interval_seconds
        self._thresholds = thresholds or PenaltyThresholds()
        self._on_decay = on_decay
        self._on_error = on_error
        self._script = redis.register_script(_LUA_DECAY)
        self._task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._task is not None:
            return
        await self.run_cycle()  # immediate first decay
        self._task = asyncio.create_task(self._loop(), name="autoblock-decay-worker")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def __aenter__(self) -> "DecayWorker":
        await self.start()
        return self

    async def __aexit__(self, *_) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # Core cycle
    # ------------------------------------------------------------------

    async def run_cycle(self) -> list[DecayResult]:
        """Run a single decay pass over all tracked IPs."""
        ips = await self._scan_ips()
        if not ips:
            return []

        tasks = [self._decay_one(ip) for ip in ips]
        results_raw = await asyncio.gather(*tasks, return_exceptions=True)
        results = [r for r in results_raw if isinstance(r, DecayResult) and r.decrement > 0]

        if results and self._on_decay:
            self._on_decay(results)
        return results

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self.run_cycle()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("autoblock DecayWorker error: %s", exc)
                if self._on_error:
                    self._on_error(exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _scan_ips(self) -> list[str]:
        pattern = self._keys.penalty_score_pattern("ip")
        prefix  = self._keys.penalty_score("ip", "")
        ips: list[str] = []
        cursor: int = 0
        while True:
            cursor, keys = await self._redis.scan(cursor, match=pattern, count=100)
            for key in keys:
                ip = key[len(prefix):]
                if ip:
                    ips.append(ip)
            if cursor == 0:
                break
        return ips

    async def _decay_one(self, ip: str) -> DecayResult:
        t = self._thresholds
        import time
        now_ms = int(time.time() * 1000)
        res = await self._script(
            keys=[
                self._keys.penalty_score("ip", ip),
                self._keys.penalty_state("ip", ip),
                self._keys.penalty_decay_ts("ip", ip),
            ],
            args=[now_ms, self._half_life_ms, t.warn, t.slow, t.block, t.blacklist],
        )
        new_score, new_state, decrement = int(res[0]), str(res[1]), int(res[2])
        return DecayResult(ip=ip, new_score=new_score, new_state=new_state, decrement=decrement)
