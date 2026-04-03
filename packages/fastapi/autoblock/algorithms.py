"""Rate limiting algorithms — asyncio-native, all operations atomic via Lua."""
from __future__ import annotations

import random
import string
import time
from dataclasses import dataclass

import redis.asyncio as aioredis

from .scripts import SLIDING_WINDOW, TOKEN_BUCKET


def _rand_suffix() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=7))


@dataclass
class SlidingWindowResult:
    allowed: bool
    count: int
    remaining: int


@dataclass
class TokenBucketResult:
    allowed: bool
    tokens_remaining: int


@dataclass
class HybridResult:
    allowed: bool
    remaining: int
    sliding_window: SlidingWindowResult
    token_bucket: TokenBucketResult


class SlidingWindow:
    def __init__(self, redis: aioredis.Redis, requests: int, window_ms: int) -> None:
        self._redis = redis
        self._requests = requests
        self._window_ms = window_ms
        self._script = redis.register_script(SLIDING_WINDOW)

    async def check(self, key: str) -> SlidingWindowResult:
        now = int(time.time() * 1000)
        member = f"{now}-{_rand_suffix()}"
        allowed, count, remaining = await self._script(
            keys=[key], args=[now, self._window_ms, self._requests, member]
        )
        return SlidingWindowResult(
            allowed=int(allowed) == 1,
            count=int(count),
            remaining=max(0, int(remaining)),
        )


class TokenBucket:
    def __init__(
        self,
        redis: aioredis.Redis,
        capacity: int,
        refill_rate: float,  # tokens/second
        cost: int = 1,
    ) -> None:
        self._redis = redis
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._cost = cost
        self._script = redis.register_script(TOKEN_BUCKET)

    async def check(self, key: str) -> TokenBucketResult:
        now = int(time.time() * 1000)
        allowed, tokens = await self._script(
            keys=[key], args=[now, self._capacity, self._refill_rate, self._cost]
        )
        return TokenBucketResult(allowed=int(allowed) == 1, tokens_remaining=int(tokens))


class HybridAlgorithm:
    """Both sliding window AND token bucket must allow — catches bursts AND sustained abuse."""

    def __init__(
        self,
        redis: aioredis.Redis,
        requests: int,
        window_ms: int,
        burst: int,
    ) -> None:
        self._sw = SlidingWindow(redis, requests, window_ms)
        self._tb = TokenBucket(
            redis,
            capacity=burst or requests,
            refill_rate=requests / (window_ms / 1000),
        )

    async def check(self, sw_key: str, tb_key: str) -> HybridResult:
        import asyncio
        sw_result, tb_result = await asyncio.gather(
            self._sw.check(sw_key),
            self._tb.check(tb_key),
        )
        return HybridResult(
            allowed=sw_result.allowed and tb_result.allowed,
            remaining=min(sw_result.remaining, tb_result.tokens_remaining),
            sliding_window=sw_result,
            token_bucket=tb_result,
        )
