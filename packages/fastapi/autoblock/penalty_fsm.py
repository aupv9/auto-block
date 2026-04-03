"""Penalty state machine — asyncio-native, transitions via atomic Lua script."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

import redis.asyncio as aioredis

from .scripts import PENALTY_TRANSITION
from .types import PenaltyState, PenaltyThresholds

DEFAULT_THRESHOLDS = PenaltyThresholds()


@dataclass
class TransitionResult:
    score: int
    state: PenaltyState
    previous_state: PenaltyState
    state_changed: bool


class PenaltyStateMachine:
    def __init__(
        self,
        redis: aioredis.Redis,
        thresholds: PenaltyThresholds = DEFAULT_THRESHOLDS,
        ttl_seconds: int = 86400,
    ) -> None:
        self._redis = redis
        self._thresholds = thresholds
        self._ttl = ttl_seconds
        self._script = redis.register_script(PENALTY_TRANSITION)

    async def increment(
        self,
        score_key: str,
        state_key: str,
        history_key: str,
        amount: int = 1,
        reason: str = "rate_limit_exceeded",
    ) -> TransitionResult:
        entry = json.dumps({"reason": reason, "amount": amount, "timestamp": int(time.time() * 1000)})
        score, state, prev_state = await self._script(
            keys=[score_key, state_key, history_key],
            args=[
                amount,
                self._thresholds.warn,
                self._thresholds.slow,
                self._thresholds.block,
                self._thresholds.blacklist,
                self._ttl,
                entry,
            ],
        )
        state = state.decode() if isinstance(state, bytes) else state
        prev_state = prev_state.decode() if isinstance(prev_state, bytes) else prev_state
        return TransitionResult(
            score=int(score),
            state=state,
            previous_state=prev_state,
            state_changed=state != prev_state,
        )

    async def get_score(self, score_key: str) -> int:
        val = await self._redis.get(score_key)
        return int(val) if val else 0

    async def get_state(self, state_key: str) -> PenaltyState:
        val = await self._redis.get(state_key)
        if val is None:
            return "CLEAN"
        return val.decode() if isinstance(val, bytes) else val  # type: ignore[return-value]

    @staticmethod
    def score_to_state(score: int, thresholds: PenaltyThresholds = DEFAULT_THRESHOLDS) -> PenaltyState:
        if score >= thresholds.blacklist:
            return "BLACKLIST"
        if score >= thresholds.block:
            return "BLOCK"
        if score >= thresholds.slow:
            return "SLOW"
        if score >= thresholds.warn:
            return "WARN"
        return "CLEAN"
