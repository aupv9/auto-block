"""Main RateLimiter — mirrors TypeScript RateLimiter, asyncio-native."""
from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import time
from dataclasses import dataclass, field

import redis.asyncio as aioredis
from opentelemetry import trace as otel_trace
from opentelemetry.trace import StatusCode

from .algorithms import HybridAlgorithm, SlidingWindow, TokenBucket
from .key_builder import KeyBuilder
from .penalty_fsm import DEFAULT_THRESHOLDS, PenaltyStateMachine
from .scripts import BLACKLIST_CHECK
from .types import (
    AutoBlockConfig,
    PenaltyState,
    RateLimitDecision,
    RequestContext,
    RuleConfig,
)

_ALLOW_ALL = RateLimitDecision(
    allowed=True, state="CLEAN", score=0, limit=math.inf, remaining=math.inf
)

_STATE_PRIORITY: dict[PenaltyState, int] = {
    "BLACKLIST": 5, "BLOCK": 4, "SLOW": 3, "WARN": 2, "CLEAN": 1
}


@dataclass
class _CompiledRule:
    rule: RuleConfig
    pattern: re.Pattern[str]


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


class RateLimiter:
    def __init__(self, redis: aioredis.Redis, config: AutoBlockConfig) -> None:
        self._redis = redis
        self._config = config
        self._keys = KeyBuilder(config.tenant)
        self._fsm = PenaltyStateMachine(
            redis,
            thresholds=config.rules[0].penalties.thresholds if config.rules else DEFAULT_THRESHOLDS,
            ttl_seconds=config.rules[0].penalties.ttl_seconds if config.rules else 86400,
        )
        self._compiled = self._compile(config.rules)
        self._blacklist_script = redis.register_script(BLACKLIST_CHECK)
        # In-memory CIDR cache, refreshed every 30 s via _refresh_cidr_cache()
        self._blacklist_cidrs: list[str] = []
        self._whitelist_cidrs: list[str] = []
        self._cidr_refresh_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start background CIDR cache refresh. Call once after creation."""
        await self._refresh_cidr_cache()
        self._cidr_refresh_task = asyncio.create_task(
            self._cidr_refresh_loop(), name="autoblock-cidr-refresh"
        )

    async def stop(self) -> None:
        """Cancel background refresh task. Call during shutdown."""
        if self._cidr_refresh_task:
            self._cidr_refresh_task.cancel()
            try:
                await self._cidr_refresh_task
            except (asyncio.CancelledError, Exception):
                pass

    async def _cidr_refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            await self._refresh_cidr_cache()

    async def _refresh_cidr_cache(self) -> None:
        try:
            self._blacklist_cidrs = await self._redis.smembers(self._keys.blacklist_cidr())  # type: ignore[assignment]
        except Exception:
            pass
        try:
            self._whitelist_cidrs = await self._redis.smembers(self._keys.whitelist_cidr())  # type: ignore[assignment]
        except Exception:
            pass

    def merge_rules(self, dynamic: list[RuleConfig]) -> None:
        """Atomically swap active rules: dynamic (Redis) overrides static (config).

        Static rules whose id does not appear in *dynamic* are preserved as
        fallback.  This is the callback invoked by RulesWatcher every 30 s.
        """
        dynamic_ids = {r.id for r in dynamic}
        merged = dynamic + [r for r in self._config.rules if r.id not in dynamic_ids]
        self._compiled = self._compile(merged)

    @staticmethod
    def _compile(rules: list[RuleConfig]) -> list[_CompiledRule]:
        return [
            _CompiledRule(rule=r, pattern=re.compile(r.endpoint_pattern))
            for r in rules
            if r.enabled
        ]

    async def check(self, ctx: RequestContext) -> RateLimitDecision:
        tracer = otel_trace.get_tracer("autoblock")
        with tracer.start_as_current_span(
            "autoblock.evaluate",
            attributes={
                "autoblock.tenant": self._config.tenant,
                "autoblock.ip": ctx.ip,
                "autoblock.endpoint": ctx.endpoint,
            },
        ) as span:
            decision = await self._do_check(ctx)
            span.set_attributes({
                "autoblock.allowed": decision.allowed,
                "autoblock.state": decision.state,
            })
            if not decision.allowed:
                span.set_status(StatusCode.ERROR, "request blocked by autoblock")
            return decision

    async def _do_check(self, ctx: RequestContext) -> RateLimitDecision:
        mw = self._config.middleware

        if ctx.endpoint in mw.skip_paths:
            return _ALLOW_ALL

        try:
            if await self._is_whitelisted(ctx.ip, ctx.user_id):
                return _ALLOW_ALL

            if await self._is_blacklisted(ctx.ip, ctx.user_id):
                return RateLimitDecision(
                    allowed=False, state="BLACKLIST", score=0,
                    limit=0, remaining=0, status_code=403,
                )

            matched = self._match_rules(ctx)
            if not matched:
                return _ALLOW_ALL

            decisions = await asyncio.gather(*[self._evaluate_rule(ctx, r) for r in matched])
            return self._worst_case(list(decisions))

        except Exception:
            if mw.fail_open:
                return _ALLOW_ALL
            raise

    # ---------------------------------------------------------------------------
    # Public management helpers
    # ---------------------------------------------------------------------------

    async def add_to_blacklist(self, ip: str, ttl_seconds: int = 3600) -> None:
        expiry = 0 if ttl_seconds == 0 else int(time.time()) + ttl_seconds
        await self._redis.zadd(self._keys.blacklist("ip"), {ip: expiry})

    async def remove_from_blacklist(self, ip: str) -> None:
        await self._redis.zrem(self._keys.blacklist("ip"), ip)

    async def add_to_whitelist(self, ip: str) -> None:
        await self._redis.sadd(self._keys.whitelist("ip"), ip)

    async def remove_from_whitelist(self, ip: str) -> None:
        await self._redis.srem(self._keys.whitelist("ip"), ip)

    async def add_cidr_to_blacklist(self, cidr: str) -> None:
        ipaddress.ip_network(cidr, strict=False)  # validate
        await self._redis.sadd(self._keys.blacklist_cidr(), cidr)
        if cidr not in self._blacklist_cidrs:
            self._blacklist_cidrs = [*self._blacklist_cidrs, cidr]

    async def remove_cidr_from_blacklist(self, cidr: str) -> None:
        await self._redis.srem(self._keys.blacklist_cidr(), cidr)
        self._blacklist_cidrs = [c for c in self._blacklist_cidrs if c != cidr]

    async def add_cidr_to_whitelist(self, cidr: str) -> None:
        ipaddress.ip_network(cidr, strict=False)  # validate
        await self._redis.sadd(self._keys.whitelist_cidr(), cidr)
        if cidr not in self._whitelist_cidrs:
            self._whitelist_cidrs = [*self._whitelist_cidrs, cidr]

    async def remove_cidr_from_whitelist(self, cidr: str) -> None:
        await self._redis.srem(self._keys.whitelist_cidr(), cidr)
        self._whitelist_cidrs = [c for c in self._whitelist_cidrs if c != cidr]

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    async def _is_whitelisted(self, ip: str, user_id: str | None) -> bool:
        checks = [self._redis.sismember(self._keys.whitelist("ip"), ip)]
        if user_id:
            checks.append(self._redis.sismember(self._keys.whitelist("uid"), user_id))
        results = await asyncio.gather(*checks)
        if any(results):
            return True
        return any(_ip_in_cidr(ip, cidr) for cidr in self._whitelist_cidrs)

    async def _is_blacklisted(self, ip: str, user_id: str | None) -> bool:
        now_sec = int(time.time())
        checks = [self._blacklist_script(keys=[self._keys.blacklist("ip")], args=[ip, now_sec])]
        if user_id:
            checks.append(self._blacklist_script(keys=[self._keys.blacklist("uid")], args=[user_id, now_sec]))
        results = await asyncio.gather(*checks)
        if any(int(r) == 1 for r in results):
            return True
        return any(_ip_in_cidr(ip, cidr) for cidr in self._blacklist_cidrs)

    def _match_rules(self, ctx: RequestContext) -> list[RuleConfig]:
        method = ctx.method.upper()
        matched = []
        for cr in self._compiled:
            if not cr.pattern.search(ctx.endpoint):
                continue
            if cr.rule.methods and "*" not in cr.rule.methods and method not in cr.rule.methods:
                continue
            matched.append(cr.rule)
        return matched

    async def _evaluate_rule(self, ctx: RequestContext, rule: RuleConfig) -> RateLimitDecision:
        ep_hash = self._keys.endpoint_hash(ctx.endpoint)
        window_ms = rule.limits.window_seconds * 1000
        requests = rule.limits.requests
        burst = rule.limits.burst

        # Evaluate each dimension independently
        checks = []
        for dim in rule.dimensions:
            if dim == "ip":
                checks.append(self._check_dim(rule, "ip", ctx.ip, ep_hash, window_ms, requests, burst))
            elif dim == "user_id" and ctx.user_id:
                checks.append(self._check_dim(rule, "uid", ctx.user_id, ep_hash, window_ms, requests, burst))
            elif dim == "endpoint":
                checks.append(self._check_dim(rule, "ep", ep_hash, ep_hash, window_ms, requests, burst))

        if not checks:
            return _ALLOW_ALL

        results = await asyncio.gather(*checks)
        all_allowed = all(r["allowed"] for r in results)
        min_remaining = min(r["remaining"] for r in results)

        # Read current penalty state for IP
        score_key = self._keys.penalty_score("ip", ctx.ip)
        state_key = self._keys.penalty_state("ip", ctx.ip)
        history_key = self._keys.penalty_history("ip", ctx.ip)

        state = await self._fsm.get_state(state_key)
        score = await self._fsm.get_score(score_key)

        if not all_allowed:
            transition = await self._fsm.increment(score_key, state_key, history_key, 1, f"rule:{rule.id}")
            state = transition.state
            score = transition.score

        return self._state_to_decision(state, score, requests, min_remaining, rule, all_allowed)

    async def _check_dim(
        self,
        rule: RuleConfig,
        dim: str,
        value: str,
        ep_hash: str,
        window_ms: int,
        requests: int,
        burst: int,
    ) -> dict:
        fail_open = {"allowed": True, "remaining": requests}
        try:
            if rule.algorithm == "sliding_window":
                key = self._keys.sliding_window(dim, value, ep_hash)
                r = await SlidingWindow(self._redis, requests, window_ms).check(key)
                return {"allowed": r.allowed, "remaining": r.remaining}

            if rule.algorithm == "token_bucket":
                key = self._keys.token_bucket(dim, value, ep_hash)
                r = await TokenBucket(self._redis, burst or requests, requests / (window_ms / 1000)).check(key)
                return {"allowed": r.allowed, "remaining": r.tokens_remaining}

            # hybrid (default)
            sw_key = self._keys.sliding_window(dim, value, ep_hash)
            tb_key = self._keys.token_bucket(dim, value, ep_hash)
            r = await HybridAlgorithm(self._redis, requests, window_ms, burst or requests).check(sw_key, tb_key)
            return {"allowed": r.allowed, "remaining": r.remaining}

        except Exception:
            return fail_open

    def _state_to_decision(
        self,
        state: PenaltyState,
        score: int,
        limit: int,
        remaining: float,
        rule: RuleConfig,
        algo_allowed: bool,
    ) -> RateLimitDecision:
        p = rule.penalties

        if state == "BLACKLIST":
            return RateLimitDecision(allowed=False, state=state, score=score, limit=limit, remaining=0, status_code=403)

        if state == "BLOCK":
            return RateLimitDecision(
                allowed=False, state=state, score=score, limit=limit, remaining=0,
                status_code=429, retry_after_seconds=p.block.duration_seconds if p.block else 300,
            )

        if state == "SLOW":
            return RateLimitDecision(
                allowed=True, state=state, score=score, limit=limit, remaining=remaining,
                delay_ms=p.slow.delay_ms if p.slow else 3000,
            )

        if state == "WARN":
            return RateLimitDecision(allowed=True, state=state, score=score, limit=limit, remaining=remaining)

        # CLEAN
        if not algo_allowed:
            return RateLimitDecision(allowed=False, state="CLEAN", score=score, limit=limit, remaining=0, status_code=429)
        return RateLimitDecision(allowed=True, state="CLEAN", score=score, limit=limit, remaining=remaining)

    def _worst_case(self, decisions: list[RateLimitDecision]) -> RateLimitDecision:
        return max(decisions, key=lambda d: _STATE_PRIORITY.get(d.state, 0))
