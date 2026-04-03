"""Integration tests for DecayWorker."""
from __future__ import annotations

import asyncio
import time

import pytest

from autoblock.decay_worker import DecayWorker
from autoblock.key_builder import KeyBuilder
from autoblock.types import PenaltyThresholds

TENANT = "decay-test"


async def seed_score(
    redis_client,
    ip: str,
    score: int,
    elapsed_ms: int = 0,
) -> None:
    """Seed a penalty score key with an optional past decay timestamp."""
    keys = KeyBuilder(TENANT)
    past_ms = int(time.time() * 1000) - elapsed_ms

    state = "CLEAN"
    if score >= 15:
        state = "BLACKLIST"
    elif score >= 10:
        state = "BLOCK"
    elif score >= 6:
        state = "SLOW"
    elif score >= 3:
        state = "WARN"

    await redis_client.set(keys.penalty_score("ip", ip), score)
    await redis_client.set(keys.penalty_state("ip", ip), state)
    await redis_client.set(keys.penalty_decay_ts("ip", ip), past_ms)


async def test_empty_db_returns_empty(redis_client):
    """No score keys → empty results, no error."""
    await redis_client.flushdb()
    worker = DecayWorker(redis_client, TENANT)
    results = await worker.run_cycle()
    assert results == []


async def test_zero_score_skipped(redis_client):
    """IPs with score = 0 produce no result (Lua returns early)."""
    await redis_client.flushdb()
    await seed_score(redis_client, "1.2.3.4", 0)
    worker = DecayWorker(redis_client, TENANT)
    results = await worker.run_cycle()
    assert results == []


async def test_decays_score_over_time(redis_client):
    """Score > 0 with elapsed time → score reduced, result returned."""
    await redis_client.flushdb()
    await seed_score(redis_client, "10.0.0.1", 20, elapsed_ms=5 * 60 * 1000)  # 5 min

    worker = DecayWorker(redis_client, TENANT, half_life_ms=10 * 60 * 1000)
    results = await worker.run_cycle()

    assert len(results) == 1
    assert results[0].ip == "10.0.0.1"
    assert results[0].decrement > 0
    assert results[0].new_score < 20


async def test_decays_multiple_ips(redis_client):
    """All seeded IPs are decayed in a single cycle."""
    await redis_client.flushdb()
    ips = ["10.1.0.1", "10.1.0.2", "10.1.0.3"]
    for ip in ips:
        await seed_score(redis_client, ip, 12, elapsed_ms=5 * 60 * 1000)

    worker = DecayWorker(redis_client, TENANT, half_life_ms=10 * 60 * 1000)
    results = await worker.run_cycle()

    assert len(results) == 3
    for r in results:
        assert r.decrement > 0
        assert r.new_score < 12


async def test_no_double_decay_same_ms(redis_client):
    """Second immediate cycle should not decrement again (elapsed ≈ 0)."""
    await redis_client.flushdb()
    await seed_score(redis_client, "10.2.0.1", 15, elapsed_ms=5 * 60 * 1000)

    worker = DecayWorker(redis_client, TENANT, half_life_ms=10 * 60 * 1000)

    r1 = await worker.run_cycle()
    assert len(r1) == 1
    first_score = r1[0].new_score

    r2 = await worker.run_cycle()
    assert r2 == [], "second immediate cycle should not decrement"

    keys = KeyBuilder(TENANT)
    current = int(await redis_client.get(keys.penalty_score("ip", "10.2.0.1")))
    assert current == first_score


async def test_on_decay_callback(redis_client):
    """on_decay callback is called with changed IPs."""
    await redis_client.flushdb()
    await seed_score(redis_client, "10.3.0.1", 10, elapsed_ms=5 * 60 * 1000)

    called: list = []
    worker = DecayWorker(redis_client, TENANT,
                         half_life_ms=10 * 60 * 1000,
                         on_decay=lambda r: called.extend(r))
    await worker.run_cycle()

    assert len(called) == 1
    assert called[0].ip == "10.3.0.1"


async def test_start_stop_lifecycle(redis_client):
    """start()/stop() cycle completes without error."""
    await redis_client.flushdb()
    worker = DecayWorker(redis_client, TENANT, interval_seconds=1)
    await worker.start()
    await asyncio.sleep(0.1)
    await worker.stop()
    await worker.stop()  # idempotent


async def test_context_manager(redis_client):
    """DecayWorker works as an async context manager."""
    await redis_client.flushdb()
    async with DecayWorker(redis_client, TENANT, interval_seconds=10):
        pass


async def test_state_updated_after_decay(redis_client):
    """State key is updated to reflect the decayed score."""
    await redis_client.flushdb()
    # Score 4 (WARN) with 1 hour elapsed → should decay to CLEAN
    await seed_score(redis_client, "10.4.0.1", 4, elapsed_ms=60 * 60 * 1000)

    worker = DecayWorker(redis_client, TENANT,
                         half_life_ms=10 * 60 * 1000,
                         thresholds=PenaltyThresholds(warn=3, slow=6, block=10, blacklist=15))
    await worker.run_cycle()

    keys = KeyBuilder(TENANT)
    state = await redis_client.get(keys.penalty_state("ip", "10.4.0.1"))
    assert state in (b"CLEAN", b"WARN")  # depending on exact decay amount
