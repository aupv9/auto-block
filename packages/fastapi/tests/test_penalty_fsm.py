import pytest
from autoblock.penalty_fsm import DEFAULT_THRESHOLDS, PenaltyStateMachine


# ---------------------------------------------------------------------------
# Pure unit tests — no Redis
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (0, "CLEAN"), (2, "CLEAN"),
    (3, "WARN"), (5, "WARN"),
    (6, "SLOW"), (9, "SLOW"),
    (10, "BLOCK"), (14, "BLOCK"),
    (15, "BLACKLIST"), (999, "BLACKLIST"),
])
def test_score_to_state(score, expected):
    assert PenaltyStateMachine.score_to_state(score) == expected


# ---------------------------------------------------------------------------
# Integration tests — real Redis
# ---------------------------------------------------------------------------

async def test_starts_clean(redis_client):
    fsm = PenaltyStateMachine(redis_client)
    state = await fsm.get_state("test:fsm:state:ip:10.0.0.1")
    score = await fsm.get_score("test:fsm:score:ip:10.0.0.1")
    assert state == "CLEAN"
    assert score == 0


async def test_escalates_to_blacklist(redis_client):
    fsm = PenaltyStateMachine(redis_client, DEFAULT_THRESHOLDS)
    sk = "test:fsm:score:ip:10.0.0.2"
    stk = "test:fsm:state:ip:10.0.0.2"
    hk = "test:fsm:history:ip:10.0.0.2"

    await fsm.increment(sk, stk, hk, 3)   # → WARN
    await fsm.increment(sk, stk, hk, 3)   # → SLOW
    await fsm.increment(sk, stk, hk, 4)   # → BLOCK
    result = await fsm.increment(sk, stk, hk, 5)  # → BLACKLIST

    assert result.state == "BLACKLIST"
    assert result.score == 15
    assert result.state_changed is True


async def test_state_changed_flag(redis_client):
    fsm = PenaltyStateMachine(redis_client, DEFAULT_THRESHOLDS)
    sk = "test:fsm:score:ip:10.0.0.3"
    stk = "test:fsm:state:ip:10.0.0.3"
    hk = "test:fsm:history:ip:10.0.0.3"

    r1 = await fsm.increment(sk, stk, hk, 1)
    r2 = await fsm.increment(sk, stk, hk, 1)
    r3 = await fsm.increment(sk, stk, hk, 1)  # hits WARN threshold

    assert r1.state == "CLEAN"
    assert r3.state == "WARN"
    assert r3.state_changed is True
    assert r3.previous_state == "CLEAN"
