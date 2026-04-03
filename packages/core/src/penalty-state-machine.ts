import type { Redis } from 'ioredis'
import { Result, ok, err } from 'neverthrow'
import type { PenaltyState, PenaltyThresholds, AutoBlockError } from './types.js'

export const DEFAULT_THRESHOLDS: PenaltyThresholds = {
  warn: 3,
  slow: 6,
  block: 10,
  blacklist: 15,
}

export interface PenaltyTransitionResult {
  score: number
  state: PenaltyState
  previousState: PenaltyState
  stateChanged: boolean
}

export class PenaltyStateMachine {
  constructor(
    private readonly redis: Redis,
    private readonly thresholds: PenaltyThresholds = DEFAULT_THRESHOLDS,
    private readonly ttlSeconds = 86400,
  ) {}

  async increment(
    scoreKey: string,
    stateKey: string,
    historyKey: string,
    amount = 1,
    reason = 'rate_limit_exceeded',
  ): Promise<Result<PenaltyTransitionResult, AutoBlockError>> {
    try {
      const historyEntry = JSON.stringify({ reason, amount, timestamp: Date.now() })

      const [score, state, prevState] = await this.redis.abPenaltyTransition(
        scoreKey,
        stateKey,
        historyKey,
        amount,
        this.thresholds.warn,
        this.thresholds.slow,
        this.thresholds.block,
        this.thresholds.blacklist,
        this.ttlSeconds,
        historyEntry,
      )

      return ok({
        score,
        state: state as PenaltyState,
        previousState: prevState as PenaltyState,
        stateChanged: state !== prevState,
      })
    } catch (cause) {
      return err({ type: 'REDIS_ERROR', cause: cause as Error })
    }
  }

  async getScore(scoreKey: string): Promise<number> {
    const val = await this.redis.get(scoreKey)
    return val !== null ? parseInt(val, 10) : 0
  }

  async getState(stateKey: string): Promise<PenaltyState> {
    const val = await this.redis.get(stateKey)
    return (val as PenaltyState | null) ?? 'CLEAN'
  }

  async getHistory(historyKey: string): Promise<Array<{ reason: string; amount: number; timestamp: number }>> {
    const entries = await this.redis.lrange(historyKey, 0, -1)
    return entries.map(e => {
      try {
        return JSON.parse(e) as { reason: string; amount: number; timestamp: number }
      } catch {
        return { reason: 'unknown', amount: 0, timestamp: 0 }
      }
    })
  }

  // Pure helper — no Redis needed
  static scoreToState(
    score: number,
    thresholds: PenaltyThresholds = DEFAULT_THRESHOLDS,
  ): PenaltyState {
    if (score >= thresholds.blacklist) return 'BLACKLIST'
    if (score >= thresholds.block) return 'BLOCK'
    if (score >= thresholds.slow) return 'SLOW'
    if (score >= thresholds.warn) return 'WARN'
    return 'CLEAN'
  }
}
