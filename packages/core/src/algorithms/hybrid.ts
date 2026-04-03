import type { Redis } from 'ioredis'
import { Result, ok, err } from 'neverthrow'
import { SlidingWindow, type SlidingWindowResult } from './sliding-window.js'
import { TokenBucket, type TokenBucketResult } from './token-bucket.js'
import type { AutoBlockError } from '../types.js'

export interface HybridResult {
  allowed: boolean
  remaining: number
  slidingWindow: SlidingWindowResult
  tokenBucket: TokenBucketResult
}

export interface HybridOptions {
  requests: number   // sustained rate (sliding window limit)
  windowMs: number   // window duration in ms
  burst: number      // burst capacity (token bucket max tokens)
}

/**
 * Hybrid algorithm: BOTH sliding window AND token bucket must allow a request.
 *
 * - Sliding window catches sustained abuse (e.g. 600 requests spread over 60s)
 * - Token bucket catches bursts (e.g. 50 requests in 100ms)
 *
 * An attacker cannot game one algorithm while staying under the other.
 */
export class HybridAlgorithm {
  private readonly sw: SlidingWindow
  private readonly tb: TokenBucket

  constructor(redis: Redis, options: HybridOptions) {
    this.sw = new SlidingWindow(redis, {
      requests: options.requests,
      windowMs: options.windowMs,
    })
    this.tb = new TokenBucket(redis, {
      capacity: options.burst || options.requests,
      refillRate: options.requests / (options.windowMs / 1000),
    })
  }

  async check(
    swKey: string,
    tbKey: string,
  ): Promise<Result<HybridResult, AutoBlockError>> {
    const [swResult, tbResult] = await Promise.all([
      this.sw.check(swKey),
      this.tb.check(tbKey),
    ])

    if (swResult.isErr()) return err(swResult.error)
    if (tbResult.isErr()) return err(tbResult.error)

    const sw = swResult.value
    const tb = tbResult.value

    return ok({
      allowed: sw.allowed && tb.allowed,
      remaining: Math.min(sw.remaining, tb.tokensRemaining),
      slidingWindow: sw,
      tokenBucket: tb,
    })
  }
}
