import type { Redis } from 'ioredis'
import { Result, ok, err } from 'neverthrow'
import type { AutoBlockError } from '../types.js'

export interface TokenBucketResult {
  allowed: boolean
  tokensRemaining: number
}

export interface TokenBucketOptions {
  capacity: number      // maximum tokens in the bucket
  refillRate: number    // tokens added per second
  cost?: number         // tokens consumed per request (default: 1)
}

export class TokenBucket {
  constructor(
    private readonly redis: Redis,
    private readonly options: TokenBucketOptions,
  ) {}

  async check(key: string): Promise<Result<TokenBucketResult, AutoBlockError>> {
    try {
      const { capacity, refillRate, cost = 1 } = this.options

      const [allowed, tokensRemaining] = await this.redis.abTokenBucket(
        key,
        Date.now(),
        capacity,
        refillRate,
        cost,
      )

      return ok({ allowed: allowed === 1, tokensRemaining })
    } catch (cause) {
      return err({ type: 'REDIS_ERROR', cause: cause as Error })
    }
  }
}
