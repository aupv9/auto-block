import type { Redis } from 'ioredis'
import { Result, ok, err } from 'neverthrow'
import type { AutoBlockError } from '../types.js'

export interface SlidingWindowResult {
  allowed: boolean
  count: number
  remaining: number
}

export interface SlidingWindowOptions {
  requests: number
  windowMs: number
}

export class SlidingWindow {
  constructor(
    private readonly redis: Redis,
    private readonly options: SlidingWindowOptions,
  ) {}

  async check(key: string): Promise<Result<SlidingWindowResult, AutoBlockError>> {
    try {
      const now = Date.now()
      // Unique member prevents duplicate scoring if the same ms fires twice
      const member = `${now}-${Math.random().toString(36).slice(2, 9)}`

      const [allowed, count, remaining] = await this.redis.abSlidingWindow(
        key,
        now,
        this.options.windowMs,
        this.options.requests,
        member,
      )

      return ok({ allowed: allowed === 1, count, remaining: Math.max(0, remaining) })
    } catch (cause) {
      return err({ type: 'REDIS_ERROR', cause: cause as Error })
    }
  }
}
