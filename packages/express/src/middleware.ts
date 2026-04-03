import type { Request, Response, NextFunction, RequestHandler } from 'express'
import type { Redis } from 'ioredis'
import { RateLimiter, type AutoBlockConfig, type AutoBlockEvents } from '@autoblock/core'
import { extractIP, buildUserIdExtractor, type UserIdExtractor } from './extractors.js'

export interface AutoBlockMiddlewareOptions {
  redis: Redis
  config: AutoBlockConfig
  /** Override IP extraction logic */
  getIP?: (req: Request) => string
  /** Override user ID extraction logic */
  getUserId?: UserIdExtractor
}

export interface AutoBlockMiddleware extends RequestHandler {
  /** Access the underlying RateLimiter for programmatic blacklist/whitelist management */
  limiter: RateLimiter
  /** Subscribe to rate limit events (blacklisted, stateChanged, blocked, allowed) */
  events: AutoBlockEvents
}

/**
 * Creates an Express middleware that enforces rate limits, progressive penalties,
 * and emits events for external consumers (e.g. auto-remediation engine).
 *
 * @example
 * ```ts
 * const guard = autoBlock({ redis, config })
 * app.use(guard)
 *
 * // Manually manage blocklist:
 * guard.limiter.addToBlacklist('1.2.3.4', 3600)
 *
 * // React to events:
 * guard.events.on('blacklisted', (e) => slackAlert(e))
 * ```
 */
export function autoBlock(options: AutoBlockMiddlewareOptions): AutoBlockMiddleware {
  const limiter = new RateLimiter(options.redis, options.config)
  const mwCfg = options.config.middleware ?? {}

  const getIP = options.getIP ?? ((req: Request) =>
    extractIP(req, {
      trustProxy: mwCfg.trustProxy,
      depth: mwCfg.trustedProxyDepth,
    })
  )

  const getUserId = options.getUserId ?? buildUserIdExtractor({
    userIdExtractor: mwCfg.userIdExtractor,
    userIdHeader: mwCfg.userIdHeader,
  })

  const handler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    const ip = getIP(req)
    const userId = getUserId(req)

    const result = await limiter.check({
      ip,
      userId,
      endpoint: req.path,
      method: req.method,
      timestamp: Date.now(),
    })

    if (result.isErr()) {
      // Fail-open: Redis error → pass through (log but don't block)
      console.warn('[autoblock] redis error, failing open', result.error)
      return next()
    }

    const decision = result.value

    // Set rate-limit headers (IETF draft-ietf-httpapi-ratelimit-headers + legacy X- prefix)
    if (decision.limit !== Infinity) {
      const limit     = decision.limit
      const remaining = Math.max(0, decision.remaining)
      const reset     = decision.retryAfterSeconds ?? 60

      // IETF standard headers
      res.setHeader('RateLimit-Limit',     limit)
      res.setHeader('RateLimit-Remaining', remaining)
      res.setHeader('RateLimit-Reset',     reset)

      // Legacy X- headers (backward compatibility)
      res.setHeader('X-RateLimit-Limit',     limit)
      res.setHeader('X-RateLimit-Remaining', remaining)
      res.setHeader('X-RateLimit-State',     decision.state)
    }

    if (!decision.allowed) {
      if (decision.retryAfterSeconds !== undefined) {
        res.setHeader('Retry-After', decision.retryAfterSeconds)
      }
      return res.status(decision.statusCode ?? 429).json({
        error: decision.statusCode === 403 ? 'Forbidden' : 'Too Many Requests',
        state: decision.state,
        retryAfter: decision.retryAfterSeconds,
      })
    }

    // SLOW state — artificial delay before continuing
    if (decision.delayMs && decision.delayMs > 0) {
      await new Promise<void>(resolve => setTimeout(resolve, decision.delayMs))
    }

    return next()
  }

  // Attach limiter and events so callers can manage blocklists and subscribe to events
  const middleware = handler as AutoBlockMiddleware
  middleware.limiter = limiter
  middleware.events = limiter.events

  return middleware
}
