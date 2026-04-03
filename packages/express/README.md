# @autoblock/express

Express.js middleware for [AutoBlock](../../) adaptive rate limiting. Wraps `@autoblock/core` with Express-native request/response handling.

## Installation

```bash
npm install @autoblock/express @autoblock/core ioredis
```

## Quick Start

```typescript
import express from 'express'
import Redis from 'ioredis'
import { autoBlock } from '@autoblock/express'

const app = express()
const redis = new Redis({ host: 'localhost', port: 6379 })

app.use(autoBlock(redis, {
  tenant: 'my-api',
  rules: [
    {
      id: 'login-limit',
      enabled: true,
      dimensions: ['ip'],
      endpointPattern: '^/api/auth/login$',
      methods: ['POST'],
      algorithm: 'hybrid',
      limits: { requests: 10, windowSeconds: 60, burst: 15 },
      penalties: {
        warn:      { scoreThreshold: 3 },
        slow:      { scoreThreshold: 6,  delayMs: 2000 },
        block:     { scoreThreshold: 10, durationSeconds: 300 },
        blacklist: { scoreThreshold: 15 },
      },
    },
    {
      id: 'api-global',
      enabled: true,
      dimensions: ['ip'],
      endpointPattern: '^/api/.*',
      methods: ['*'],
      algorithm: 'sliding_window',
      limits: { requests: 200, windowSeconds: 60, burst: 200 },
      penalties: {
        warn:      { scoreThreshold: 5 },
        block:     { scoreThreshold: 15 },
        blacklist: { scoreThreshold: 25 },
      },
    },
  ],
  middleware: {
    trustProxy: true,          // read real IP from X-Forwarded-For
    trustedProxyDepth: 1,      // 1 = one load balancer in front
    skipPaths: ['/health', '/metrics'],
    failOpen: true,            // allow requests if Redis is down
  },
}))

app.post('/api/auth/login', (req, res) => {
  res.json({ token: 'example' })
})

app.listen(3000)
```

## Response Headers

The middleware automatically adds rate-limit headers to every response:

```
RateLimit-Remaining: 9          ← IETF draft-ietf-httpapi-ratelimit-headers
RateLimit-Reset: 60
X-RateLimit-Remaining: 9        ← Legacy (backward compat)
X-RateLimit-State: CLEAN
```

On denial (429 / 403):

```json
{ "error": "Too many requests. Please slow down.", "state": "BLOCK", "retryAfter": 60 }
```

## User ID Extraction

For per-user rate limiting, the middleware extracts a user ID from:

1. JWT `sub` claim — set `userIdExtractor: 'jwt_sub'`
2. Custom header — set `userIdExtractor: 'header'` and `userIdHeader: 'x-user-id'`

```typescript
app.use(autoBlock(redis, {
  tenant: 'my-api',
  rules: [...],
  middleware: {
    userIdExtractor: 'jwt_sub',   // reads Bearer token, decodes sub (no verification)
  },
}))
```

> The JWT is decoded **without signature verification** — solely for rate-limiting key purposes.

## Hot-Reload + Decay

```typescript
import { RulesWatcher, DecayWorker } from '@autoblock/core'
import { createLimiter } from '@autoblock/express'

const limiter = createLimiter(redis, config)
app.use(limiter.middleware())

const watcher = new RulesWatcher(redis, limiter.rateLimiter, { intervalMs: 30_000 })
const decay   = new DecayWorker(redis, config.tenant, { halfLifeMs: 10 * 60 * 1000 })

watcher.start()
decay.start()

process.on('SIGTERM', () => { watcher.stop(); decay.stop() })
```

## Proxy Trust

When running behind a load balancer or reverse proxy, set `trustProxy: true`. AutoBlock reads the leftmost trustworthy IP from `X-Forwarded-For`:

```
X-Forwarded-For: <client-ip>, <proxy1>, <proxy2>
                  ↑ extracted when trustProxyDepth=1
```

`trustProxyDepth` controls how many right-side proxy hops are trusted (default: 1).

## Configuration

See [`@autoblock/core` README](../core/README.md) for the full `RuleConfig`, `PenaltyConfig`, and `MiddlewareConfig` reference.
