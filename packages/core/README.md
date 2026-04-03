# @autoblock/core

Core rate-limiting algorithms and penalty FSM for AutoBlock. Framework-agnostic — used by `@autoblock/express` and the FastAPI / Spring / Go SDK adapters.

## Installation

```bash
npm install @autoblock/core ioredis
```

## Quick Start

```typescript
import Redis from 'ioredis'
import { RateLimiter } from '@autoblock/core'

const redis = new Redis({ host: 'localhost', port: 6379 })

const limiter = new RateLimiter(redis, {
  tenant: 'my-app',
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
  ],
})

const decision = await limiter.check({
  ip: '1.2.3.4',
  endpoint: '/api/auth/login',
  method: 'POST',
})

if (!decision._unsafeUnwrap().allowed) {
  console.log('Blocked:', decision._unsafeUnwrap().state)
}
```

## Configuration Reference

### `AutoBlockConfig`

| Field        | Type             | Required | Description                                      |
|--------------|------------------|----------|--------------------------------------------------|
| `tenant`     | `string`         | Yes      | Namespaces all Redis keys. Use per-service name. |
| `rules`      | `RuleConfig[]`   | Yes      | Ordered list of rate-limit rules (first match). |
| `middleware` | `MiddlewareConfig` | No     | Proxy trust, skip paths, user ID extraction.     |

### `RuleConfig`

| Field             | Type                                         | Default    | Description                                      |
|-------------------|----------------------------------------------|------------|--------------------------------------------------|
| `id`              | `string`                                     | —          | Unique rule identifier.                          |
| `enabled`         | `boolean`                                    | `true`     | Disable without removing.                        |
| `dimensions`      | `('ip' \| 'user_id' \| 'endpoint')[]`        | `['ip']`   | Which dimensions to rate-limit.                  |
| `endpointPattern` | `string` (regex)                             | —          | Regex matched against the request path.          |
| `methods`         | `string[]`                                   | `['*']`    | HTTP methods. `*` matches all.                   |
| `algorithm`       | `'sliding_window' \| 'token_bucket' \| 'hybrid'` | `'hybrid'` | Algorithm selection.                    |
| `limits.requests` | `number`                                     | —          | Max requests in the window.                      |
| `limits.windowSeconds` | `number`                                | —          | Sliding window duration.                         |
| `limits.burst`    | `number`                                     | `requests` | Token bucket burst capacity.                     |

### `PenaltyConfig`

Each step (`warn`, `slow`, `block`, `blacklist`) accepts:

| Field            | Description                                   |
|------------------|-----------------------------------------------|
| `scoreThreshold` | Penalty score at which this state is entered. |
| `delayMs`        | (SLOW only) Artificial delay added to request.|
| `durationSeconds`| (BLOCK only) How long the block lasts.        |

### `MiddlewareConfig`

| Field               | Default       | Description                                         |
|---------------------|---------------|-----------------------------------------------------|
| `failOpen`          | `true`        | Allow requests when Redis is unavailable.           |
| `skipPaths`         | `[]`          | Paths exempt from rate limiting (e.g. `/health`).   |
| `trustProxy`        | `false`       | Read client IP from `X-Forwarded-For`.              |
| `trustedProxyDepth` | `1`           | Number of trusted proxy hops.                       |
| `userIdExtractor`   | `'none'`      | `'jwt_sub'`, `'header'`, or `'none'`.               |
| `userIdHeader`      | `'x-user-id'` | Header name when `userIdExtractor = 'header'`.      |

## Hot-Reload Rules

Rules stored in the `ab:{tenant}:rules:endpoint` Redis hash are automatically merged with static config rules. Dynamic rules take precedence over static ones with the same ID.

```typescript
import { RulesWatcher } from '@autoblock/core'

const watcher = new RulesWatcher(redis, limiter, {
  intervalMs: 30_000,          // poll every 30 s (default)
  onReload: (rules) => console.log('Reloaded', rules.length, 'dynamic rules'),
})
watcher.start()

// on graceful shutdown:
watcher.stop()
```

## Score Decay

Without the AutoBlock engine, IPs never "cool down" unless you run a `DecayWorker`:

```typescript
import { DecayWorker } from '@autoblock/core'

const decay = new DecayWorker(redis, 'my-app', {
  halfLifeMs:  10 * 60 * 1000,  // score halves every 10 minutes
  intervalMs:  60 * 1000,        // scan every minute
  onDecay: (results) => console.log('Decayed', results.length, 'IPs'),
})
decay.start()

// on shutdown:
decay.stop()
```

## Response Headers

Every request receives:

| Header                | Description                          |
|-----------------------|--------------------------------------|
| `RateLimit-Remaining` | Remaining requests (IETF draft)      |
| `RateLimit-Reset`     | Seconds until window resets          |
| `X-RateLimit-Remaining` | Same (legacy)                      |
| `X-RateLimit-State`   | FSM state: `CLEAN`, `WARN`, …        |

On denial:

| Header        | Description                                    |
|---------------|------------------------------------------------|
| `Retry-After` | Seconds to wait (BLOCK / 429 responses only)   |

## Penalty State Machine

```
CLEAN ──→ WARN ──→ SLOW ──→ BLOCK ──→ BLACKLIST
  │         │        │        │
  └─────────┴────────┴────────┘ (score decays over time)
```

Each dimension (IP, user, endpoint) accumulates a penalty score independently. The worst-case state across all active dimensions determines the final decision.

## Algorithms

| Algorithm       | Catches          | Trade-off                          |
|-----------------|------------------|------------------------------------|
| `sliding_window`| Sustained abuse  | Can allow short bursts             |
| `token_bucket`  | Bursts           | Doesn't catch slow sustained abuse |
| `hybrid`        | Both             | Recommended for auth endpoints     |

## Redis Key Schema

```
ab:{tenant}:sw:ip:{ip}:{ep_hash}       sorted set  (sliding window)
ab:{tenant}:tb:ip:{ip}:{ep_hash}       hash        (token bucket)
ab:{tenant}:penalty:score:ip:{ip}      string      (integer)
ab:{tenant}:penalty:state:ip:{ip}      string      (CLEAN|WARN|…)
ab:{tenant}:blacklist:ip               sorted set  (score = expiry unix ts)
ab:{tenant}:whitelist:ip               set
ab:{tenant}:rules:endpoint             hash        (rule_id → JSON)
```

All counter operations use Lua scripts — atomicity is guaranteed without `WATCH`/`MULTI`.
