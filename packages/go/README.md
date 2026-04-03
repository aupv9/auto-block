# autoblock-go

Go SDK for [AutoBlock](../../) adaptive rate limiting. Compatible with `net/http`, chi, gin, echo, and any router that uses `http.Handler`.

## Installation

```bash
go get github.com/autoblock/autoblock-go
```

Requires Go 1.22+, Redis 7+.

## Quick Start

```go
package main

import (
    "net/http"

    "github.com/redis/go-redis/v9"
    autoblock "github.com/autoblock/autoblock-go"
)

func main() {
    rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})

    limiter, err := autoblock.New(autoblock.Config{
        Tenant: "my-app",
        Redis:  rdb,
        Rules: []autoblock.Rule{
            {
                Path:          "/api/auth/login",
                Limit:         10,
                WindowSeconds: 60,
                Algorithm:     autoblock.AlgorithmHybrid,
            },
            {
                Path:          "/api/**",
                Limit:         200,
                WindowSeconds: 60,
                Algorithm:     autoblock.AlgorithmSlidingWindow,
            },
        },
        Thresholds: autoblock.Thresholds{
            Warn: 3, Slow: 6, Block: 10, Blacklist: 15,
        },
        TrustProxy:      true,
        TrustProxyDepth: 1,
    })
    if err != nil {
        panic(err)
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/api/auth/login", loginHandler)

    http.ListenAndServe(":8080", limiter.Middleware(mux))
}
```

## Chi Router

```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()
r.Use(limiter.Middleware)
r.Post("/api/auth/login", loginHandler)
```

## Configuration

### `Config`

| Field             | Type            | Required | Description                                             |
|-------------------|-----------------|----------|---------------------------------------------------------|
| `Tenant`          | `string`        | Yes      | Namespaces all Redis keys.                              |
| `Redis`           | `*redis.Client` | Yes      | go-redis client.                                        |
| `Rules`           | `[]Rule`        | No       | Rate-limit rules. First match wins.                     |
| `Thresholds`      | `Thresholds`    | No       | Penalty FSM thresholds. Defaults: 3/6/10/15.            |
| `FailOpen`        | `*bool`         | No       | Allow on Redis error (default `true`).                  |
| `TrustProxy`      | `bool`          | No       | Read IP from `X-Forwarded-For`.                         |
| `TrustProxyDepth` | `int`           | No       | Trusted proxy hops (default 1).                         |
| `KeyPrefix`       | `string`        | No       | Redis key prefix (default `"ab"`).                      |

### `Rule`

| Field           | Type        | Default      | Description                                       |
|-----------------|-------------|--------------|---------------------------------------------------|
| `Path`          | `string`    | —            | Ant-style path pattern (`/api/**`, `/api/*`).     |
| `Limit`         | `int`       | —            | Max requests per window.                          |
| `WindowSeconds` | `int`       | `60`         | Sliding window / token bucket window.             |
| `Algorithm`     | `Algorithm` | `AlgorithmHybrid` | `AlgorithmSlidingWindow`, `AlgorithmTokenBucket`, or `AlgorithmHybrid`. |
| `PerUser`       | `bool`      | `false`      | Enable per-user dimension.                        |
| `PerEndpoint`   | `bool`      | `false`      | Scope counter to exact path.                      |

### `Thresholds`

| Field       | Default | Description                          |
|-------------|---------|--------------------------------------|
| `Warn`      | `3`     | Score to enter WARN state.           |
| `Slow`      | `6`     | Score to enter SLOW state (3 s delay).|
| `Block`     | `10`    | Score to enter BLOCK state (429).    |
| `Blacklist` | `15`    | Score to enter BLACKLIST state (403).|

## Path Patterns

Uses Ant-style patterns:

| Pattern           | Matches                              |
|-------------------|--------------------------------------|
| `/api/auth/login` | Exact match only                     |
| `/api/*`          | One path segment: `/api/users`       |
| `/api/**`         | Any depth: `/api/users/123/orders`   |

## Hot-Reload Rules

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

watcher := limiter.NewWatcher(autoblock.WatcherOptions{
    Interval: 30 * time.Second,
    OnReload: func(rules []autoblock.Rule) {
        log.Printf("Reloaded %d dynamic rules", len(rules))
    },
})
go watcher.Run(ctx)
```

## Score Decay

```go
decay := limiter.NewDecayWorker(autoblock.DecayWorkerOptions{
    HalfLife: 10 * time.Minute,
    Interval: 60 * time.Second,
    OnDecay:  func(r []autoblock.DecayResult) { log.Printf("Decayed %d IPs", len(r)) },
})
go decay.Run(ctx)
```

## User ID via Header

The middleware reads `X-User-ID` from request headers as the user dimension when `PerUser: true` on a rule.

```go
// Client sets:
req.Header.Set("X-User-ID", "user-123")
```

## Response Headers

| Header                | Description                          |
|-----------------------|--------------------------------------|
| `RateLimit-Remaining` | Remaining requests (IETF draft)      |
| `RateLimit-Reset`     | Seconds until window resets          |
| `X-RateLimit-Remaining` | Same (legacy)                      |
| `X-RateLimit-State`   | `CLEAN`, `WARN`, `SLOW`, `BLOCK`, `BLACKLIST` |

On denial:

```json
{ "error": "Too many requests. Please slow down.", "state": "BLOCK", "retryAfter": 60 }
```

## Direct Evaluation (without HTTP middleware)

```go
decision := limiter.Evaluate(ctx, ip, userID, path)
if !decision.Allowed {
    log.Printf("Blocked: %s (status %d)", decision.State, decision.StatusCode)
}
if decision.DelayMs > 0 {
    time.Sleep(time.Duration(decision.DelayMs) * time.Millisecond)
}
```
