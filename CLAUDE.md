# AutoBlock — Claude Project Instructions

## Project Overview
AutoBlock is an open-source adaptive multi-layer rate limiting & auto-remediation platform.
It fills the gap between "return 429" and "push to WAF + notify + audit" in a single, cloud-portable, framework-agnostic package.

## Monorepo Structure
```
autoblock/
├── packages/core/          TypeScript — algorithms, FSM, Redis client (npm: @autoblock/core)
├── packages/express/       TypeScript — Express.js middleware (npm: @autoblock/express)
├── packages/fastapi/       Python 3.11+ — Starlette/FastAPI middleware (PyPI: autoblock)
├── packages/spring/        Java 21 — Spring Boot 3.x starter (Maven: io.autoblock)
├── engine/                 Go 1.22 — auto-remediation service (WAF push, notifier)
├── api/                    Go 1.22 — management REST API (chi router)
├── dashboards/             Grafana JSON + Prometheus alerts YAML
├── deploy/helm/autoblock/  Helm 3 chart
└── docker/                 docker-compose.yml for local dev
```

## Tech Stack Per Component

### packages/core & packages/express (TypeScript)
- Runtime: Node.js 20 LTS
- Language: TypeScript 5.x strict mode
- Redis client: ioredis (with Lua scripting for atomicity)
- Build: tsup (ESM + CJS dual output)
- Test: vitest + testcontainers (real Redis)
- Validation: zod for config schema
- Key rule: ALL rate limit counter operations MUST use Lua scripts (atomic)

### packages/fastapi (Python)
- Python 3.11+, asyncio-native
- Redis client: redis.asyncio (from redis-py 5+)
- Framework: Starlette middleware (works with FastAPI + bare Starlette)
- Test: pytest-asyncio + testcontainers-python
- Packaging: pyproject.toml (hatchling)

### packages/spring (Java)
- Java 21, Spring Boot 3.3+
- Redis client: Lettuce (async, reactive-capable)
- Use virtual threads: spring.threads.virtual.enabled=true
- Packaging: Maven, published as Spring Boot starter

### engine/ & api/ (Go)
- Go 1.22+
- Redis: github.com/redis/go-redis/v9
- AWS WAF: github.com/aws/aws-sdk-go-v2/service/wafv2
- Cloudflare: github.com/cloudflare/cloudflare-go
- Config: github.com/spf13/viper
- HTTP router (api/): github.com/go-chi/chi/v5
- Metrics: github.com/prometheus/client_golang
- Structured logging: log/slog (stdlib, Go 1.21+)
- Test: testify + dockertest

## Core Concepts

### Penalty State Machine
States: CLEAN → WARN → SLOW → BLOCK → BLACKLIST
- Score is accumulated per dimension (IP, UserID, endpoint) independently
- Each dimension has its own state; worst-case wins
- Score decays over time (configurable half-life)
- State transitions are stored in Redis with TTL

### Redis Key Schema
```
ab:{tenant}:sw:ip:{ip}:{endpoint_hash}          # sorted set (sliding window)
ab:{tenant}:tb:ip:{ip}:{endpoint_hash}          # hash (token bucket: tokens, last_refill)
ab:{tenant}:penalty:score:ip:{ip}               # string (integer, atomically incremented)
ab:{tenant}:penalty:state:ip:{ip}               # string (CLEAN|WARN|SLOW|BLOCK|BLACKLIST)
ab:{tenant}:penalty:history:ip:{ip}             # list (JSON events, capped at 100)
ab:{tenant}:blacklist:ip                        # sorted set (score = expiry unix ts)
ab:{tenant}:whitelist:ip                        # set
ab:{tenant}:waf:synced:ip:{ip}                  # hash (provider → synced_at)
ab:{tenant}:audit:stream                        # Redis Stream (XADD)
ab:{tenant}:rules:endpoint                      # hash (rule_id → JSON)
```

### WAF Provider Interface (Go)
```go
type WAFProvider interface {
    AddToBlocklist(ctx context.Context, ip string, ttl time.Duration, reason string) error
    RemoveFromBlocklist(ctx context.Context, ip string) error
    IsBlocked(ctx context.Context, ip string) (bool, error)
    HealthCheck(ctx context.Context) error
}
```

### Algorithm: Hybrid Sliding Window + Token Bucket
- Sliding window: catches sustained rate abuse (counts in a rolling time window)
- Token bucket: catches bursts (refills at constant rate, depletes on requests)
- BOTH must pass for a request to proceed — sliding window OR token bucket violation → penalty

## Conventions

### Naming
- Redis keys: always prefixed with `ab:{tenant}:`
- Go packages: lowercase, no underscores (e.g., `watcher`, `remediation`, `waf`)
- TypeScript: camelCase functions, PascalCase types/interfaces
- Config YAML keys: snake_case

### Error Handling
- Go: always wrap errors with context (`fmt.Errorf("watcher: %w", err)`)
- TypeScript: use Result type pattern (neverthrow library) for algorithmic code
- fail_open=true by default: Redis timeout → allow request, log warning

### Testing Strategy
- Unit tests: mock Redis with scripts/testcontainers
- Integration tests: real Redis via testcontainers (Node) / dockertest (Go)
- e2e: k6 load test scripts in tests/e2e/k6/
- All Lua scripts must have unit tests (mock KEYS/ARGV)

### Commit Convention
- feat(core): add hybrid algorithm
- feat(engine): aws-waf provider
- fix(express): ip extraction from x-forwarded-for
- test(core): sliding window edge cases
- docs: update configuration reference

## Local Development
```bash
# Start full local stack
docker compose -f docker/docker-compose.yml up -d

# Services:
# Redis        → localhost:6379
# AutoBlock API → localhost:8080
# AutoBlock Engine → (background service, no HTTP port)
# Prometheus   → localhost:9090
# Grafana      → localhost:3000 (admin/admin)
```

## MVP Implementation Order
1. packages/core — sliding window Lua script + penalty FSM
2. packages/express — Express middleware wrapping core
3. engine/ — Redis pub/sub watcher + AWS WAF provider + Slack notify
4. api/ — /status, /blacklist, /whitelist endpoints
5. docker/ — docker-compose.yml with Redis + engine + api + Grafana
6. dashboards/ — Grafana dashboard JSON
