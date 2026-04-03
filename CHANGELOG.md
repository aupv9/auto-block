# Changelog

All notable changes to AutoBlock are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- 6f: `scripts/bump-version.sh` — cross-SDK version bump + git tag helper
- 6f: `.github/workflows/release.yml` — tag-triggered publish to npm, PyPI, Maven Central
- 6e: OpenTelemetry tracing — `autoblock.evaluate` span in all 4 SDKs (Go, TypeScript, Python, Spring); no-op when OTel SDK not configured
- 6d: CIDR blacklist/whitelist — subnet-level blocking (`10.0.0.0/8`, `192.168.0.0/16`) in all SDKs; management API auto-detects CIDR notation in existing endpoints
- 6c: Push-based rule invalidation — engine publishes to `ab:{tenant}:rules:changed` on every rule write/delete; all SDK watchers subscribe for sub-second propagation (falls back to 30 s polling if pub/sub unavailable)
- 6b: Per-package READMEs for core, express, fastapi, spring, go with quick-start, config reference, and algorithm comparison tables
- 6a: Integration tests for `RulesWatcher` and `DecayWorker` in TypeScript, Python, and Go (testcontainers-based, real Redis)

---

## [0.1.0] — 2026-01-15

### Added

#### Core SDK (`@autoblock/core`, TypeScript)
- Hybrid sliding-window + token-bucket algorithm with Lua atomicity
- Penalty FSM: CLEAN → WARN → SLOW → BLOCK → BLACKLIST per dimension (IP, user ID, endpoint)
- `RulesWatcher` — hot-reload rules from Redis every 30 s
- `DecayWorker` — exponential half-life score decay
- IETF `RateLimit-*` headers + legacy `X-RateLimit-*` headers
- zod config validation, neverthrow Result types, fail_open semantics

#### Express Middleware (`@autoblock/express`)
- `createAutoBlockMiddleware()` — drop-in Express.js middleware
- Proxy trust, `X-Forwarded-For` chain parsing, configurable user ID extraction
- Exposes `limiter` for programmatic blacklist/whitelist management

#### FastAPI / Starlette Middleware (`autoblock`, Python)
- `AutoBlockMiddleware` — asyncio-native ASGI middleware
- `lifespan`-compatible startup/shutdown hooks for background workers
- JWT `sub` claim extraction, `httpx` test client integration

#### Spring Boot Starter (`autoblock-spring-boot-starter`, Java)
- `@ConditionalOnWebApplication` auto-configuration
- `AutoBlockFilter` extends `OncePerRequestFilter`, virtual-thread safe
- Spring Security integration via reflection (`SecurityContextHolder`)
- `StructuredTaskScope` for parallel IP + user dimension evaluation
- `application.yml` property binding via `@ConfigurationProperties`

#### Engine (`engine/`, Go)
- Redis pub/sub watcher for penalty score escalation to BLACKLIST
- AWS WAF provider: `AddToBlocklist`, `RemoveFromBlocklist`
- Cloudflare WAF provider: IP Access Rules API
- Nginx upstream blocklist file generator
- Slack notification on BLACKLIST state
- PagerDuty incident creation on BLACKLIST state
- Audit stream — `XADD` to `ab:{tenant}:audit:stream`

#### Management API (`api/`, Go)
- `GET/POST/DELETE /api/v1/blacklist/ip` — exact IP + CIDR range management
- `GET/POST/DELETE /api/v1/whitelist/ip` — exact IP + CIDR range management
- `GET/POST/PUT/DELETE /api/v1/rules` — dynamic rule CRUD with pub/sub invalidation
- `GET /api/v1/status` — health + tenant stats

#### Infrastructure
- `docker/docker-compose.yml` — full local stack (Redis, engine, API, Prometheus, Grafana)
- `deploy/helm/autoblock/` — production Helm 3 chart
- `dashboards/` — Grafana dashboard JSON + Prometheus alert rules
- `.github/workflows/` — CI for TypeScript, Python, Java, Go SDK, engine

#### Testing
- `tests/e2e/k6/` — baseline, brute-force, progressive-penalty, load-test scripts
- testcontainers integration tests in all 4 SDK languages
