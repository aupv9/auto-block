# AutoBlock Spring Boot Starter

Spring Boot 3.x auto-configuration for [AutoBlock](../../) adaptive rate limiting. Supports both Spring MVC (servlet) and Spring WebFlux (reactive) stacks.

## Installation

```xml
<dependency>
  <groupId>io.autoblock</groupId>
  <artifactId>autoblock-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

Requires Java 21+ with `--enable-preview` (for `StructuredTaskScope`):

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-compiler-plugin</artifactId>
  <configuration>
    <compilerArgs>--enable-preview</compilerArgs>
  </configuration>
</plugin>
```

## Quick Start

Add to `application.yaml`:

```yaml
autoblock:
  enabled: true
  tenant: my-app
  trust-proxy: true
  trust-proxy-depth: 1
  hot-reload:
    enabled: true
    interval-seconds: 30
  decay:
    enabled: true
    half-life-seconds: 600   # 10 minutes
    interval-seconds: 60

  rules:
    - id: login-limit
      path: /api/auth/login
      methods: [POST]
      limit: 10
      window-seconds: 60
      algorithm: HYBRID
      penalties:
        warn-threshold: 3
        slow-threshold: 6
        slow-delay-ms: 2000
        block-threshold: 10
        block-duration-seconds: 300
        blacklist-threshold: 15
```

That's it — `AutoBlockAutoConfiguration` registers the filter automatically.

## Configuration Properties

### Core

| Property              | Default  | Description                                            |
|-----------------------|----------|--------------------------------------------------------|
| `autoblock.enabled`   | `true`   | Master switch.                                         |
| `autoblock.tenant`    | —        | Required. Namespaces all Redis keys.                   |
| `autoblock.trust-proxy` | `false` | Read client IP from `X-Forwarded-For`.               |
| `autoblock.trust-proxy-depth` | `1` | Number of trusted proxy hops.                     |
| `autoblock.fail-open` | `true`   | Allow requests when Redis is unavailable.              |

### Rules (`autoblock.rules[]`)

| Property           | Default       | Description                                    |
|--------------------|---------------|------------------------------------------------|
| `id`               | —             | Unique rule ID.                                |
| `path`             | —             | Ant-style path pattern (`/api/**`).            |
| `methods`          | `[*]`         | HTTP methods.                                  |
| `limit`            | —             | Max requests per window.                       |
| `window-seconds`   | —             | Sliding window duration.                       |
| `algorithm`        | `HYBRID`      | `SLIDING_WINDOW`, `TOKEN_BUCKET`, or `HYBRID`. |
| `per-user`         | `false`       | Enable per-user dimension.                     |
| `per-endpoint`     | `false`       | Scope counter to exact path.                   |

### Penalty thresholds (`autoblock.rules[].penalties`)

| Property                    | Default | Description                                     |
|-----------------------------|---------|-------------------------------------------------|
| `warn-threshold`            | `3`     | Penalty score to enter WARN state.              |
| `slow-threshold`            | `6`     | Penalty score to enter SLOW state.              |
| `slow-delay-ms`             | `2000`  | Artificial delay added in SLOW state (ms).      |
| `block-threshold`           | `10`    | Penalty score to enter BLOCK state (429).       |
| `block-duration-seconds`    | `300`   | Duration of BLOCK.                              |
| `blacklist-threshold`       | `15`    | Penalty score to enter BLACKLIST state (403).   |

### Hot-Reload (`autoblock.hot-reload`)

| Property                          | Default | Description                                  |
|-----------------------------------|---------|----------------------------------------------|
| `autoblock.hot-reload.enabled`    | `false` | Enable Redis hash polling for dynamic rules. |
| `autoblock.hot-reload.interval-seconds` | `30` | Poll interval.                          |

### Score Decay (`autoblock.decay`)

| Property                      | Default | Description                                       |
|-------------------------------|---------|---------------------------------------------------|
| `autoblock.decay.enabled`     | `false` | Enable standalone score decay.                    |
| `autoblock.decay.half-life-seconds` | `600` | Half-life for exponential decay.             |
| `autoblock.decay.interval-seconds` | `60` | How often to run a decay cycle.               |

## Spring Security Integration

When `spring-security-core` is on the classpath, AutoBlock automatically reads the authenticated principal from `SecurityContextHolder.getAuthentication().getName()` for per-user rate limiting. No configuration required — detected at runtime via reflection.

```java
// In a custom filter or controller — user is extracted automatically:
// SecurityContextHolder.getContext().getAuthentication().getName()
// → used as userId dimension
```

Anonymous users (`"anonymousUser"`) are treated as unauthenticated.

## Filter Order

The filter runs at order `-200` (before Spring Security's default `-100`). This ensures unauthenticated requests are checked against the IP dimension before security filters run.

To change the order:

```yaml
autoblock:
  filter-order: -300
```

## WebFlux (Reactive)

The starter auto-detects the stack. For WebFlux apps, `AutoBlockWebFilter` (which implements `WebFilter`) is registered instead of `AutoBlockFilter`. The blocking Redis call is offloaded to `Schedulers.boundedElastic()`.

## Custom User ID Extraction

Override `extractUserId` in a subclass:

```java
@Component
public class MyAutoBlockFilter extends AutoBlockFilter {
    public MyAutoBlockFilter(RateLimiter limiter, AutoBlockProperties props) {
        super(limiter, props);
    }

    @Override
    protected String extractUserId(HttpServletRequest request) {
        // e.g. from a custom JWT attribute
        return (String) request.getAttribute("jwtSubject");
    }
}
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

## Requirements

- Java 21+ (with `--enable-preview`)
- Spring Boot 3.3+
- Redis 7+
- `spring-data-redis` (included transitively)
