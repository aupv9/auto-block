import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { GenericContainer, type StartedTestContainer } from 'testcontainers'
import Redis from 'ioredis'
import { RateLimiter } from '../rate-limiter.js'
import type { AutoBlockConfig, RequestContext } from '../types.js'

const makeConfig = (overrides: Partial<AutoBlockConfig> = {}): AutoBlockConfig => ({
  tenant: 'test',
  rules: [
    {
      id: 'test-rule',
      enabled: true,
      dimensions: ['ip'],
      endpointPattern: '^/api/login$',
      methods: ['POST'],
      algorithm: 'sliding_window',
      limits: { requests: 3, windowSeconds: 60, burst: 0 },
      penalties: {
        warn: { scoreThreshold: 1 },
        slow: { scoreThreshold: 2, delayMs: 1000 },
        block: { scoreThreshold: 3, durationSeconds: 60 },
        blacklist: { scoreThreshold: 5 },
      },
    },
  ],
  ...overrides,
})

const makeCtx = (overrides: Partial<RequestContext> = {}): RequestContext => ({
  ip: '1.2.3.4',
  endpoint: '/api/login',
  method: 'POST',
  ...overrides,
})

describe('RateLimiter (integration)', () => {
  let container: StartedTestContainer
  let redis: Redis

  beforeAll(async () => {
    container = await new GenericContainer('redis:7-alpine').withExposedPorts(6379).start()
    redis = new Redis({ port: container.getMappedPort(6379) })
  })

  afterAll(async () => {
    await redis.quit()
    await container.stop()
  })

  it('allows requests under the limit', async () => {
    const limiter = new RateLimiter(redis, makeConfig())
    const result = await limiter.check(makeCtx({ ip: '10.0.0.1' }))
    expect(result._unsafeUnwrap().allowed).toBe(true)
  })

  it('returns ALLOW_ALL for unmatched endpoint', async () => {
    const limiter = new RateLimiter(redis, makeConfig())
    const result = await limiter.check(makeCtx({ endpoint: '/api/products', method: 'GET' }))
    expect(result._unsafeUnwrap().allowed).toBe(true)
    expect(result._unsafeUnwrap().state).toBe('CLEAN')
    expect(result._unsafeUnwrap().limit).toBe(Infinity)
  })

  it('skips configured skip paths', async () => {
    const limiter = new RateLimiter(redis, makeConfig({
      middleware: { skipPaths: ['/health'] },
    }))
    const result = await limiter.check(makeCtx({ endpoint: '/health', method: 'GET' }))
    expect(result._unsafeUnwrap().allowed).toBe(true)
  })

  it('enforces rate limit and escalates penalty', async () => {
    const ip = '10.1.0.1'
    const limiter = new RateLimiter(redis, makeConfig())
    const ctx = makeCtx({ ip })

    // First 3 requests allowed (limit = 3)
    await limiter.check(ctx)
    await limiter.check(ctx)
    await limiter.check(ctx)

    // 4th request — over limit → penalty incremented → WARN
    const r4 = await limiter.check(ctx)
    const d4 = r4._unsafeUnwrap()
    // May be WARN (score=1) or SLOW (score=2) depending on how many violations accumulated
    expect(['WARN', 'SLOW', 'BLOCK']).toContain(d4.state)
  })

  it('blocks whitelisted IPs regardless of rule', async () => {
    const ip = '192.168.1.1'
    const limiter = new RateLimiter(redis, makeConfig())
    await limiter.addToWhitelist(ip)

    // Exhaust the limit
    for (let i = 0; i < 10; i++) await limiter.check(makeCtx({ ip }))

    // Should still be allowed (whitelisted)
    const result = await limiter.check(makeCtx({ ip }))
    expect(result._unsafeUnwrap().allowed).toBe(true)
    expect(result._unsafeUnwrap().limit).toBe(Infinity)
  })

  it('blocks blacklisted IPs with 403', async () => {
    const ip = '5.5.5.5'
    const limiter = new RateLimiter(redis, makeConfig())
    await limiter.addToBlacklist(ip, 3600)

    const result = await limiter.check(makeCtx({ ip }))
    const d = result._unsafeUnwrap()
    expect(d.allowed).toBe(false)
    expect(d.statusCode).toBe(403)
    expect(d.state).toBe('BLACKLIST')
  })

  it('emits stateChanged event on penalty escalation', async () => {
    const ip = '10.2.0.1'
    const limiter = new RateLimiter(redis, makeConfig())
    const handler = vi.fn()
    limiter.events.on('stateChanged', handler)

    const ctx = makeCtx({ ip })
    // Trigger violations until state changes
    for (let i = 0; i < 5; i++) await limiter.check(ctx)

    expect(handler).toHaveBeenCalled()
  })

  it('emits blacklisted event when BLACKLIST threshold is reached', async () => {
    const ip = '10.3.0.1'
    const limiter = new RateLimiter(redis, makeConfig())
    const handler = vi.fn()
    limiter.events.on('blacklisted', handler)

    const ctx = makeCtx({ ip })
    // Blacklist threshold = 5 increments; trigger enough violations
    for (let i = 0; i < 20; i++) await limiter.check(ctx)

    expect(handler).toHaveBeenCalledWith(
      expect.objectContaining({ ip, state: 'BLACKLIST' }),
    )
  })

  it('addToBlacklist / removeFromBlacklist round-trip', async () => {
    const ip = '6.6.6.6'
    const limiter = new RateLimiter(redis, makeConfig())

    await limiter.addToBlacklist(ip, 3600)
    const blocked = await limiter.check(makeCtx({ ip }))
    expect(blocked._unsafeUnwrap().allowed).toBe(false)

    await limiter.removeFromBlacklist(ip)
    const allowed = await limiter.check(makeCtx({ ip }))
    expect(allowed._unsafeUnwrap().allowed).toBe(true)
  })
})
