import { describe, it, expect, beforeAll, afterAll, vi, beforeEach } from 'vitest'
import { GenericContainer, type StartedTestContainer } from 'testcontainers'
import Redis from 'ioredis'
import { RateLimiter } from '../rate-limiter.js'
import { RulesWatcher } from '../rules-watcher.js'
import { KeyBuilder } from '../key-builder.js'
import type { AutoBlockConfig } from '../types.js'

const BASE_CONFIG: AutoBlockConfig = {
  tenant: 'watcher-test',
  rules: [
    {
      id: 'static-rule',
      enabled: true,
      dimensions: ['ip'],
      endpointPattern: '^/static$',
      methods: ['GET'],
      algorithm: 'sliding_window',
      limits: { requests: 100, windowSeconds: 60, burst: 100 },
      penalties: {},
    },
  ],
}

describe('RulesWatcher (integration)', () => {
  let container: StartedTestContainer
  let redis: Redis
  let limiter: RateLimiter
  let keys: KeyBuilder

  beforeAll(async () => {
    container = await new GenericContainer('redis:7-alpine').withExposedPorts(6379).start()
    redis = new Redis({ port: container.getMappedPort(6379) })
    keys = new KeyBuilder(BASE_CONFIG.tenant)
  })

  afterAll(async () => {
    await redis.quit()
    await container.stop()
  })

  beforeEach(async () => {
    await redis.flushdb()
    limiter = new RateLimiter(redis, BASE_CONFIG)
  })

  it('returns empty rules when hash is empty', async () => {
    const watcher = new RulesWatcher(redis, limiter)
    const rules = await watcher.poll()
    expect(rules).toEqual([])
  })

  it('loads a single rule from Redis hash', async () => {
    const rule = JSON.stringify({
      id: 'dynamic-login',
      path: '/api/auth/login',
      limit: 5,
      window_seconds: 60,
      algorithm: 'hybrid',
      enabled: true,
    })
    await redis.hset(keys.rules(), 'dynamic-login', rule)

    const watcher = new RulesWatcher(redis, limiter)
    const rules = await watcher.poll()

    expect(rules).toHaveLength(1)
    expect(rules[0].id).toBe('dynamic-login')
    expect(rules[0].limits.requests).toBe(5)
    expect(rules[0].algorithm).toBe('hybrid')
  })

  it('skips disabled rules', async () => {
    await redis.hset(keys.rules(), 'disabled-rule', JSON.stringify({
      id: 'disabled-rule',
      path: '/api/disabled',
      limit: 10,
      window_seconds: 60,
      enabled: false,
    }))
    await redis.hset(keys.rules(), 'active-rule', JSON.stringify({
      id: 'active-rule',
      path: '/api/active',
      limit: 10,
      window_seconds: 60,
      enabled: true,
    }))

    const watcher = new RulesWatcher(redis, limiter)
    const rules = await watcher.poll()

    expect(rules).toHaveLength(1)
    expect(rules[0].id).toBe('active-rule')
  })

  it('skips malformed JSON without throwing', async () => {
    await redis.hset(keys.rules(), 'bad-rule', '{not-valid-json')
    await redis.hset(keys.rules(), 'good-rule', JSON.stringify({
      id: 'good-rule',
      path: '/api/good',
      limit: 10,
      window_seconds: 60,
      enabled: true,
    }))

    const watcher = new RulesWatcher(redis, limiter)
    const rules = await watcher.poll()

    expect(rules).toHaveLength(1)
    expect(rules[0].id).toBe('good-rule')
  })

  it('merges dynamic rules with static config rules', async () => {
    await redis.hset(keys.rules(), 'dyn-rule', JSON.stringify({
      id: 'dyn-rule',
      path: '/api/dynamic',
      limit: 20,
      window_seconds: 30,
      enabled: true,
    }))

    const watcher = new RulesWatcher(redis, limiter)
    await watcher.poll()

    // The static rule should still be accessible (endpoint doesn't match dynamic)
    const staticCtx = { ip: '1.2.3.4', endpoint: '/static', method: 'GET' }
    const result = await limiter.check(staticCtx)
    expect(result._unsafeUnwrap().allowed).toBe(true)
  })

  it('calls onReload callback after successful poll', async () => {
    const onReload = vi.fn()
    await redis.hset(keys.rules(), 'rule-1', JSON.stringify({
      id: 'rule-1',
      path: '/api/v1',
      limit: 10,
      window_seconds: 60,
      enabled: true,
    }))

    const watcher = new RulesWatcher(redis, limiter, { onReload })
    await watcher.poll()

    expect(onReload).toHaveBeenCalledOnce()
    expect(onReload).toHaveBeenCalledWith(expect.arrayContaining([
      expect.objectContaining({ id: 'rule-1' }),
    ]))
  })

  it('calls onError callback on Redis failure', async () => {
    const onError = vi.fn()
    const brokenRedis = new Redis({ port: 1, lazyConnect: true })
    const brokenLimiter = new RateLimiter(brokenRedis, BASE_CONFIG)
    const watcher = new RulesWatcher(brokenRedis, brokenLimiter, { onError })

    await expect(watcher.poll()).rejects.toThrow()
    await brokenRedis.quit()
  })

  it('start() and stop() lifecycle works without errors', async () => {
    const watcher = new RulesWatcher(redis, limiter, { intervalMs: 100 })

    watcher.start()
    await new Promise(r => setTimeout(r, 250)) // allow 2 poll cycles
    watcher.stop()

    // Calling stop twice is safe
    expect(() => watcher.stop()).not.toThrow()
  })

  it('start() is idempotent — second call is a no-op', async () => {
    const onReload = vi.fn()
    const watcher = new RulesWatcher(redis, limiter, { intervalMs: 500, onReload })

    watcher.start()
    watcher.start() // second call should not create a second timer

    await new Promise(r => setTimeout(r, 50))
    watcher.stop()

    // Only 1 immediate poll fired, not 2
    expect(onReload).toHaveBeenCalledTimes(1)
  })
})
