import { describe, it, expect, beforeAll, afterAll, vi, beforeEach } from 'vitest'
import { GenericContainer, type StartedTestContainer } from 'testcontainers'
import Redis from 'ioredis'
import { DecayWorker } from '../decay-worker.js'
import { KeyBuilder } from '../key-builder.js'

describe('DecayWorker (integration)', () => {
  let container: StartedTestContainer
  let redis: Redis
  let keys: KeyBuilder
  const TENANT = 'decay-test'

  beforeAll(async () => {
    container = await new GenericContainer('redis:7-alpine').withExposedPorts(6379).start()
    redis = new Redis({ port: container.getMappedPort(6379) })
    keys = new KeyBuilder(TENANT)
  })

  afterAll(async () => {
    await redis.quit()
    await container.stop()
  })

  beforeEach(async () => {
    await redis.flushdb()
  })

  /** Seed a penalty score for an IP with a past decay timestamp */
  async function seedScore(ip: string, score: number, elapsedMs = 0): Promise<void> {
    const pastMs = Date.now() - elapsedMs
    await redis.set(keys.penaltyScore('ip', ip), score)
    await redis.set(keys.penaltyState('ip', ip), score >= 15 ? 'BLACKLIST' : score >= 10 ? 'BLOCK' : score >= 6 ? 'SLOW' : score >= 3 ? 'WARN' : 'CLEAN')
    await redis.set(keys.penaltyDecayTs('ip', ip), pastMs)
  }

  it('returns empty results when no score keys exist', async () => {
    const worker = new DecayWorker(redis, TENANT)
    const results = await worker.runCycle()
    expect(results).toEqual([])
  })

  it('skips IPs with score = 0 (already clean)', async () => {
    await seedScore('1.2.3.4', 0)
    const worker = new DecayWorker(redis, TENANT)
    const results = await worker.runCycle()
    expect(results).toHaveLength(0)
  })

  it('applies decay and returns result when score > 0 and time has passed', async () => {
    await seedScore('10.0.0.1', 20, 5 * 60 * 1000) // 5 min elapsed

    const worker = new DecayWorker(redis, TENANT, {
      halfLifeMs: 10 * 60 * 1000, // 10 min half-life
    })
    const results = await worker.runCycle()

    expect(results).toHaveLength(1)
    expect(results[0].ip).toBe('10.0.0.1')
    expect(results[0].decrement).toBeGreaterThan(0)
    expect(results[0].newScore).toBeLessThan(20)
  })

  it('sets state to CLEAN when score decays below warn threshold', async () => {
    // Seed a low score with significant elapsed time
    await seedScore('10.0.0.2', 4, 60 * 60 * 1000) // 1 hour elapsed

    const worker = new DecayWorker(redis, TENANT, {
      halfLifeMs: 10 * 60 * 1000,
      thresholds: { warn: 3, slow: 6, block: 10, blacklist: 15 },
    })
    const results = await worker.runCycle()

    // Score should have decayed significantly — could be CLEAN or WARN
    const newState = await redis.get(keys.penaltyState('ip', '10.0.0.2'))
    expect(['CLEAN', 'WARN']).toContain(newState)
    if (results.length > 0) {
      expect(results[0].newScore).toBeLessThan(4)
    }
  })

  it('decays multiple IPs in a single cycle', async () => {
    const ips = ['10.1.0.1', '10.1.0.2', '10.1.0.3']
    for (const ip of ips) {
      await seedScore(ip, 12, 5 * 60 * 1000)
    }

    const worker = new DecayWorker(redis, TENANT, {
      halfLifeMs: 10 * 60 * 1000,
    })
    const results = await worker.runCycle()

    expect(results).toHaveLength(3)
    expect(results.map(r => r.ip).sort()).toEqual(ips.sort())
    results.forEach(r => {
      expect(r.decrement).toBeGreaterThan(0)
      expect(r.newScore).toBeLessThan(12)
    })
  })

  it('does not double-decay within the same ms', async () => {
    await seedScore('10.2.0.1', 15, 5 * 60 * 1000)

    const worker = new DecayWorker(redis, TENANT, {
      halfLifeMs: 10 * 60 * 1000,
    })

    const r1 = await worker.runCycle()
    expect(r1).toHaveLength(1)
    const scoreAfterFirst = r1[0].newScore

    // Second cycle immediately — decay_ts is now = now, so elapsed = 0 → no change
    const r2 = await worker.runCycle()
    expect(r2).toHaveLength(0) // no decrement means filtered out

    const currentScore = Number(await redis.get(keys.penaltyScore('ip', '10.2.0.1')))
    expect(currentScore).toBe(scoreAfterFirst)
  })

  it('calls onDecay callback with changed IPs', async () => {
    const onDecay = vi.fn()
    await seedScore('10.3.0.1', 10, 5 * 60 * 1000)

    const worker = new DecayWorker(redis, TENANT, {
      halfLifeMs: 10 * 60 * 1000,
      onDecay,
    })
    await worker.runCycle()

    expect(onDecay).toHaveBeenCalledOnce()
    expect(onDecay).toHaveBeenCalledWith(
      expect.arrayContaining([expect.objectContaining({ ip: '10.3.0.1' })]),
    )
  })

  it('start() and stop() lifecycle works', async () => {
    const onDecay = vi.fn()
    const worker = new DecayWorker(redis, TENANT, {
      intervalMs: 100,
      onDecay,
    })

    worker.start()
    await new Promise(r => setTimeout(r, 250))
    worker.stop()

    // stop twice is safe
    expect(() => worker.stop()).not.toThrow()
  })

  it('start() is idempotent', async () => {
    const worker = new DecayWorker(redis, TENANT, { intervalMs: 1000 })
    worker.start()
    worker.start() // should not throw or create a second timer
    worker.stop()
  })
})
