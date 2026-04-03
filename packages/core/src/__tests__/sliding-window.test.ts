import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { GenericContainer, type StartedTestContainer } from 'testcontainers'
import Redis from 'ioredis'
import { SlidingWindow } from '../algorithms/sliding-window.js'
import { setupRedisCommands } from '../redis-setup.js'

describe('SlidingWindow (integration)', () => {
  let container: StartedTestContainer
  let redis: Redis

  beforeAll(async () => {
    container = await new GenericContainer('redis:7-alpine').withExposedPorts(6379).start()
    redis = new Redis({ port: container.getMappedPort(6379) })
    setupRedisCommands(redis)
  })

  afterAll(async () => {
    await redis.quit()
    await container.stop()
  })

  it('allows requests under the limit', async () => {
    const sw = new SlidingWindow(redis, { requests: 10, windowMs: 60_000 })
    const result = await sw.check('test:sw:under-limit')

    expect(result.isOk()).toBe(true)
    expect(result._unsafeUnwrap().allowed).toBe(true)
    expect(result._unsafeUnwrap().count).toBe(1)
  })

  it('blocks after limit is reached', async () => {
    const sw = new SlidingWindow(redis, { requests: 3, windowMs: 60_000 })
    const key = 'test:sw:limit-reached'

    await sw.check(key)
    await sw.check(key)
    await sw.check(key) // 3rd — exactly at limit

    const blocked = await sw.check(key) // 4th — over limit
    expect(blocked._unsafeUnwrap().allowed).toBe(false)
    expect(blocked._unsafeUnwrap().remaining).toBe(0)
  })

  it('counts remaining correctly', async () => {
    const sw = new SlidingWindow(redis, { requests: 5, windowMs: 60_000 })
    const key = 'test:sw:remaining'

    const r1 = await sw.check(key)
    expect(r1._unsafeUnwrap().remaining).toBe(4)

    const r2 = await sw.check(key)
    expect(r2._unsafeUnwrap().remaining).toBe(3)
  })

  it('different keys are independent', async () => {
    const sw = new SlidingWindow(redis, { requests: 2, windowMs: 60_000 })
    const key1 = 'test:sw:indep-1'
    const key2 = 'test:sw:indep-2'

    await sw.check(key1)
    await sw.check(key1) // key1 at limit

    const r = await sw.check(key2)
    expect(r._unsafeUnwrap().allowed).toBe(true) // key2 independent
  })
})
