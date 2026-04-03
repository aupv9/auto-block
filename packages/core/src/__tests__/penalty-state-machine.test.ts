import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { GenericContainer, type StartedTestContainer } from 'testcontainers'
import Redis from 'ioredis'
import { PenaltyStateMachine, DEFAULT_THRESHOLDS } from '../penalty-state-machine.js'
import { setupRedisCommands } from '../redis-setup.js'

// ---------------------------------------------------------------------------
// Pure unit tests (no Redis)
// ---------------------------------------------------------------------------

describe('PenaltyStateMachine.scoreToState (pure)', () => {
  it.each([
    [0, 'CLEAN'],
    [2, 'CLEAN'],
    [3, 'WARN'],
    [5, 'WARN'],
    [6, 'SLOW'],
    [9, 'SLOW'],
    [10, 'BLOCK'],
    [14, 'BLOCK'],
    [15, 'BLACKLIST'],
    [999, 'BLACKLIST'],
  ] as const)('score %i → %s', (score, expected) => {
    expect(PenaltyStateMachine.scoreToState(score)).toBe(expected)
  })

  it('respects custom thresholds', () => {
    const custom = { warn: 5, slow: 10, block: 20, blacklist: 30 }
    expect(PenaltyStateMachine.scoreToState(4, custom)).toBe('CLEAN')
    expect(PenaltyStateMachine.scoreToState(7, custom)).toBe('WARN')
    expect(PenaltyStateMachine.scoreToState(15, custom)).toBe('SLOW')
    expect(PenaltyStateMachine.scoreToState(25, custom)).toBe('BLOCK')
    expect(PenaltyStateMachine.scoreToState(30, custom)).toBe('BLACKLIST')
  })
})

// ---------------------------------------------------------------------------
// Integration tests (real Redis via testcontainers)
// ---------------------------------------------------------------------------

describe('PenaltyStateMachine (integration)', () => {
  let container: StartedTestContainer
  let redis: Redis

  beforeAll(async () => {
    container = await new GenericContainer('redis:7-alpine').withExposedPorts(6379).start()
    redis = new Redis({ port: container.getMappedPort(6379), lazyConnect: false })
    setupRedisCommands(redis)
  })

  afterAll(async () => {
    await redis.quit()
    await container.stop()
  })

  it('starts at CLEAN with score 0', async () => {
    const fsm = new PenaltyStateMachine(redis)
    const state = await fsm.getState('ab:test:penalty:state:ip:10.0.0.1')
    const score = await fsm.getScore('ab:test:penalty:score:ip:10.0.0.1')
    expect(state).toBe('CLEAN')
    expect(score).toBe(0)
  })

  it('transitions CLEAN → WARN after reaching warn threshold', async () => {
    const fsm = new PenaltyStateMachine(redis, DEFAULT_THRESHOLDS)
    const scoreKey = 'ab:test:penalty:score:ip:10.0.0.2'
    const stateKey = 'ab:test:penalty:state:ip:10.0.0.2'
    const histKey = 'ab:test:penalty:history:ip:10.0.0.2'

    // Increment to warn threshold (3)
    const result = await fsm.increment(scoreKey, stateKey, histKey, 3, 'test')
    expect(result.isOk()).toBe(true)
    expect(result._unsafeUnwrap().state).toBe('WARN')
    expect(result._unsafeUnwrap().stateChanged).toBe(true)
    expect(result._unsafeUnwrap().previousState).toBe('CLEAN')
  })

  it('escalates through all states with cumulative increments', async () => {
    const fsm = new PenaltyStateMachine(redis, DEFAULT_THRESHOLDS)
    const scoreKey = 'ab:test:penalty:score:ip:10.0.0.3'
    const stateKey = 'ab:test:penalty:state:ip:10.0.0.3'
    const histKey = 'ab:test:penalty:history:ip:10.0.0.3'

    await fsm.increment(scoreKey, stateKey, histKey, 3)  // → WARN
    await fsm.increment(scoreKey, stateKey, histKey, 3)  // → SLOW (6)
    await fsm.increment(scoreKey, stateKey, histKey, 4)  // → BLOCK (10)
    const final = await fsm.increment(scoreKey, stateKey, histKey, 5) // → BLACKLIST (15)

    expect(final._unsafeUnwrap().state).toBe('BLACKLIST')
    expect(final._unsafeUnwrap().score).toBe(15)
  })

  it('records history (ring buffer capped at 100)', async () => {
    const fsm = new PenaltyStateMachine(redis, DEFAULT_THRESHOLDS)
    const scoreKey = 'ab:test:penalty:score:ip:10.0.0.4'
    const stateKey = 'ab:test:penalty:state:ip:10.0.0.4'
    const histKey = 'ab:test:penalty:history:ip:10.0.0.4'

    await fsm.increment(scoreKey, stateKey, histKey, 1, 'rule:login')
    await fsm.increment(scoreKey, stateKey, histKey, 1, 'rule:api')

    const history = await fsm.getHistory(histKey)
    expect(history.length).toBe(2)
    // LPUSH → newest first
    expect(history[0]?.reason).toBe('rule:api')
    expect(history[1]?.reason).toBe('rule:login')
  })
})
