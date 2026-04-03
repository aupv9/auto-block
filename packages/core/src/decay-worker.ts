import type { Redis } from 'ioredis'
import { KeyBuilder } from './key-builder.js'
import type { PenaltyThresholds } from './types.js'
import { DEFAULT_THRESHOLDS } from './penalty-state-machine.js'

// ---------------------------------------------------------------------------
// Lua script — identical to engine/internal/store/decay.go scoreDecayLua
// ---------------------------------------------------------------------------
const LUA_DECAY = `
local score_key    = KEYS[1]
local state_key    = KEYS[2]
local decay_ts_key = KEYS[3]
local now          = tonumber(ARGV[1])
local half_life_ms = tonumber(ARGV[2])
local warn_t       = tonumber(ARGV[3])
local slow_t       = tonumber(ARGV[4])
local block_t      = tonumber(ARGV[5])
local blacklist_t  = tonumber(ARGV[6])

local raw = redis.call('GET', score_key)
if not raw then return {0, 'CLEAN', 0} end
local score = tonumber(raw)
if score <= 0 then return {0, 'CLEAN', 0} end

local last_decay = tonumber(redis.call('GET', decay_ts_key) or tostring(now))
local elapsed = now - last_decay
if elapsed <= 0 then
  return {score, redis.call('GET', state_key) or 'CLEAN', 0}
end

local factor    = math.exp(-0.693147 * elapsed / half_life_ms)
local new_score = math.floor(score * factor)
if new_score < 0 then new_score = 0 end
local decrement = score - new_score

redis.call('SET', decay_ts_key, now)

if decrement <= 0 then
  return {score, redis.call('GET', state_key) or 'CLEAN', 0}
end

redis.call('SET', score_key, new_score)

local state
if     new_score >= blacklist_t then state = 'BLACKLIST'
elseif new_score >= block_t     then state = 'BLOCK'
elseif new_score >= slow_t      then state = 'SLOW'
elseif new_score >= warn_t      then state = 'WARN'
else                                  state = 'CLEAN'
end

redis.call('SET', state_key, state)
return {new_score, state, decrement}
`

export interface DecayResult {
  ip: string
  newScore: number
  newState: string
  decrement: number
}

export interface DecayWorkerOptions {
  /** Half-life for exponential score decay. Default: 10 minutes. */
  halfLifeMs?: number
  /** How often to run a decay cycle. Default: 60 000 ms (1 minute). */
  intervalMs?: number
  thresholds?: PenaltyThresholds
  onDecay?: (results: DecayResult[]) => void
  onError?: (err: Error) => void
}

/**
 * DecayWorker periodically scans penalty score keys in Redis and applies
 * exponential half-life decay — allowing IPs to "cool down" over time
 * without requiring the Go engine.
 *
 * Usage (standalone / no engine):
 *   const worker = new DecayWorker(redis, { tenant: 'my-app' })
 *   worker.start()
 *   // on shutdown:
 *   worker.stop()
 */
export class DecayWorker {
  private timer?: ReturnType<typeof setInterval>
  private readonly keys: KeyBuilder
  private readonly halfLifeMs: number
  private readonly intervalMs: number
  private readonly thresholds: PenaltyThresholds

  constructor(
    private readonly redis: Redis,
    private readonly tenant: string,
    private readonly opts: DecayWorkerOptions = {},
  ) {
    this.keys = new KeyBuilder(tenant)
    this.halfLifeMs = opts.halfLifeMs ?? 10 * 60 * 1000
    this.intervalMs = opts.intervalMs ?? 60_000
    this.thresholds = opts.thresholds ?? DEFAULT_THRESHOLDS
  }

  /** Start periodic decay. Fires immediately, then every intervalMs. */
  start(): void {
    if (this.timer !== undefined) return
    const tick = (): void => {
      this.runCycle().catch(err => this.opts.onError?.(err as Error))
    }
    tick()
    this.timer = setInterval(tick, this.intervalMs)
    if (typeof this.timer.unref === 'function') this.timer.unref()
  }

  stop(): void {
    if (this.timer !== undefined) {
      clearInterval(this.timer)
      this.timer = undefined
    }
  }

  /** Run a single decay cycle — callable directly in tests. */
  async runCycle(): Promise<DecayResult[]> {
    const ips = await this.scanIPs()
    if (ips.length === 0) return []

    const results = await Promise.all(ips.map(ip => this.decayOne(ip)))
    const changed = results.filter((r): r is DecayResult => r !== null && r.decrement > 0)

    if (changed.length > 0) this.opts.onDecay?.(changed)
    return changed
  }

  // -------------------------------------------------------------------------

  private async scanIPs(): Promise<string[]> {
    const pattern = this.keys.penaltyScorePattern('ip')
    const prefix  = this.keys.penaltyScore('ip', '')
    const ips: string[] = []

    let cursor = '0'
    do {
      const [next, keys] = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100)
      cursor = next
      for (const key of keys) {
        const ip = key.slice(prefix.length)
        if (ip) ips.push(ip)
      }
    } while (cursor !== '0')

    return ips
  }

  private async decayOne(ip: string): Promise<DecayResult | null> {
    const t = this.thresholds
    const res = await this.redis.eval(
      LUA_DECAY,
      3,
      this.keys.penaltyScore('ip', ip),
      this.keys.penaltyState('ip', ip),
      this.keys.penaltyDecayTs('ip', ip),
      Date.now(),
      this.halfLifeMs,
      t.warn,
      t.slow,
      t.block,
      t.blacklist,
    ) as [number, string, number]

    if (!Array.isArray(res) || res.length < 3) return null
    return {
      ip,
      newScore:  Number(res[0]),
      newState:  String(res[1]),
      decrement: Number(res[2]),
    }
  }
}
