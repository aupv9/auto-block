import type { Redis } from 'ioredis'
import { Result, ok, err } from 'neverthrow'
import { trace, SpanStatusCode } from '@opentelemetry/api'
import { KeyBuilder } from './key-builder.js'
import { SlidingWindow } from './algorithms/sliding-window.js'
import { TokenBucket } from './algorithms/token-bucket.js'
import { HybridAlgorithm } from './algorithms/hybrid.js'
import { PenaltyStateMachine, DEFAULT_THRESHOLDS } from './penalty-state-machine.js'
import { AutoBlockEvents, type BlocklistEvent } from './events.js'
import { setupRedisCommands } from './redis-setup.js'
import type {
  AutoBlockConfig,
  AutoBlockError,
  RateLimitDecision,
  RequestContext,
  RuleConfig,
  PenaltyThresholds,
  PenaltyState,
} from './types.js'

// ---------------------------------------------------------------------------
// CIDR helpers (IPv4 only — covers the most common ops-facing use cases)
// ---------------------------------------------------------------------------

function ipv4ToNum(ip: string): number {
  return ip.split('.').reduce((acc, oct) => ((acc << 8) | parseInt(oct, 10)) >>> 0, 0) >>> 0
}

function ipInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf('/')
  if (slash === -1) return ip === cidr
  const bits = parseInt(cidr.slice(slash + 1), 10)
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return (ipv4ToNum(ip) & mask) === (ipv4ToNum(cidr.slice(0, slash)) & mask)
}

const ALLOW_ALL: RateLimitDecision = {
  allowed: true,
  state: 'CLEAN',
  score: 0,
  limit: Infinity,
  remaining: Infinity,
}

const STATE_PRIORITY: Record<PenaltyState, number> = {
  BLACKLIST: 5,
  BLOCK: 4,
  SLOW: 3,
  WARN: 2,
  CLEAN: 1,
}

const DEFAULT_MIDDLEWARE = {
  failOpen: true,
  skipPaths: ['/health', '/ready', '/favicon.ico'],
  trustProxy: true,
  trustedProxyDepth: 1,
  ipHeader: 'x-forwarded-for',
  userIdExtractor: 'none' as const,
}

export class RateLimiter {
  readonly events: AutoBlockEvents

  /** Expose tenant so RulesWatcher can build the correct Redis key. */
  get tenant(): string { return this.config.tenant }

  private readonly keys: KeyBuilder
  private readonly fsm: PenaltyStateMachine
  // Not readonly — RulesWatcher atomically replaces this reference.
  private compiledRules: Array<{ rule: RuleConfig; pattern: RegExp }>

  // In-memory CIDR cache refreshed every 30 s
  private blacklistCidrs: string[] = []
  private whitelistCidrs: string[] = []
  private cidrRefreshTimer?: ReturnType<typeof setInterval>

  constructor(
    private readonly redis: Redis,
    private readonly config: AutoBlockConfig,
  ) {
    setupRedisCommands(redis)

    this.keys = new KeyBuilder(config.tenant)
    this.events = new AutoBlockEvents()
    this.compiledRules = this.compileRules(config.rules)

    this.fsm = new PenaltyStateMachine(
      redis,
      this.globalThresholds(),
      config.rules[0]?.penalties.ttlSeconds ?? 86400,
    )

    void this.refreshCidrCache()
    this.cidrRefreshTimer = setInterval(() => void this.refreshCidrCache(), 30_000)
    this.cidrRefreshTimer.unref?.()
  }

  /** Stop background CIDR refresh. Call during graceful shutdown. */
  destroy(): void {
    if (this.cidrRefreshTimer !== undefined) clearInterval(this.cidrRefreshTimer)
  }

  private async refreshCidrCache(): Promise<void> {
    try {
      this.blacklistCidrs = await this.redis.smembers(this.keys.blacklistCidr())
    } catch { /* fail open */ }
    try {
      this.whitelistCidrs = await this.redis.smembers(this.keys.whitelistCidr())
    } catch { /* fail open */ }
  }

  /**
   * Atomically swap the active rules with a new set loaded from Redis.
   * Static rules from config are kept as fallback when dynamic is empty.
   * Called by RulesWatcher on each poll cycle.
   */
  mergeRules(dynamic: RuleConfig[]): void {
    const merged = [
      ...dynamic,
      // keep static rules that have no matching id in the dynamic set
      ...this.config.rules.filter(s => !dynamic.some(d => d.id === s.id)),
    ]
    this.compiledRules = this.compileRules(merged)
  }

  private compileRules(rules: RuleConfig[]): Array<{ rule: RuleConfig; pattern: RegExp }> {
    return rules
      .filter(r => r.enabled)
      .map(rule => ({ rule, pattern: new RegExp(rule.endpointPattern) }))
  }

  async check(ctx: RequestContext): Promise<Result<RateLimitDecision, AutoBlockError>> {
    const tracer = trace.getTracer('autoblock')
    return tracer.startActiveSpan('autoblock.evaluate', async span => {
      span.setAttributes({
        'autoblock.tenant': this.config.tenant,
        'autoblock.ip': ctx.ip,
        'autoblock.endpoint': ctx.endpoint,
      })
      try {
        const result = await this.doCheck(ctx)
        if (result.isOk()) {
          span.setAttributes({
            'autoblock.allowed': result.value.allowed,
            'autoblock.state': result.value.state,
          })
          if (!result.value.allowed) span.setStatus({ code: SpanStatusCode.ERROR, message: 'request blocked' })
        }
        return result
      } finally {
        span.end()
      }
    })
  }

  private async doCheck(ctx: RequestContext): Promise<Result<RateLimitDecision, AutoBlockError>> {
    const mw = { ...DEFAULT_MIDDLEWARE, ...this.config.middleware }

    if (mw.skipPaths.some(p => ctx.endpoint === p)) return ok(ALLOW_ALL)

    try {
      if (await this.isWhitelisted(ctx.ip, ctx.userId)) return ok(ALLOW_ALL)

      if (await this.isBlacklisted(ctx.ip, ctx.userId)) {
        return ok({ allowed: false, state: 'BLACKLIST', score: 0, limit: 0, remaining: 0, statusCode: 403 })
      }

      const matched = this.matchRules(ctx)
      if (matched.length === 0) return ok(ALLOW_ALL)

      const decisions = await Promise.all(matched.map(rule => this.evaluateRule(ctx, rule)))
      const decision = this.worstCase(decisions)

      if (!decision.allowed) {
        this.events.emit('blocked', { ctx, decision, ruleId: matched[0]?.id ?? '' })
      }

      return ok(decision)
    } catch (cause) {
      if (mw.failOpen) return ok(ALLOW_ALL)
      return err({ type: 'REDIS_ERROR', cause: cause as Error })
    }
  }

  // ---------------------------------------------------------------------------
  // Blacklist / whitelist management (used by engine + management API)
  // ---------------------------------------------------------------------------

  async addToBlacklist(ip: string, ttlSeconds: number, reason = 'manual'): Promise<void> {
    const expiryTs = ttlSeconds === 0 ? 0 : Math.floor(Date.now() / 1000) + ttlSeconds
    await this.redis.zadd(this.keys.blacklist('ip'), expiryTs, ip)
  }

  async removeFromBlacklist(ip: string): Promise<void> {
    await this.redis.zrem(this.keys.blacklist('ip'), ip)
  }

  async addToWhitelist(ip: string): Promise<void> {
    await this.redis.sadd(this.keys.whitelist('ip'), ip)
  }

  async removeFromWhitelist(ip: string): Promise<void> {
    await this.redis.srem(this.keys.whitelist('ip'), ip)
  }

  // CIDR management
  async addCidrToBlacklist(cidr: string): Promise<void> {
    await this.redis.sadd(this.keys.blacklistCidr(), cidr)
    this.blacklistCidrs = [...this.blacklistCidrs.filter(c => c !== cidr), cidr]
  }

  async removeCidrFromBlacklist(cidr: string): Promise<void> {
    await this.redis.srem(this.keys.blacklistCidr(), cidr)
    this.blacklistCidrs = this.blacklistCidrs.filter(c => c !== cidr)
  }

  async addCidrToWhitelist(cidr: string): Promise<void> {
    await this.redis.sadd(this.keys.whitelistCidr(), cidr)
    this.whitelistCidrs = [...this.whitelistCidrs.filter(c => c !== cidr), cidr]
  }

  async removeCidrFromWhitelist(cidr: string): Promise<void> {
    await this.redis.srem(this.keys.whitelistCidr(), cidr)
    this.whitelistCidrs = this.whitelistCidrs.filter(c => c !== cidr)
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async isWhitelisted(ip: string, userId?: string): Promise<boolean> {
    const pipe = this.redis.pipeline()
    pipe.sismember(this.keys.whitelist('ip'), ip)
    if (userId) pipe.sismember(this.keys.whitelist('uid'), userId)
    const results = await pipe.exec()
    if (results?.some(([, res]) => res === 1)) return true
    return this.whitelistCidrs.some(cidr => ipInCidr(ip, cidr))
  }

  private async isBlacklisted(ip: string, userId?: string): Promise<boolean> {
    const nowSec = Math.floor(Date.now() / 1000)
    const pipe = this.redis.pipeline()
    pipe.abBlacklistCheck(this.keys.blacklist('ip'), ip, nowSec)
    if (userId) pipe.abBlacklistCheck(this.keys.blacklist('uid'), userId, nowSec)
    const results = await pipe.exec()
    if (results?.some(([, res]) => res === 1)) return true
    return this.blacklistCidrs.some(cidr => ipInCidr(ip, cidr))
  }

  private matchRules(ctx: RequestContext): RuleConfig[] {
    return this.compiledRules
      .filter(({ rule, pattern }) => {
        if (!pattern.test(ctx.endpoint)) return false
        if (
          rule.methods.length > 0 &&
          !rule.methods.includes('*') &&
          !rule.methods.includes(ctx.method.toUpperCase())
        ) return false
        return true
      })
      .map(({ rule }) => rule)
  }

  private async evaluateRule(ctx: RequestContext, rule: RuleConfig): Promise<RateLimitDecision> {
    const epHash = this.keys.endpointHash(ctx.endpoint)
    const { requests, windowSeconds, burst } = rule.limits
    const windowMs = windowSeconds * 1000

    // Evaluate each dimension independently (worst-case across dimensions)
    const checks: Array<Promise<{ allowed: boolean; remaining: number }>> = []

    for (const dim of rule.dimensions) {
      if (dim === 'ip') {
        checks.push(this.checkDimension(rule, 'ip', ctx.ip, epHash, windowMs, requests, burst))
      } else if (dim === 'user_id' && ctx.userId) {
        checks.push(this.checkDimension(rule, 'uid', ctx.userId, epHash, windowMs, requests, burst))
      } else if (dim === 'endpoint') {
        checks.push(this.checkDimension(rule, 'ep', epHash, epHash, windowMs, requests, burst))
      }
    }

    if (checks.length === 0) return ALLOW_ALL

    const results = await Promise.all(checks)
    const allAllowed = results.every(r => r.allowed)
    const minRemaining = Math.min(...results.map(r => r.remaining))

    // Read current penalty state for IP
    const scoreKey = this.keys.penaltyScore('ip', ctx.ip)
    const stateKey = this.keys.penaltyState('ip', ctx.ip)
    const historyKey = this.keys.penaltyHistory('ip', ctx.ip)

    let penaltyState = await this.fsm.getState(stateKey)
    let score = await this.fsm.getScore(scoreKey)

    // Increment penalty on rate-limit violation
    if (!allAllowed) {
      const transition = await this.fsm.increment(scoreKey, stateKey, historyKey, 1, `rule:${rule.id}`)
      if (transition.isOk()) {
        penaltyState = transition.value.state
        score = transition.value.score

        if (transition.value.stateChanged) {
          const evt: BlocklistEvent = {
            ip: ctx.ip,
            userId: ctx.userId,
            state: transition.value.state,
            previousState: transition.value.previousState,
            score,
            reason: `rule:${rule.id}`,
            timestamp: new Date(),
          }
          this.events.emit('stateChanged', evt)
          if (transition.value.state === 'BLACKLIST') {
            this.events.emit('blacklisted', evt)
          }
        }
      }
    }

    return this.stateToDecision(penaltyState, score, requests, minRemaining, rule, allAllowed)
  }

  private stateToDecision(
    state: PenaltyState,
    score: number,
    limit: number,
    remaining: number,
    rule: RuleConfig,
    algorithmAllowed: boolean,
  ): RateLimitDecision {
    const p = rule.penalties

    switch (state) {
      case 'BLACKLIST':
        return { allowed: false, state, score, limit, remaining: 0, statusCode: 403 }

      case 'BLOCK':
        return {
          allowed: false,
          state,
          score,
          limit,
          remaining: 0,
          statusCode: 429,
          retryAfterSeconds: p.block?.durationSeconds ?? 300,
        }

      case 'SLOW':
        return {
          allowed: true,
          state,
          score,
          limit,
          remaining,
          delayMs: p.slow?.delayMs ?? 3000,
        }

      case 'WARN':
        return { allowed: true, state, score, limit, remaining }

      default: // CLEAN
        if (!algorithmAllowed) {
          return { allowed: false, state: 'CLEAN', score, limit, remaining: 0, statusCode: 429 }
        }
        return { allowed: true, state: 'CLEAN', score, limit, remaining }
    }
  }

  private async checkDimension(
    rule: RuleConfig,
    dimension: 'ip' | 'uid' | 'ep',
    value: string,
    epHash: string,
    windowMs: number,
    requests: number,
    burst: number,
  ): Promise<{ allowed: boolean; remaining: number }> {
    const failOpen = { allowed: true, remaining: requests }

    if (rule.algorithm === 'sliding_window') {
      const key = this.keys.slidingWindow(dimension, value, epHash)
      const result = await new SlidingWindow(this.redis, { requests, windowMs }).check(key)
      if (result.isErr()) return failOpen
      return { allowed: result.value.allowed, remaining: result.value.remaining }
    }

    if (rule.algorithm === 'token_bucket') {
      const key = this.keys.tokenBucket(dimension, value, epHash)
      const result = await new TokenBucket(this.redis, {
        capacity: burst || requests,
        refillRate: requests / (windowMs / 1000),
      }).check(key)
      if (result.isErr()) return failOpen
      return { allowed: result.value.allowed, remaining: result.value.tokensRemaining }
    }

    // hybrid (default)
    const swKey = this.keys.slidingWindow(dimension, value, epHash)
    const tbKey = this.keys.tokenBucket(dimension, value, epHash)
    const result = await new HybridAlgorithm(this.redis, { requests, windowMs, burst: burst || requests })
      .check(swKey, tbKey)
    if (result.isErr()) return failOpen
    return { allowed: result.value.allowed, remaining: result.value.remaining }
  }

  private worstCase(decisions: RateLimitDecision[]): RateLimitDecision {
    return decisions.reduce((worst, current) => {
      const cp = STATE_PRIORITY[current.state] ?? 0
      const wp = STATE_PRIORITY[worst.state] ?? 0
      return cp > wp ? current : worst
    }, decisions[0] ?? ALLOW_ALL)
  }

  private globalThresholds(): PenaltyThresholds {
    for (const rule of this.config.rules) {
      if (rule.penalties.thresholds) return rule.penalties.thresholds
      // Build from the first rule that has any explicit penalty steps
      if (rule.penalties.warn || rule.penalties.blacklist) {
        return {
          warn: rule.penalties.warn?.scoreThreshold ?? DEFAULT_THRESHOLDS.warn,
          slow: rule.penalties.slow?.scoreThreshold ?? DEFAULT_THRESHOLDS.slow,
          block: rule.penalties.block?.scoreThreshold ?? DEFAULT_THRESHOLDS.block,
          blacklist: rule.penalties.blacklist?.scoreThreshold ?? DEFAULT_THRESHOLDS.blacklist,
        }
      }
    }
    return DEFAULT_THRESHOLDS
  }
}
