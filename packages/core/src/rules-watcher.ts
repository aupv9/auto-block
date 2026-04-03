import type { Redis } from 'ioredis'
import type { RateLimiter } from './rate-limiter.js'
import { KeyBuilder } from './key-builder.js'
import type { RuleConfig } from './types.js'

export interface RulesWatcherOptions {
  /** Poll interval in milliseconds. Default: 30 000 (30 s). */
  intervalMs?: number
  /** Called after each successful reload with the new dynamic rules. */
  onReload?: (rules: RuleConfig[]) => void
  /** Called when a Redis error occurs during polling. */
  onError?: (err: Error) => void
}

/**
 * RulesWatcher polls `ab:{tenant}:rules:endpoint` (Redis hash) every 30 s
 * and hot-reloads rate-limit rules into the associated RateLimiter without
 * requiring a service restart.
 *
 * Usage:
 *   const watcher = new RulesWatcher(redis, limiter)
 *   watcher.start()          // polls immediately, then every 30 s
 *   // later...
 *   watcher.stop()
 */
export class RulesWatcher {
  private timer?: ReturnType<typeof setInterval>
  private subscriber?: Redis
  private readonly keys: KeyBuilder

  constructor(
    private readonly redis: Redis,
    private readonly limiter: RateLimiter,
    private readonly opts: RulesWatcherOptions = {},
  ) {
    this.keys = new KeyBuilder(limiter.tenant)
  }

  /**
   * Start polling + pub/sub subscription. Idempotent.
   * An immediate poll fires before the first interval.
   * Pub/sub failures degrade gracefully to ticker-only mode.
   */
  start(): void {
    if (this.timer !== undefined) return // already running
    const interval = this.opts.intervalMs ?? 30_000

    const tick = (): void => {
      this.poll().catch(err => this.opts.onError?.(err as Error))
    }

    tick()
    this.timer = setInterval(tick, interval)
    if (typeof this.timer.unref === 'function') this.timer.unref()

    // Subscribe for push-based invalidation (best-effort).
    this.startSubscriber().catch(() => {
      // Pub/sub unavailable — ticker-only fallback already running.
    })
  }

  /** Stop polling and unsubscribe. */
  stop(): void {
    if (this.timer !== undefined) {
      clearInterval(this.timer)
      this.timer = undefined
    }
    if (this.subscriber !== undefined) {
      this.subscriber.disconnect()
      this.subscriber = undefined
    }
  }

  /** Perform a single poll cycle (also callable manually in tests). */
  async poll(): Promise<RuleConfig[]> {
    const raw = await this.redis.hgetall(this.keys.rules())
    const dynamic = parseDynamicRules(raw ?? {})
    this.limiter.mergeRules(dynamic)
    this.opts.onReload?.(dynamic)
    return dynamic
  }

  // ---- Pub/sub subscription ------------------------------------------------

  private async startSubscriber(): Promise<void> {
    // ioredis requires a dedicated connection for subscribe mode.
    this.subscriber = this.redis.duplicate()
    await this.subscriber.subscribe(this.keys.rulesChanged())

    this.subscriber.on('message', (_channel: string, _message: string) => {
      // Engine published a change — reload immediately.
      this.poll().catch(err => this.opts.onError?.(err as Error))
    })

    this.subscriber.on('error', () => {
      // Silently ignore — ticker fallback is still running.
    })
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function parseDynamicRules(raw: Record<string, string>): RuleConfig[] {
  const rules: RuleConfig[] = []
  for (const json of Object.values(raw)) {
    try {
      const r = JSON.parse(json) as Record<string, unknown>
      if (r['enabled'] === false) continue
      rules.push(mapRedisRule(r))
    } catch {
      // skip malformed JSON — engine writes are atomic, so this is rare
    }
  }
  return rules
}

function mapRedisRule(r: Record<string, unknown>): RuleConfig {
  const penalties = (r['penalties'] as RuleConfig['penalties'] | undefined) ?? {}
  return {
    id:              String(r['id'] ?? ''),
    enabled:         (r['enabled'] as boolean | undefined) ?? true,
    description:     r['description'] as string | undefined,
    dimensions:      (r['dimensions'] as RuleConfig['dimensions'] | undefined) ?? ['ip'],
    endpointPattern: String(r['path'] ?? r['endpoint_pattern'] ?? ''),
    methods:         (r['methods'] as string[] | undefined) ?? ['*'],
    algorithm:       (r['algorithm'] as RuleConfig['algorithm'] | undefined) ?? 'hybrid',
    limits: {
      requests:      Number(r['limit'] ?? 100),
      windowSeconds: Number(r['window_seconds'] ?? 60),
      burst:         Number(r['burst'] ?? r['limit'] ?? 100),
    },
    penalties,
    tags: (r['tags'] as string[] | undefined) ?? [],
  }
}
