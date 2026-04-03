import { createHash } from 'node:crypto'

export class KeyBuilder {
  constructor(
    private readonly tenant: string,
    private readonly prefix = 'ab',
  ) {}

  private base(...parts: string[]): string {
    return [this.prefix, this.tenant, ...parts].join(':')
  }

  endpointHash(path: string): string {
    return createHash('sha256').update(path).digest('hex').slice(0, 8)
  }

  // Rate limit counters
  slidingWindow(dimension: 'ip' | 'uid' | 'ep', value: string, epHash?: string): string {
    return epHash
      ? this.base('sw', dimension, value, epHash)
      : this.base('sw', dimension, value)
  }

  tokenBucket(dimension: 'ip' | 'uid' | 'ep', value: string, epHash?: string): string {
    return epHash
      ? this.base('tb', dimension, value, epHash)
      : this.base('tb', dimension, value)
  }

  // Penalty tracking
  penaltyScore(dimension: 'ip' | 'uid', value: string): string {
    return this.base('penalty', 'score', dimension, value)
  }

  penaltyState(dimension: 'ip' | 'uid', value: string): string {
    return this.base('penalty', 'state', dimension, value)
  }

  penaltyHistory(dimension: 'ip' | 'uid', value: string): string {
    return this.base('penalty', 'history', dimension, value)
  }

  penaltyDecayTs(dimension: 'ip' | 'uid', value: string): string {
    return this.base('penalty', 'decay', dimension, value)
  }

  penaltyScorePattern(dimension: 'ip' | 'uid'): string {
    return this.base('penalty', 'score', dimension, '*')
  }

  // Allow/deny lists
  blacklist(type: 'ip' | 'uid'): string {
    return this.base('blacklist', type)
  }

  blacklistCidr(): string {
    return this.base('blacklist', 'cidr')
  }

  whitelist(type: 'ip' | 'uid'): string {
    return this.base('whitelist', type)
  }

  whitelistCidr(): string {
    return this.base('whitelist', 'cidr')
  }

  // Dynamic rules hash (managed by engine API, hot-reloaded by SDKs)
  rules(): string        { return this.base('rules', 'endpoint') }
  rulesChanged(): string { return this.base('rules', 'changed') }

  // Audit
  auditStream(): string {
    return this.base('audit', 'stream')
  }
}
