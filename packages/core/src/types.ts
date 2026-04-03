export type PenaltyState = 'CLEAN' | 'WARN' | 'SLOW' | 'BLOCK' | 'BLACKLIST'

export interface PenaltyThresholds {
  warn: number
  slow: number
  block: number
  blacklist: number
}

export interface RequestContext {
  ip: string
  userId?: string
  endpoint: string
  method: string
  timestamp?: number
}

export interface RateLimitDecision {
  allowed: boolean
  state: PenaltyState
  score: number
  limit: number
  remaining: number
  retryAfterSeconds?: number
  delayMs?: number
  statusCode?: number
}

export type Dimension = 'ip' | 'user_id' | 'endpoint'

export type Algorithm = 'sliding_window' | 'token_bucket' | 'hybrid'

export interface LimitsConfig {
  requests: number
  windowSeconds: number
  burst: number
}

export interface PenaltyStepConfig {
  scoreThreshold: number
  actions?: string[]
  delayMs?: number
  durationSeconds?: number
  notify?: string[]
}

export interface PenaltyConfig {
  warn?: PenaltyStepConfig
  slow?: PenaltyStepConfig & { delayMs: number }
  block?: PenaltyStepConfig
  blacklist?: PenaltyStepConfig
  thresholds?: PenaltyThresholds
  ttlSeconds?: number
}

export interface RuleConfig {
  id: string
  enabled: boolean
  description?: string
  dimensions: Dimension[]
  endpointPattern: string
  methods: string[]
  algorithm: Algorithm
  limits: LimitsConfig
  penalties: PenaltyConfig
  tags?: string[]
}

export interface MiddlewareConfig {
  failOpen: boolean
  skipPaths: string[]
  trustProxy: boolean
  trustedProxyDepth: number
  ipHeader: string
  userIdExtractor: 'jwt_sub' | 'header' | 'none'
  userIdHeader?: string
}

export interface AutoBlockConfig {
  tenant: string
  rules: RuleConfig[]
  middleware?: Partial<MiddlewareConfig>
}

export interface AutoBlockError {
  type: 'REDIS_ERROR' | 'INVALID_CONFIG' | 'INVALID_INPUT'
  cause?: Error
  message?: string
}
