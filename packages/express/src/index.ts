export { autoBlock } from './middleware.js'
export type { AutoBlockMiddlewareOptions, AutoBlockMiddleware } from './middleware.js'

export {
  extractIP,
  jwtSubExtractor,
  headerExtractor,
  buildUserIdExtractor,
} from './extractors.js'
export type { UserIdExtractor } from './extractors.js'

// Re-export core types so consumers only need @autoblock/express
export type {
  AutoBlockConfig,
  RuleConfig,
  RateLimitDecision,
  RequestContext,
  PenaltyState,
  BlocklistEvent,
  RateLimitEvent,
} from '@autoblock/core'
