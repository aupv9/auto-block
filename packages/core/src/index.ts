// Types
export type {
  PenaltyState,
  PenaltyThresholds,
  RequestContext,
  RateLimitDecision,
  Dimension,
  Algorithm,
  LimitsConfig,
  PenaltyStepConfig,
  PenaltyConfig,
  RuleConfig,
  MiddlewareConfig,
  AutoBlockConfig,
  AutoBlockError,
} from './types.js'

// Core classes
export { KeyBuilder } from './key-builder.js'
export { setupRedisCommands } from './redis-setup.js'

// Algorithms
export { SlidingWindow } from './algorithms/sliding-window.js'
export type { SlidingWindowResult, SlidingWindowOptions } from './algorithms/sliding-window.js'

export { TokenBucket } from './algorithms/token-bucket.js'
export type { TokenBucketResult, TokenBucketOptions } from './algorithms/token-bucket.js'

export { HybridAlgorithm } from './algorithms/hybrid.js'
export type { HybridResult, HybridOptions } from './algorithms/hybrid.js'

// Penalty FSM
export { PenaltyStateMachine, DEFAULT_THRESHOLDS } from './penalty-state-machine.js'
export type { PenaltyTransitionResult } from './penalty-state-machine.js'

// Events
export { AutoBlockEvents } from './events.js'
export type { BlocklistEvent, RateLimitEvent } from './events.js'

// Main entry point
export { RateLimiter } from './rate-limiter.js'

// Hot-reload watcher
export { RulesWatcher } from './rules-watcher.js'
export type { RulesWatcherOptions } from './rules-watcher.js'

// Standalone score decay (no engine required)
export { DecayWorker } from './decay-worker.js'
export type { DecayWorkerOptions, DecayResult } from './decay-worker.js'
