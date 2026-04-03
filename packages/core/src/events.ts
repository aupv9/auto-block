import { EventEmitter } from 'node:events'
import type { PenaltyState, RequestContext, RateLimitDecision } from './types.js'

export interface BlocklistEvent {
  ip: string
  userId?: string
  state: PenaltyState
  previousState: PenaltyState
  score: number
  reason: string
  timestamp: Date
}

export interface RateLimitEvent {
  ctx: RequestContext
  decision: RateLimitDecision
  ruleId: string
}

export interface AutoBlockEvents {
  on(event: 'blacklisted', listener: (e: BlocklistEvent) => void): this
  on(event: 'stateChanged', listener: (e: BlocklistEvent) => void): this
  on(event: 'blocked', listener: (e: RateLimitEvent) => void): this
  on(event: 'allowed', listener: (e: RateLimitEvent) => void): this

  emit(event: 'blacklisted', e: BlocklistEvent): boolean
  emit(event: 'stateChanged', e: BlocklistEvent): boolean
  emit(event: 'blocked', e: RateLimitEvent): boolean
  emit(event: 'allowed', e: RateLimitEvent): boolean
}

export class AutoBlockEvents extends EventEmitter {}
