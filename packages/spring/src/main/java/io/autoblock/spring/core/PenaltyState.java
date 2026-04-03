package io.autoblock.spring.core;

import io.autoblock.spring.config.AutoBlockProperties.ThresholdProperties;

/**
 * Progressive penalty state for a single rate-limit dimension.
 * Mirrors PenaltyState in packages/core (TypeScript) and penalty_fsm.py (Python).
 *
 * Transitions: CLEAN → WARN → SLOW → BLOCK → BLACKLIST
 * Each state is entered when the accumulated penalty score crosses a threshold.
 */
public enum PenaltyState {
    /** No violations detected. Request passes through immediately. */
    CLEAN,
    /** Approaching limit. Request passes; warning header added. */
    WARN,
    /** Over limit. Request passes after artificial delay (typically 3s). */
    SLOW,
    /** Significantly over limit. Request rejected with 429 + Retry-After. */
    BLOCK,
    /** Persistent attacker. Request rejected with 403; IP pushed to WAF. */
    BLACKLIST;

    /** Derive state from numeric penalty score and configured thresholds. */
    public static PenaltyState fromScore(long score, ThresholdProperties t) {
        if (score >= t.blacklist()) return BLACKLIST;
        if (score >= t.block())     return BLOCK;
        if (score >= t.slow())      return SLOW;
        if (score >= t.warn())      return WARN;
        return CLEAN;
    }

    /** Parse the string value stored in Redis back to enum. */
    public static PenaltyState fromRedis(String value) {
        if (value == null || value.isBlank()) return CLEAN;
        return switch (value.toUpperCase()) {
            case "WARN"      -> WARN;
            case "SLOW"      -> SLOW;
            case "BLOCK"     -> BLOCK;
            case "BLACKLIST" -> BLACKLIST;
            default          -> CLEAN;
        };
    }

    public boolean requestAllowed()  { return this == CLEAN || this == WARN || this == SLOW; }
    public boolean shouldDelay()     { return this == SLOW; }
    public boolean shouldBlock()     { return this == BLOCK || this == BLACKLIST; }
    public boolean isForbidden()     { return this == BLACKLIST; }
    public int     httpStatus()      { return isForbidden() ? 403 : 429; }
}
