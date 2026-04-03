package io.autoblock.spring.core;

/**
 * Sealed result of a rate-limit evaluation.
 *
 * Pattern match in the filter:
 * <pre>{@code
 * switch (decision) {
 *     case RateLimitDecision.Allow(var state, var remaining, var delayMs) -> {
 *         if (delayMs > 0) Thread.sleep(Duration.ofMillis(delayMs));
 *         chain.doFilter(req, res);
 *     }
 *     case RateLimitDecision.Deny(var state, var status, var retryAfter) ->
 *         sendDenyResponse(res, status, retryAfter, state);
 * }
 * }</pre>
 */
public sealed interface RateLimitDecision
    permits RateLimitDecision.Allow, RateLimitDecision.Deny {

    PenaltyState state();

    /**
     * Request is permitted to proceed. May include an artificial delay for SLOW state.
     *
     * @param state      current penalty state for this dimension
     * @param remaining  estimated remaining requests before hitting the limit
     * @param delayMs    milliseconds to sleep before forwarding (0 = none)
     */
    record Allow(
        PenaltyState state,
        int remaining,
        long delayMs
    ) implements RateLimitDecision {}

    /**
     * Request is denied. Caller should return the appropriate HTTP error.
     *
     * @param state             BLOCK (429) or BLACKLIST (403)
     * @param statusCode        HTTP status to return
     * @param retryAfterSeconds seconds until the client may retry (0 = permanent/unknown)
     */
    record Deny(
        PenaltyState state,
        int statusCode,
        long retryAfterSeconds
    ) implements RateLimitDecision {}

    // ---- Static factories ------------------------------------------------

    static Allow allow(PenaltyState state, int remaining) {
        return new Allow(state, remaining, state.shouldDelay() ? 3_000L : 0L);
    }

    static Allow allowClean(int remaining) {
        return new Allow(PenaltyState.CLEAN, remaining, 0L);
    }

    static Deny block(long retryAfterSeconds) {
        return new Deny(PenaltyState.BLOCK, 429, retryAfterSeconds);
    }

    static Deny blacklist() {
        return new Deny(PenaltyState.BLACKLIST, 403, 0L);
    }

    // ---- Helpers ---------------------------------------------------------

    default boolean isAllowed() { return this instanceof Allow; }
    default boolean isDenied()  { return this instanceof Deny; }
}
