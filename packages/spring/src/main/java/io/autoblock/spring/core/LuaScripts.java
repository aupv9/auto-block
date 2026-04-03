package io.autoblock.spring.core;

/**
 * Lua scripts for atomic Redis operations.
 *
 * These are byte-for-byte identical in logic to:
 *   - packages/core/src/redis-setup.ts  (TypeScript)
 *   - packages/fastapi/autoblock/scripts.py  (Python)
 *   - engine/internal/store/*.lua  (Go)
 *
 * All three SDKs share the same Redis key schema so they can coexist in the
 * same Redis instance without conflict or double-counting.
 */
public final class LuaScripts {

    private LuaScripts() {}

    /**
     * Sliding window rate limiter.
     *
     * KEYS[1] = sorted-set key (e.g. ab:tenant:sw:ip:1.2.3.4)
     * ARGV[1] = current time ms (Unix epoch)
     * ARGV[2] = window size ms
     * ARGV[3] = request limit within window
     * ARGV[4] = unique request ID (for ZADD dedup)
     *
     * Returns: {allowed (0|1), count_after, remaining}
     */
    public static final String SLIDING_WINDOW = """
            local key        = KEYS[1]
            local now        = tonumber(ARGV[1])
            local window_ms  = tonumber(ARGV[2])
            local limit      = tonumber(ARGV[3])
            local req_id     = ARGV[4]
            redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window_ms)
            local count   = redis.call('ZCARD', key)
            local allowed = count < limit and 1 or 0
            if allowed == 1 then
              redis.call('ZADD', key, now, req_id)
              redis.call('PEXPIRE', key, window_ms)
            end
            return {allowed, count + allowed, limit - count - allowed}
            """;

    /**
     * Token bucket rate limiter.
     *
     * KEYS[1] = hash key (e.g. ab:tenant:tb:ip:1.2.3.4)
     * ARGV[1] = current time ms
     * ARGV[2] = bucket capacity
     * ARGV[3] = refill rate (tokens/second)
     * ARGV[4] = TTL ms (expire after inactivity)
     *
     * Returns: {allowed (0|1), tokens_remaining, capacity}
     */
    public static final String TOKEN_BUCKET = """
            local key         = KEYS[1]
            local now         = tonumber(ARGV[1])
            local capacity    = tonumber(ARGV[2])
            local refill_rate = tonumber(ARGV[3])
            local window_ms   = tonumber(ARGV[4])
            local bucket      = redis.call('HMGET', key, 'tokens', 'last_refill')
            local tokens      = tonumber(bucket[1]) or capacity
            local last_refill = tonumber(bucket[2]) or now
            local elapsed     = now - last_refill
            local refill      = math.floor(elapsed * refill_rate / 1000)
            tokens = math.min(capacity, tokens + refill)
            if refill > 0 then last_refill = now end
            local allowed = tokens >= 1 and 1 or 0
            if allowed == 1 then tokens = tokens - 1 end
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
            redis.call('PEXPIRE', key, window_ms)
            return {allowed, tokens, capacity}
            """;

    /**
     * Increment penalty score and derive new FSM state atomically.
     *
     * KEYS[1] = penalty score key   (ab:tenant:penalty:score:ip:1.2.3.4)
     * KEYS[2] = penalty state key   (ab:tenant:penalty:state:ip:1.2.3.4)
     * KEYS[3] = history ring key    (ab:tenant:penalty:history:ip:1.2.3.4)
     * ARGV[1] = increment amount
     * ARGV[2] = warn threshold
     * ARGV[3] = slow threshold
     * ARGV[4] = block threshold
     * ARGV[5] = blacklist threshold
     * ARGV[6] = reason string (appended to history)
     * ARGV[7] = TTL ms
     *
     * Returns: {new_score (integer), new_state (string)}
     */
    public static final String PENALTY_TRANSITION = """
            local score_key      = KEYS[1]
            local state_key      = KEYS[2]
            local history_key    = KEYS[3]
            local increment      = tonumber(ARGV[1])
            local warn_t         = tonumber(ARGV[2])
            local slow_t         = tonumber(ARGV[3])
            local block_t        = tonumber(ARGV[4])
            local blacklist_t    = tonumber(ARGV[5])
            local reason         = ARGV[6]
            local ttl_ms         = tonumber(ARGV[7])
            local score = tonumber(redis.call('INCRBY', score_key, increment))
            local state
            if score >= blacklist_t then state = 'BLACKLIST'
            elseif score >= block_t then state = 'BLOCK'
            elseif score >= slow_t  then state = 'SLOW'
            elseif score >= warn_t  then state = 'WARN'
            else                         state = 'CLEAN' end
            redis.call('SET', state_key, state, 'PX', ttl_ms)
            redis.call('LPUSH', history_key, reason)
            redis.call('LTRIM', history_key, 0, 9)
            redis.call('PEXPIRE', score_key, ttl_ms)
            return {score, state}
            """;

    /**
     * Check whether an IP is in the blacklist sorted set (lazy expiry).
     *
     * KEYS[1] = blacklist sorted-set key (ab:tenant:blacklist:ip)
     * ARGV[1] = IP address
     * ARGV[2] = current time (Unix seconds) for TTL comparison
     *
     * Returns: {is_blocked (0|1), retry_after_seconds (-1 = permanent/not blocked)}
     */
    public static final String BLACKLIST_CHECK = """
            local key    = KEYS[1]
            local member = ARGV[1]
            local now    = tonumber(ARGV[2])
            local score  = redis.call('ZSCORE', key, member)
            if not score then return {0, -1} end
            score = tonumber(score)
            if score == 0 then return {1, 0} end
            if score > now then return {1, math.floor(score - now)} end
            redis.call('ZREM', key, member)
            return {0, -1}
            """;
}
