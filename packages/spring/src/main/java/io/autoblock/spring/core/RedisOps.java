package io.autoblock.spring.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Low-level Redis operations using pre-compiled Lua scripts.
 *
 * All methods are synchronous and safe to call from virtual threads — Lettuce
 * uses non-blocking I/O under the hood but the blocking API is fine here since
 * Spring Boot's virtual-thread Tomcat will not pin platform threads.
 *
 * No {@code synchronized} blocks — concurrency is delegated to Redis atomicity.
 */
public final class RedisOps {

    private static final Logger log = LoggerFactory.getLogger(RedisOps.class);

    // Pre-compiled scripts (SHA cached by Spring Data Redis after first SCRIPT LOAD)
    private static final DefaultRedisScript<List> SLIDING_WINDOW_SCRIPT;
    private static final DefaultRedisScript<List> TOKEN_BUCKET_SCRIPT;
    private static final DefaultRedisScript<List> PENALTY_TRANSITION_SCRIPT;
    private static final DefaultRedisScript<List> BLACKLIST_CHECK_SCRIPT;

    static {
        SLIDING_WINDOW_SCRIPT    = script(LuaScripts.SLIDING_WINDOW);
        TOKEN_BUCKET_SCRIPT      = script(LuaScripts.TOKEN_BUCKET);
        PENALTY_TRANSITION_SCRIPT = script(LuaScripts.PENALTY_TRANSITION);
        BLACKLIST_CHECK_SCRIPT   = script(LuaScripts.BLACKLIST_CHECK);
    }

    private final StringRedisTemplate redis;

    public RedisOps(StringRedisTemplate redis) {
        this.redis = redis;
    }

    // ---- Sliding window --------------------------------------------------

    public record SlidingWindowResult(boolean allowed, long count, long remaining) {}

    public Optional<SlidingWindowResult> slidingWindow(
        String key, long windowMs, int limit
    ) {
        try {
            var now   = Instant.now().toEpochMilli();
            var reqId = UUID.randomUUID().toString();

            @SuppressWarnings("unchecked")
            List<Long> r = redis.execute(
                SLIDING_WINDOW_SCRIPT,
                List.of(key),
                String.valueOf(now),
                String.valueOf(windowMs),
                String.valueOf(limit),
                reqId
            );

            if (r == null || r.size() < 3) return Optional.empty();
            return Optional.of(new SlidingWindowResult(r.get(0) == 1L, r.get(1), r.get(2)));

        } catch (Exception e) {
            log.warn("slidingWindow Redis error for key={}: {}", key, e.getMessage());
            return Optional.empty();
        }
    }

    // ---- Token bucket ----------------------------------------------------

    public record TokenBucketResult(boolean allowed, long tokensRemaining, long capacity) {}

    public Optional<TokenBucketResult> tokenBucket(
        String key, int capacity, double refillRate, long windowMs
    ) {
        try {
            @SuppressWarnings("unchecked")
            List<Long> r = redis.execute(
                TOKEN_BUCKET_SCRIPT,
                List.of(key),
                String.valueOf(Instant.now().toEpochMilli()),
                String.valueOf(capacity),
                String.valueOf(refillRate),
                String.valueOf(windowMs)
            );

            if (r == null || r.size() < 3) return Optional.empty();
            return Optional.of(new TokenBucketResult(r.get(0) == 1L, r.get(1), r.get(2)));

        } catch (Exception e) {
            log.warn("tokenBucket Redis error for key={}: {}", key, e.getMessage());
            return Optional.empty();
        }
    }

    // ---- Penalty FSM -----------------------------------------------------

    public record PenaltyTransitionResult(long score, PenaltyState state) {}

    public Optional<PenaltyTransitionResult> penaltyTransition(
        String scoreKey,
        String stateKey,
        String historyKey,
        int increment,
        int warnT, int slowT, int blockT, int blacklistT,
        String reason,
        long ttlMs
    ) {
        try {
            @SuppressWarnings("unchecked")
            List<Object> r = redis.execute(
                PENALTY_TRANSITION_SCRIPT,
                List.of(scoreKey, stateKey, historyKey),
                String.valueOf(increment),
                String.valueOf(warnT),
                String.valueOf(slowT),
                String.valueOf(blockT),
                String.valueOf(blacklistT),
                reason,
                String.valueOf(ttlMs)
            );

            if (r == null || r.size() < 2) return Optional.empty();
            var score = ((Number) r.get(0)).longValue();
            var state = PenaltyState.fromRedis(r.get(1).toString());
            return Optional.of(new PenaltyTransitionResult(score, state));

        } catch (Exception e) {
            log.warn("penaltyTransition Redis error for scoreKey={}: {}", scoreKey, e.getMessage());
            return Optional.empty();
        }
    }

    // ---- Blacklist check -------------------------------------------------

    public record BlacklistResult(boolean blocked, long retryAfterSeconds) {}

    public Optional<BlacklistResult> blacklistCheck(String blacklistKey, String ip) {
        try {
            var nowSeconds = Instant.now().getEpochSecond();

            @SuppressWarnings("unchecked")
            List<Long> r = redis.execute(
                BLACKLIST_CHECK_SCRIPT,
                List.of(blacklistKey),
                ip,
                String.valueOf(nowSeconds)
            );

            if (r == null || r.size() < 2) return Optional.empty();
            return Optional.of(new BlacklistResult(r.get(0) == 1L, r.get(1)));

        } catch (Exception e) {
            log.warn("blacklistCheck Redis error for ip={}: {}", ip, e.getMessage());
            return Optional.empty();
        }
    }

    // ---- Hash operations (for hot-reload) --------------------------------

    /** Returns all field→value pairs from a Redis hash, or an empty map on error. */
    public java.util.Map<Object, Object> hGetAll(String key) {
        try {
            var result = redis.opsForHash().entries(key);
            return result != null ? result : java.util.Map.of();
        } catch (Exception e) {
            log.warn("hGetAll Redis error for key={}: {}", key, e.getMessage());
            return java.util.Map.of();
        }
    }

    // ---- Generic string get ----------------------------------------------

    public Optional<String> getString(String key) {
        try {
            return Optional.ofNullable(redis.opsForValue().get(key));
        } catch (Exception e) {
            log.warn("getString Redis error for key={}: {}", key, e.getMessage());
            return Optional.empty();
        }
    }

    // ---- Whitelist check -------------------------------------------------

    public boolean isWhitelisted(String whitelistKey, String ip) {
        try {
            return Boolean.TRUE.equals(redis.opsForSet().isMember(whitelistKey, ip));
        } catch (Exception e) {
            log.warn("whitelist check failed for ip={}: {}", ip, e.getMessage());
            return false;
        }
    }

    // ---- Set operations (CIDR lists) -------------------------------------

    /** Returns all members of a Redis set, or an empty set on error. */
    public Set<String> smembers(String key) {
        try {
            var result = redis.opsForSet().members(key);
            return result != null ? result : Set.of();
        } catch (Exception e) {
            log.warn("smembers Redis error for key={}: {}", key, e.getMessage());
            return Set.of();
        }
    }

    // ---- helpers ---------------------------------------------------------

    @SuppressWarnings("rawtypes")
    private static DefaultRedisScript<List> script(String lua) {
        var s = new DefaultRedisScript<List>();
        s.setScriptText(lua);
        s.setResultType(List.class);
        return s;
    }
}
