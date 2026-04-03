package io.autoblock.spring.core;

import io.autoblock.spring.config.AutoBlockProperties;
import io.autoblock.spring.config.AutoBlockProperties.Algorithm;
import io.autoblock.spring.config.AutoBlockProperties.RuleProperties;
import io.autoblock.spring.config.AutoBlockProperties.ThresholdProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Main rate-limit orchestrator.
 *
 * Evaluation order per request:
 *  1. Whitelist check — skip everything, return ALLOW
 *  2. Blacklist check — return DENY immediately (no score increment needed)
 *  3. Match a rule against the request path
 *  4. Evaluate IP dimension + optional user dimension in parallel
 *     using {@link StructuredTaskScope} (JDK 21 preview)
 *  5. Worst-case penalty state wins across all evaluated dimensions
 *  6. Increment penalty score atomically via Lua
 *  7. Apply state: ALLOW / SLOW (delay) / BLOCK (429) / BLACKLIST (403)
 *
 * fail_open behaviour: any Redis error returns {@link RateLimitDecision#allowClean}
 * to avoid blocking legitimate traffic on infra failure.
 */
public class RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RateLimiter.class);

    /** 3-second artificial delay for SLOW state — same constant as other SDKs. */
    static final long SLOW_DELAY_MS = 3_000L;

    /** Default TTL for penalty keys: 24 hours. */
    private static final long PENALTY_TTL_MS = 24L * 60 * 60 * 1000;

    private final AutoBlockProperties          props;
    private final RedisOps                     redis;
    private final KeyBuilder                   keys;
    private final ThresholdProperties          thresholds;
    // AtomicReference allows RulesWatcher to hot-swap without locks.
    private final AtomicReference<List<CompiledRule>> rulesRef;
    // CopyOnWriteArrayList allows lock-free reads from request threads.
    private final CopyOnWriteArrayList<String> blacklistCidrs = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<String> whitelistCidrs = new CopyOnWriteArrayList<>();

    public RateLimiter(AutoBlockProperties props, RedisOps redis) {
        this.props      = props;
        this.redis      = redis;
        this.keys       = new KeyBuilder(props.tenant());
        this.thresholds = props.thresholds();
        this.rulesRef   = new AtomicReference<>(compile(props.rules()));
        refreshCidrCache();
        startCidrRefreshLoop();
    }

    /** Refresh the in-memory CIDR cache from Redis. Called on startup and every 30 s. */
    public void refreshCidrCache() {
        try {
            Set<String> bl = redis.smembers(keys.blacklistCidr());
            blacklistCidrs.clear();
            blacklistCidrs.addAll(bl);
        } catch (Exception e) {
            log.debug("CIDR blacklist refresh failed (fail_open): {}", e.getMessage());
        }
        try {
            Set<String> wl = redis.smembers(keys.whitelistCidr());
            whitelistCidrs.clear();
            whitelistCidrs.addAll(wl);
        } catch (Exception e) {
            log.debug("CIDR whitelist refresh failed (fail_open): {}", e.getMessage());
        }
    }

    private void startCidrRefreshLoop() {
        Thread.ofVirtual().name("autoblock-cidr-refresh").start(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(30_000);
                    refreshCidrCache();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        });
    }

    /** Returns true if {@code ip} falls within any CIDR in {@code cidrs}. */
    private static boolean ipInAnyCidr(String ip, List<String> cidrs) {
        if (cidrs.isEmpty()) return false;
        try {
            var addr = InetAddress.getByName(ip);
            for (String cidr : cidrs) {
                if (cidrContains(cidr, addr)) return true;
            }
        } catch (UnknownHostException ignored) { /* invalid IP — skip */ }
        return false;
    }

    private static boolean cidrContains(String cidr, InetAddress addr) {
        int slash = cidr.indexOf('/');
        if (slash < 0) {
            try { return InetAddress.getByName(cidr).equals(addr); }
            catch (UnknownHostException e) { return false; }
        }
        int prefixLen = Integer.parseInt(cidr.substring(slash + 1));
        try {
            var network = InetAddress.getByName(cidr.substring(0, slash));
            byte[] netBytes  = network.getAddress();
            byte[] addrBytes = addr.getAddress();
            if (netBytes.length != addrBytes.length) return false;
            int fullBytes = prefixLen / 8;
            int remainder = prefixLen % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (netBytes[i] != addrBytes[i]) return false;
            }
            if (remainder > 0 && fullBytes < netBytes.length) {
                int mask = (0xFF << (8 - remainder)) & 0xFF;
                return (netBytes[fullBytes] & mask) == (addrBytes[fullBytes] & mask);
            }
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Atomically replaces the active rule set.
     * Dynamic rules (from Redis) take priority; static config rules whose path
     * is not present in the dynamic set are kept as fallback.
     * Called by {@link io.autoblock.spring.core.RulesWatcher} every 30 s.
     */
    public void reloadRules(List<RuleProperties> dynamicRules) {
        var dynPaths = dynamicRules.stream().map(RuleProperties::path).collect(java.util.stream.Collectors.toSet());
        var merged   = new ArrayList<>(dynamicRules);
        if (props.rules() != null) {
            props.rules().stream()
                .filter(r -> !dynPaths.contains(r.path()))
                .forEach(merged::add);
        }
        rulesRef.set(compile(merged));
    }

    // ---- Public API ------------------------------------------------------

    /**
     * Evaluate the rate-limit decision for an incoming request.
     *
     * @param ip       client IP (after proxy trust processing)
     * @param userId   authenticated user ID, or null
     * @param endpoint normalized request path, e.g. "/api/auth/login"
     */
    public RateLimitDecision evaluate(String ip, String userId, String endpoint) {
        // 1. Whitelist — fast exit (exact IP or CIDR range)
        if (redis.isWhitelisted(keys.whitelist("ip"), ip) || ipInAnyCidr(ip, whitelistCidrs)) {
            return RateLimitDecision.allowClean(Integer.MAX_VALUE);
        }

        // 2. Blacklist — fast reject (exact IP or CIDR range)
        var blResult = redis.blacklistCheck(keys.blacklist("ip"), ip);
        if (blResult.isEmpty() && !props.failOpen()) {
            return RateLimitDecision.blacklist();
        }
        if ((blResult.isPresent() && blResult.get().blocked()) || ipInAnyCidr(ip, blacklistCidrs)) {
            return RateLimitDecision.blacklist();
        }

        // 3. Rule match
        var rule = matchRule(endpoint);
        if (rule == null) {
            return RateLimitDecision.allowClean(Integer.MAX_VALUE);
        }

        // 4-5. Parallel dimension evaluation via StructuredTaskScope
        try {
            return evaluateDimensions(ip, userId, endpoint, rule);
        } catch (Exception e) {
            if (props.failOpen()) {
                log.warn("Rate limit evaluation failed (fail_open=true), allowing request. error={}", e.getMessage());
                return RateLimitDecision.allowClean(0);
            }
            log.error("Rate limit evaluation failed (fail_open=false), denying request.", e);
            return RateLimitDecision.block(60L);
        }
    }

    // ---- Dimension evaluation --------------------------------------------

    @SuppressWarnings("preview")
    private RateLimitDecision evaluateDimensions(
        String ip, String userId, String endpoint, CompiledRule rule
    ) throws Exception {
        try (var scope = new StructuredTaskScope.ShutdownOnFailure()) {

            // Always evaluate IP dimension
            var ipTask = scope.fork(() -> evaluateIP(ip, endpoint, rule));

            // Optionally evaluate user dimension (rule.perUser + userId present)
            StructuredTaskScope.Subtask<DimensionResult> userTask = null;
            if (rule.props().perUser() && userId != null) {
                userTask = scope.fork(() -> evaluateUser(userId, endpoint, rule));
            }

            scope.join().throwIfFailed();

            var ipResult = ipTask.get();
            if (userTask != null) {
                var userResult = userTask.get();
                // Worst state across all dimensions
                return worstCase(ipResult, userResult, rule);
            }

            return toDecision(ipResult, ip, "ip", rule);
        }
    }

    private DimensionResult evaluateIP(String ip, String endpoint, CompiledRule rule) {
        var ep = rule.props().perEndpoint() ? endpoint : null;
        return checkAlgorithm(
            keys.slidingWindow("ip", ip, ep),
            keys.tokenBucket("ip", ip, ep),
            keys.penaltyScore("ip", ip),
            keys.penaltyState("ip", ip),
            keys.penaltyHistory("ip", ip),
            ip, "ip", rule
        );
    }

    private DimensionResult evaluateUser(String userId, String endpoint, CompiledRule rule) {
        var ep = rule.props().perEndpoint() ? endpoint : null;
        return checkAlgorithm(
            keys.slidingWindow("uid", userId, ep),
            keys.tokenBucket("uid", userId, ep),
            keys.penaltyScore("uid", userId),
            keys.penaltyState("uid", userId),
            keys.penaltyHistory("uid", userId),
            userId, "uid", rule
        );
    }

    /** Intermediate result from algorithm check before penalty FSM. */
    private record AlgoResult(boolean allowed, int remaining) {
        static AlgoResult failOpen()  { return new AlgoResult(true,  0); }
        static AlgoResult failClosed(){ return new AlgoResult(false, 0); }
    }

    private DimensionResult checkAlgorithm(
        String swKey, String tbKey,
        String scoreKey, String stateKey, String historyKey,
        String value, String dimension, CompiledRule rule
    ) {
        var r    = rule.props();
        var algo = runAlgorithm(r, swKey, tbKey);

        // Increment penalty if over limit
        if (!algo.allowed()) {
            var ptResult = redis.penaltyTransition(
                scoreKey, stateKey, historyKey,
                1,
                thresholds.warn(), thresholds.slow(), thresholds.block(), thresholds.blacklist(),
                "rate_exceeded:" + dimension + ":" + value,
                PENALTY_TTL_MS
            );
            var state = ptResult.map(RedisOps.PenaltyTransitionResult::state).orElse(PenaltyState.BLOCK);
            return new DimensionResult(false, state, algo.remaining(), dimension, value);
        }

        // Read current state even if allowed (might still be in WARN/SLOW from prior violations)
        var currentState = readCurrentState(stateKey);
        return new DimensionResult(true, currentState, algo.remaining(), dimension, value);
    }

    private AlgoResult runAlgorithm(RuleProperties r, String swKey, String tbKey) {
        return switch (r.algorithm()) {
            case SLIDING_WINDOW -> redis.slidingWindow(swKey, r.windowMs(), r.limit())
                .map(res -> new AlgoResult(res.allowed(), (int) res.remaining()))
                .orElseGet(() -> props.failOpen() ? AlgoResult.failOpen() : AlgoResult.failClosed());

            case TOKEN_BUCKET -> redis.tokenBucket(tbKey, r.limit(), (double) r.limit() / r.windowSeconds(), r.windowMs())
                .map(res -> new AlgoResult(res.allowed(), (int) res.tokensRemaining()))
                .orElseGet(() -> props.failOpen() ? AlgoResult.failOpen() : AlgoResult.failClosed());

            case HYBRID -> {
                var sw = redis.slidingWindow(swKey, r.windowMs(), r.limit());
                var tb = redis.tokenBucket(tbKey, r.limit(), (double) r.limit() / r.windowSeconds(), r.windowMs());
                if (sw.isEmpty() || tb.isEmpty()) {
                    yield props.failOpen() ? AlgoResult.failOpen() : AlgoResult.failClosed();
                }
                yield new AlgoResult(
                    sw.get().allowed() && tb.get().allowed(),
                    (int) Math.min(sw.get().remaining(), tb.get().tokensRemaining())
                );
            }
        };
    }

    private PenaltyState readCurrentState(String stateKey) {
        return redis.getString(stateKey)
            .map(PenaltyState::fromRedis)
            .orElse(PenaltyState.CLEAN);
    }

    // ---- Decision helpers ------------------------------------------------

    private RateLimitDecision toDecision(DimensionResult result, String ip, String dim, CompiledRule rule) {
        return switch (result.state()) {
            case CLEAN, WARN -> RateLimitDecision.allow(result.state(), result.remaining());
            case SLOW        -> new RateLimitDecision.Allow(PenaltyState.SLOW, result.remaining(), SLOW_DELAY_MS);
            case BLOCK       -> RateLimitDecision.block(rule.props().windowSeconds());
            case BLACKLIST   -> RateLimitDecision.blacklist();
        };
    }

    private RateLimitDecision worstCase(DimensionResult a, DimensionResult b, CompiledRule rule) {
        // Higher ordinal = worse state
        var worst = a.state().ordinal() >= b.state().ordinal() ? a : b;
        return toDecision(worst, worst.value(), worst.dimension(), rule);
    }

    // ---- Rule compilation ------------------------------------------------

    private CompiledRule matchRule(String path) {
        for (var rule : rulesRef.get()) {
            if (rule.pattern().matcher(path).matches()) return rule;
        }
        return null;
    }

    private static List<CompiledRule> compile(List<RuleProperties> ruleProps) {
        if (ruleProps == null) return List.of();
        return ruleProps.stream()
            .map(r -> new CompiledRule(r, toPattern(r.path())))
            .toList();
    }

    /** Convert an Ant-style path pattern to a regex (e.g. /api/** → /api/.*). */
    private static Pattern toPattern(String antPath) {
        var regex = antPath
            .replace(".", "\\.")
            .replace("**", ".+")
            .replace("*", "[^/]+");
        return Pattern.compile("^" + regex + "$");
    }

    // ---- Inner types -----------------------------------------------------

    private record CompiledRule(RuleProperties props, Pattern pattern) {}

    private record DimensionResult(
        boolean allowed,
        PenaltyState state,
        int remaining,
        String dimension,
        String value
    ) {}
}
