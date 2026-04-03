package io.autoblock.spring.core;

import io.autoblock.spring.config.AutoBlockProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Periodically scans penalty score keys and applies exponential half-life
 * decay so IPs "cool down" over time without requiring the Go engine.
 *
 * <p>Uses a virtual thread for zero platform-thread overhead.
 * Wire it as an optional bean via {@link io.autoblock.spring.AutoBlockAutoConfiguration}.
 */
public class DecayWorker implements InitializingBean, DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(DecayWorker.class);

    // Identical to engine/internal/store/decay.go scoreDecayLua
    private static final String LUA_DECAY = """
        local score_key    = KEYS[1]
        local state_key    = KEYS[2]
        local decay_ts_key = KEYS[3]
        local now          = tonumber(ARGV[1])
        local half_life_ms = tonumber(ARGV[2])
        local warn_t       = tonumber(ARGV[3])
        local slow_t       = tonumber(ARGV[4])
        local block_t      = tonumber(ARGV[5])
        local blacklist_t  = tonumber(ARGV[6])

        local raw = redis.call('GET', score_key)
        if not raw then return {0, 'CLEAN', 0} end
        local score = tonumber(raw)
        if score <= 0 then return {0, 'CLEAN', 0} end

        local last_decay = tonumber(redis.call('GET', decay_ts_key) or tostring(now))
        local elapsed = now - last_decay
        if elapsed <= 0 then
          return {score, redis.call('GET', state_key) or 'CLEAN', 0}
        end

        local factor    = math.exp(-0.693147 * elapsed / half_life_ms)
        local new_score = math.floor(score * factor)
        if new_score < 0 then new_score = 0 end
        local decrement = score - new_score

        redis.call('SET', decay_ts_key, now)

        if decrement <= 0 then
          return {score, redis.call('GET', state_key) or 'CLEAN', 0}
        end

        redis.call('SET', score_key, new_score)

        local state
        if     new_score >= blacklist_t then state = 'BLACKLIST'
        elseif new_score >= block_t     then state = 'BLOCK'
        elseif new_score >= slow_t      then state = 'SLOW'
        elseif new_score >= warn_t      then state = 'WARN'
        else                                  state = 'CLEAN'
        end

        redis.call('SET', state_key, state)
        return {new_score, state, decrement}
        """;

    @SuppressWarnings("rawtypes")
    private static final DefaultRedisScript<List> DECAY_SCRIPT;

    static {
        DECAY_SCRIPT = new DefaultRedisScript<>();
        DECAY_SCRIPT.setScriptText(LUA_DECAY);
        DECAY_SCRIPT.setResultType(List.class);
    }

    public record DecayResult(String ip, int newScore, String newState, int decrement) {}

    private final StringRedisTemplate          redis;
    private final KeyBuilder                   keys;
    private final AutoBlockProperties.ThresholdProperties thresholds;
    private final long                         halfLifeMs;
    private final Duration                     interval;
    private final Consumer<List<DecayResult>>  onDecay;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile Thread workerThread;

    public DecayWorker(
        StringRedisTemplate redis,
        AutoBlockProperties props
    ) {
        this(redis, props, Duration.ofMinutes(10), Duration.ofSeconds(60), null);
    }

    public DecayWorker(
        StringRedisTemplate redis,
        AutoBlockProperties props,
        Duration halfLife,
        Duration interval,
        Consumer<List<DecayResult>> onDecay
    ) {
        this.redis      = redis;
        this.keys       = new KeyBuilder(props.tenant());
        this.thresholds = props.thresholds();
        this.halfLifeMs = halfLife.toMillis();
        this.interval   = interval;
        this.onDecay    = onDecay;
    }

    // ---- Lifecycle -------------------------------------------------------

    @Override
    public void afterPropertiesSet() { start(); }

    @Override
    public void destroy() { stop(); }

    public void start() {
        if (!running.compareAndSet(false, true)) return;

        try { runCycle(); } catch (Exception e) {
            log.warn("autoblock DecayWorker initial cycle failed: {}", e.getMessage());
        }

        workerThread = Thread.ofVirtual()
            .name("autoblock-decay-worker")
            .start(this::loop);
    }

    public void stop() {
        running.set(false);
        var t = workerThread;
        if (t != null) t.interrupt();
    }

    // ---- Core cycle -------------------------------------------------------

    /** Run a single decay cycle. Callable directly in tests. */
    public List<DecayResult> runCycle() {
        var ips = scanIPs();
        var results = new ArrayList<DecayResult>();
        for (var ip : ips) {
            try {
                var r = decayOne(ip);
                if (r != null && r.decrement() > 0) results.add(r);
            } catch (Exception e) {
                log.debug("autoblock DecayWorker: decay failed for ip={}: {}", ip, e.getMessage());
            }
        }
        if (!results.isEmpty() && onDecay != null) onDecay.accept(results);
        log.debug("autoblock DecayWorker: decayed {} IPs", results.size());
        return results;
    }

    // ---- Background loop -------------------------------------------------

    private void loop() {
        while (running.get()) {
            try {
                Thread.sleep(interval);
                runCycle();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.warn("autoblock DecayWorker cycle error: {}", e.getMessage());
            }
        }
    }

    // ---- Redis operations ------------------------------------------------

    private Set<String> scanIPs() {
        try {
            var pattern = keys.penaltyScorePattern("ip");
            var found = redis.keys(pattern);   // uses KEYS — acceptable for low-frequency decay
            return found != null ? found : Set.of();
        } catch (Exception e) {
            log.warn("autoblock DecayWorker: scan failed: {}", e.getMessage());
            return Set.of();
        }
    }

    @SuppressWarnings("unchecked")
    private DecayResult decayOne(String fullKey) {
        // Extract IP from full key: ab:{tenant}:penalty:score:ip:{ip}
        var prefix = keys.penaltyScore("ip", "");
        var ip     = fullKey.startsWith(prefix) ? fullKey.substring(prefix.length()) : fullKey;
        if (ip.isBlank()) return null;

        var t     = thresholds;
        var nowMs = Instant.now().toEpochMilli();

        List<Object> res = redis.execute(
            DECAY_SCRIPT,
            List.of(
                keys.penaltyScore("ip", ip),
                keys.penaltyState("ip", ip),
                keys.penaltyDecayTs("ip", ip)
            ),
            String.valueOf(nowMs),
            String.valueOf(halfLifeMs),
            String.valueOf(t.warn()),
            String.valueOf(t.slow()),
            String.valueOf(t.block()),
            String.valueOf(t.blacklist())
        );

        if (res == null || res.size() < 3) return null;
        var newScore  = ((Number) res.get(0)).intValue();
        var newState  = res.get(1).toString();
        var decrement = ((Number) res.get(2)).intValue();
        return new DecayResult(ip, newScore, newState, decrement);
    }
}
