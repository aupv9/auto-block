package io.autoblock.spring.core;

import io.autoblock.spring.config.AutoBlockProperties;
import io.autoblock.spring.config.AutoBlockProperties.Algorithm;
import io.autoblock.spring.config.AutoBlockProperties.RuleProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.json.BasicJsonParser;
import org.springframework.data.redis.connection.Message;
import org.springframework.data.redis.connection.MessageListener;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Polls {@code ab:{tenant}:rules:endpoint} (Redis hash) every 30 s AND
 * subscribes to the {@code ab:{tenant}:rules:changed} pub/sub channel so that
 * rule changes published by the AutoBlock engine are applied immediately
 * (&lt;1 s latency instead of up to 30 s).
 *
 * <p>Runs in a virtual thread ({@code Thread.ofVirtual()}) — no platform-thread
 * cost and no Spring {@code @Scheduled} dependency.
 *
 * <p>Wired as a bean by {@link io.autoblock.spring.AutoBlockAutoConfiguration}
 * when {@code autoblock.hot-reload.enabled=true} (default: true).
 */
public class RulesWatcher implements InitializingBean, DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(RulesWatcher.class);
    private static final BasicJsonParser JSON = new BasicJsonParser();

    private final RateLimiter        limiter;
    private final RedisOps           redis;
    private final StringRedisTemplate redisTemplate;
    private final KeyBuilder         keys;
    private final Duration           interval;
    private final Consumer<List<RuleProperties>> onReload;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile Thread watcherThread;
    private volatile RedisMessageListenerContainer listenerContainer;

    /** Convenience constructor — no push subscriber (poll-only). */
    public RulesWatcher(
        RateLimiter limiter,
        RedisOps redis,
        AutoBlockProperties props
    ) {
        this(limiter, redis, null, props, Duration.ofSeconds(30), null);
    }

    public RulesWatcher(
        RateLimiter limiter,
        RedisOps redis,
        StringRedisTemplate redisTemplate,
        AutoBlockProperties props,
        Duration interval,
        Consumer<List<RuleProperties>> onReload
    ) {
        this.limiter       = limiter;
        this.redis         = redis;
        this.redisTemplate = redisTemplate;
        this.keys          = new KeyBuilder(props.tenant());
        this.interval      = interval;
        this.onReload      = onReload;
    }

    // ---- Lifecycle -------------------------------------------------------

    @Override
    public void afterPropertiesSet() {
        start();
    }

    @Override
    public void destroy() {
        stop();
    }

    public void start() {
        if (!running.compareAndSet(false, true)) return;  // idempotent

        // Immediate first poll (blocking, before traffic arrives)
        try {
            poll();
        } catch (Exception e) {
            log.warn("autoblock RulesWatcher initial poll failed: {}", e.getMessage());
        }

        watcherThread = Thread.ofVirtual()
            .name("autoblock-rules-watcher")
            .start(this::loop);

        // Subscribe for push-based invalidation (best-effort — fails gracefully).
        startPushSubscriber();
    }

    public void stop() {
        running.set(false);
        var t = watcherThread;
        if (t != null) t.interrupt();
        var c = listenerContainer;
        if (c != null) {
            try { c.stop(); } catch (Exception ignored) {}
        }
    }

    // ---- Core poll -------------------------------------------------------

    /**
     * Single poll cycle — publicly callable in tests.
     */
    public List<RuleProperties> poll() {
        var raw = redis.hGetAll(keys.rules());
        var dynamic = parseRules(raw);
        limiter.reloadRules(dynamic);
        if (onReload != null) onReload.accept(dynamic);
        log.debug("autoblock RulesWatcher reloaded {} dynamic rules", dynamic.size());
        return dynamic;
    }

    // ---- Background poll loop --------------------------------------------

    private void loop() {
        while (running.get()) {
            try {
                Thread.sleep(interval);
                poll();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.warn("autoblock RulesWatcher poll error: {}", e.getMessage());
            }
        }
    }

    // ---- Push subscriber -------------------------------------------------

    /**
     * Subscribes to {@code ab:{tenant}:rules:changed} via Spring Data Redis
     * pub/sub. On any message, triggers an immediate {@link #poll()}.
     * Gracefully skipped if {@code redisTemplate} is null.
     */
    private void startPushSubscriber() {
        if (redisTemplate == null) return;

        try {
            var factory = redisTemplate.getConnectionFactory();
            if (factory == null) return;

            MessageListener listener = (Message msg, byte[] pattern) -> {
                log.debug("autoblock RulesWatcher: push notification received, reloading immediately");
                try {
                    poll();
                } catch (Exception e) {
                    log.warn("autoblock RulesWatcher push-reload failed: {}", e.getMessage());
                }
            };

            var container = new RedisMessageListenerContainer();
            container.setConnectionFactory(factory);
            container.addMessageListener(listener, new ChannelTopic(keys.rulesChanged()));
            container.afterPropertiesSet();
            container.start();
            this.listenerContainer = container;

            log.debug("autoblock RulesWatcher: subscribed to push channel {}", keys.rulesChanged());
        } catch (Exception e) {
            log.debug("autoblock RulesWatcher: pub/sub unavailable ({}), poll-only mode", e.getMessage());
        }
    }

    // ---- Rule parsing ----------------------------------------------------

    private List<RuleProperties> parseRules(Map<Object, Object> raw) {
        var result = new ArrayList<RuleProperties>();
        for (var entry : raw.entrySet()) {
            try {
                var jsonStr = entry.getValue().toString();
                var r = JSON.parseMap(jsonStr);

                if (Boolean.FALSE.equals(r.get("enabled"))) continue;

                var path   = (String) r.getOrDefault("path", "");
                var limit  = toInt(r.getOrDefault("limit", 100));
                var window = toInt(r.getOrDefault("window_seconds", 60));
                var algo   = parseAlgorithm((String) r.getOrDefault("algorithm", "hybrid"));
                var perUser     = Boolean.TRUE.equals(r.get("per_user"));
                var perEndpoint = Boolean.TRUE.equals(r.get("per_endpoint"));

                if (path == null || path.isBlank() || limit <= 0) continue;

                result.add(new RuleProperties(path, limit, window, algo, perUser, perEndpoint));
            } catch (Exception e) {
                log.debug("autoblock RulesWatcher: skipping malformed rule entry: {}", e.getMessage());
            }
        }
        return result;
    }

    private static int toInt(Object v) {
        if (v instanceof Number n) return n.intValue();
        try { return Integer.parseInt(v.toString()); } catch (NumberFormatException e) { return 0; }
    }

    private static Algorithm parseAlgorithm(String raw) {
        if (raw == null) return Algorithm.HYBRID;
        return switch (raw.toLowerCase()) {
            case "sliding_window" -> Algorithm.SLIDING_WINDOW;
            case "token_bucket"   -> Algorithm.TOKEN_BUCKET;
            default               -> Algorithm.HYBRID;
        };
    }
}
