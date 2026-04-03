package io.autoblock.spring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

/**
 * Type-safe configuration for the AutoBlock Spring Boot starter.
 *
 * Example application.yml:
 * <pre>
 * autoblock:
 *   tenant: my-app
 *   trust-proxy: true
 *   thresholds:
 *     warn: 3
 *     slow: 6
 *     block: 10
 *     blacklist: 15
 *   rules:
 *     - path: /api/auth/login
 *       limit: 10
 *       window-seconds: 60
 *       algorithm: HYBRID
 *       per-user: true
 *     - path: /api/**
 *       limit: 100
 *       window-seconds: 60
 *       algorithm: SLIDING_WINDOW
 * </pre>
 */
@ConfigurationProperties(prefix = "autoblock")
public record AutoBlockProperties(
    @DefaultValue("true")  boolean enabled,
    @DefaultValue("default") String tenant,
    @DefaultValue("true")  boolean failOpen,
    @DefaultValue("false") boolean trustProxy,
    @DefaultValue("2")     int trustProxyDepth,
    @DefaultValue          ThresholdProperties thresholds,
    List<RuleProperties> rules
) {

    /**
     * Progressive penalty thresholds — score at which each state is entered.
     * Mirrors DEFAULT_THRESHOLDS in packages/core.
     */
    public record ThresholdProperties(
        @DefaultValue("3")  int warn,
        @DefaultValue("6")  int slow,
        @DefaultValue("10") int block,
        @DefaultValue("15") int blacklist
    ) {
        /** Canonical constructor — validates ordering. */
        public ThresholdProperties {
            if (!(warn < slow && slow < block && block < blacklist)) {
                throw new IllegalArgumentException(
                    "Thresholds must be strictly ascending: warn < slow < block < blacklist");
            }
        }
    }

    /**
     * A single rate-limit rule matched against incoming request paths.
     * Rules are evaluated in order; first match wins.
     */
    public record RuleProperties(
        String path,
        int limit,
        @DefaultValue("60") int windowSeconds,
        @DefaultValue("HYBRID") Algorithm algorithm,
        @DefaultValue("false") boolean perUser,
        @DefaultValue("false") boolean perEndpoint
    ) {
        public RuleProperties {
            if (path == null || path.isBlank()) {
                throw new IllegalArgumentException("Rule path must not be blank");
            }
            if (limit <= 0) {
                throw new IllegalArgumentException("Rule limit must be positive, got: " + limit);
            }
        }

        public long windowMs() {
            return (long) windowSeconds * 1_000;
        }
    }

    public enum Algorithm {
        SLIDING_WINDOW,
        TOKEN_BUCKET,
        /** Both must pass — protects against sustained abuse AND bursts. */
        HYBRID
    }
}
