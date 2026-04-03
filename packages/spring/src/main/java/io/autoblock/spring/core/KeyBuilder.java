package io.autoblock.spring.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Constructs Redis keys using the canonical AutoBlock schema.
 *
 * Key format: {prefix}:{tenant}:{type}:{dimension}:{value}[:{ep_hash}]
 *
 * This is a direct port of:
 *   - packages/core/src/key-builder.ts  (TypeScript)
 *   - packages/fastapi/autoblock/key_builder.py  (Python)
 *   - engine/internal/keys/keys.go  (Go)
 *
 * All four produce identical keys for the same inputs, enabling the Go
 * remediation engine to read penalty state set by this middleware.
 */
public final class KeyBuilder {

    private final String prefix;
    private final String tenant;

    public KeyBuilder(String tenant) {
        this(tenant, "ab");
    }

    public KeyBuilder(String tenant, String prefix) {
        if (tenant == null || tenant.isBlank()) throw new IllegalArgumentException("tenant must not be blank");
        if (prefix == null || prefix.isBlank()) throw new IllegalArgumentException("prefix must not be blank");
        this.tenant = tenant;
        this.prefix = prefix;
    }

    /** Sliding-window sorted-set key for a given dimension + optional endpoint. */
    public String slidingWindow(String dimension, String value, String endpoint) {
        return buildKey("sw", dimension, value, endpoint);
    }

    /** Token-bucket hash key for a given dimension + optional endpoint. */
    public String tokenBucket(String dimension, String value, String endpoint) {
        return buildKey("tb", dimension, value, endpoint);
    }

    /** Penalty score counter key (string, integer). */
    public String penaltyScore(String dimension, String value) {
        return "%s:%s:penalty:score:%s:%s".formatted(prefix, tenant, dimension, value);
    }

    /** Penalty FSM state key (string: CLEAN|WARN|SLOW|BLOCK|BLACKLIST). */
    public String penaltyState(String dimension, String value) {
        return "%s:%s:penalty:state:%s:%s".formatted(prefix, tenant, dimension, value);
    }

    /** Penalty history ring buffer (list, last 10 reasons). */
    public String penaltyHistory(String dimension, String value) {
        return "%s:%s:penalty:history:%s:%s".formatted(prefix, tenant, dimension, value);
    }

    /** Last-decay timestamp key (string, unix ms). */
    public String penaltyDecayTs(String dimension, String value) {
        return "%s:%s:penalty:decay:%s:%s".formatted(prefix, tenant, dimension, value);
    }

    /** SCAN pattern for all penalty score keys of a dimension. */
    public String penaltyScorePattern(String dimension) {
        return "%s:%s:penalty:score:%s:*".formatted(prefix, tenant, dimension);
    }

    /** IP blacklist sorted set (score = expiry unix-seconds; 0 = permanent). */
    public String blacklist(String type) {
        return "%s:%s:blacklist:%s".formatted(prefix, tenant, type);
    }

    /** CIDR blacklist set (no TTL per entry; managed separately). */
    public String blacklistCidr() {
        return "%s:%s:blacklist:cidr".formatted(prefix, tenant);
    }

    /** IP whitelist set. */
    public String whitelist(String type) {
        return "%s:%s:whitelist:%s".formatted(prefix, tenant, type);
    }

    /** CIDR whitelist set. */
    public String whitelistCidr() {
        return "%s:%s:whitelist:cidr".formatted(prefix, tenant);
    }

    /** Dynamic rules hash (managed by engine API, hot-reloaded by SDKs). */
    public String rules() {
        return "%s:%s:rules:endpoint".formatted(prefix, tenant);
    }

    /** Pub/sub channel: published by engine on every rule write/delete. */
    public String rulesChanged() {
        return "%s:%s:rules:changed".formatted(prefix, tenant);
    }

    /** Audit event stream. */
    public String auditStream() {
        return "%s:%s:audit:stream".formatted(prefix, tenant);
    }

    // ---- private helpers -------------------------------------------------

    private String buildKey(String type, String dimension, String value, String endpoint) {
        if (endpoint != null && !endpoint.isBlank()) {
            var epHash = sha256Hex(endpoint).substring(0, 8);
            return "%s:%s:%s:%s:%s:%s".formatted(prefix, tenant, type, dimension, value, epHash);
        }
        return "%s:%s:%s:%s:%s".formatted(prefix, tenant, type, dimension, value);
    }

    private static String sha256Hex(String input) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed present in every JRE
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
