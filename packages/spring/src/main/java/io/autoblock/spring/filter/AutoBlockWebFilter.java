package io.autoblock.spring.filter;

import io.autoblock.spring.config.AutoBlockProperties;
import io.autoblock.spring.core.PenaltyState;
import io.autoblock.spring.core.RateLimitDecision;
import io.autoblock.spring.core.RateLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Spring WebFlux {@link WebFilter} that applies AutoBlock rate limiting on every request.
 *
 * The rate-limit evaluation calls Redis synchronously via Lettuce's blocking API.
 * This is offloaded to {@link Schedulers#boundedElastic()} so the Netty event loop
 * is never blocked — pattern consistent with Spring's own data-access abstractions
 * when mixing blocking I/O into a reactive pipeline.
 *
 * Response headers added on every request:
 * <ul>
 *   <li>{@code X-RateLimit-Remaining} — estimated remaining requests</li>
 *   <li>{@code X-RateLimit-State}     — current penalty FSM state</li>
 * </ul>
 *
 * On denial:
 * <ul>
 *   <li>BLOCK (429): {@code Retry-After} + JSON body</li>
 *   <li>BLACKLIST (403): JSON body</li>
 * </ul>
 *
 * Implements {@link Ordered} so it runs before Spring Security's
 * {@code SecurityWebFilterChain} (order -100).
 */
public class AutoBlockWebFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AutoBlockWebFilter.class);

    /** Run before Spring Security's default order of -100. */
    static final int ORDER = -200;

    private final RateLimiter         limiter;
    private final AutoBlockProperties props;

    public AutoBlockWebFilter(RateLimiter limiter, AutoBlockProperties props) {
        this.limiter = limiter;
        this.props   = props;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!props.enabled()) {
            return chain.filter(exchange);
        }

        var request = exchange.getRequest();
        var ip      = extractIp(request);
        var userId  = extractUserId(request);
        var path    = request.getPath().value();

        // Offload blocking Redis I/O off the Netty event loop
        return Mono.fromCallable(() -> limiter.evaluate(ip, userId, path))
            .subscribeOn(Schedulers.boundedElastic())
            .flatMap(decision -> applyDecision(exchange, chain, decision, ip));
    }

    // ---- Decision handling -----------------------------------------------

    private Mono<Void> applyDecision(
        ServerWebExchange exchange,
        WebFilterChain    chain,
        RateLimitDecision decision,
        String            ip
    ) {
        return switch (decision) {
            case RateLimitDecision.Allow(var state, var remaining, var delayMs) -> {
                addHeaders(exchange.getResponse(), state, remaining, 60L);
                if (delayMs > 0) {
                    log.debug("SLOW penalty: delaying {}ms for ip={}", delayMs, ip);
                    // Reactor delay — does not block any thread
                    yield Mono.delay(Duration.ofMillis(delayMs))
                        .then(chain.filter(exchange));
                }
                yield chain.filter(exchange);
            }
            case RateLimitDecision.Deny(var state, var statusCode, var retryAfter) -> {
                log.info("Request denied: ip={} state={} status={}", ip, state, statusCode);
                addHeaders(exchange.getResponse(), state, 0, retryAfter);
                yield writeDenyResponse(exchange.getResponse(), statusCode, retryAfter, state);
            }
        };
    }

    // ---- Response helpers ------------------------------------------------

    private static void addHeaders(
        ServerHttpResponse response, PenaltyState state, int remaining, long resetSeconds
    ) {
        var h     = response.getHeaders();
        var rem   = String.valueOf(Math.max(0, remaining));
        var reset = String.valueOf(resetSeconds > 0 ? resetSeconds : 60);
        // IETF draft-ietf-httpapi-ratelimit-headers
        h.set("RateLimit-Remaining", rem);
        h.set("RateLimit-Reset",     reset);
        // Legacy X- headers
        h.set("X-RateLimit-Remaining", rem);
        h.set("X-RateLimit-State",     state.name());
    }

    private static Mono<Void> writeDenyResponse(
        ServerHttpResponse response,
        int                statusCode,
        long               retryAfter,
        PenaltyState       state
    ) {
        response.setStatusCode(HttpStatus.resolve(statusCode));
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        if (statusCode == 429 && retryAfter > 0) {
            response.getHeaders().set("Retry-After", String.valueOf(retryAfter));
        }

        var message = statusCode == 403
            ? "Your IP has been blocked due to repeated policy violations."
            : "Too many requests. Please slow down.";

        var body = """
                {"error":"%s","state":"%s","retryAfter":%d}
                """.formatted(message, state.name(), retryAfter).strip();

        var bytes = body.getBytes(StandardCharsets.UTF_8);
        var buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    // ---- Extraction helpers ----------------------------------------------

    private String extractIp(ServerHttpRequest request) {
        if (props.trustProxy()) {
            var xff = request.getHeaders().get("X-Forwarded-For");
            if (xff != null && !xff.isEmpty()) {
                var parts = xff.get(0).split(",");
                var depth = props.trustProxyDepth();
                var idx = parts.length - depth;
                if (idx < 0) idx = 0;
                var raw = parts[idx].trim();
                if (!raw.isBlank()) return sanitize(raw);
            }
        }
        return Optional.ofNullable(request.getRemoteAddress())
            .map(InetSocketAddress::getHostString)
            .map(AutoBlockWebFilter::sanitize)
            .orElse("unknown");
    }

    /**
     * Extract authenticated user ID for multi-dimensional rate limiting.
     *
     * <p>Priority order:
     * <ol>
     *   <li>Spring Security {@code SecurityContextHolder} — reads
     *       {@code Authentication.getName()} when Spring Security is on the classpath.
     *       Note: for reactive apps, prefer overriding this method to read from
     *       {@code ReactiveSecurityContextHolder} via the exchange attributes.</li>
     *   <li>{@code X-User-ID} request header (internal service-to-service).</li>
     * </ol>
     *
     * <p>Override this method to customise extraction logic.
     */
    protected String extractUserId(ServerHttpRequest request) {
        // 1. Spring Security (ThreadLocal-based; works in non-reactive context)
        var secUserId = SecurityContextExtractor.extractPrincipalName();
        if (secUserId != null) return secUserId;

        // 2. X-User-ID header (set by upstream auth proxies)
        List<String> header = request.getHeaders().get("X-User-ID");
        if (header != null && !header.isEmpty()) {
            var val = header.get(0);
            if (!val.isBlank()) return val;
        }
        return null;
    }

    private static String sanitize(String ip) {
        if (ip == null) return "unknown";
        if (ip.startsWith("[") && ip.contains("]")) ip = ip.substring(1, ip.indexOf(']'));
        var zoneIdx = ip.indexOf('%');
        if (zoneIdx > 0) ip = ip.substring(0, zoneIdx);
        return ip.trim();
    }
}
