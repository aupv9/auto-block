package io.autoblock.spring.filter;

import io.autoblock.spring.config.AutoBlockProperties;
import io.autoblock.spring.core.PenaltyState;
import io.autoblock.spring.core.RateLimitDecision;
import io.autoblock.spring.core.RateLimiter;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.StatusCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

public class AutoBlockFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AutoBlockFilter.class);

    private final RateLimiter         limiter;
    private final AutoBlockProperties props;

    public AutoBlockFilter(RateLimiter limiter, AutoBlockProperties props) {
        this.limiter = limiter;
        this.props   = props;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest  request,
        HttpServletResponse response,
        FilterChain         chain
    ) throws ServletException, IOException {

        if (!props.enabled()) {
            chain.doFilter(request, response);
            return;
        }

        var ip     = IpExtractor.extract(request, props.trustProxy(), props.trustProxyDepth());
        var userId = extractUserId(request);
        var path   = request.getRequestURI();

        // OTel span — no-op when no SDK is registered.
        var tracer = GlobalOpenTelemetry.getTracer("autoblock");
        var span   = tracer.spanBuilder("autoblock.evaluate")
            .setAttribute("autoblock.tenant",   props.tenant())
            .setAttribute("autoblock.ip",       ip)
            .setAttribute("autoblock.endpoint", path)
            .startSpan();

        RateLimitDecision decision;
        try (var ignored = span.makeCurrent()) {
            decision = limiter.evaluate(ip, userId, path);
        } finally {
            switch (decision) {
                case RateLimitDecision.Allow allow -> {
                    span.setAttribute("autoblock.allowed", true);
                    span.setAttribute("autoblock.state", allow.state().name());
                }
                case RateLimitDecision.Deny deny -> {
                    span.setAttribute("autoblock.allowed", false);
                    span.setAttribute("autoblock.state", deny.state().name());
                    span.setStatus(StatusCode.ERROR, "request blocked by autoblock");
                }
            }
            span.end();
        }

        switch (decision) {
            case RateLimitDecision.Allow(var state, var remaining, var delayMs) -> {
                addRateLimitHeaders(response, state, remaining);
                if (delayMs > 0) {
                    log.debug("SLOW penalty applied: sleeping {}ms for ip={}", delayMs, ip);
                    sleepQuietly(delayMs);
                }
                chain.doFilter(request, response);
            }
            case RateLimitDecision.Deny(var state, var statusCode, var retryAfter) -> {
                log.info("Request denied: ip={} state={} status={}", ip, state, statusCode);
                addRateLimitHeaders(response, state, 0, retryAfter);
                sendDenyResponse(response, statusCode, retryAfter, state);
            }
        }
    }

    private static void addRateLimitHeaders(HttpServletResponse response, PenaltyState state, int remaining) {
        addRateLimitHeaders(response, state, remaining, 60L);
    }

    private static void addRateLimitHeaders(HttpServletResponse response, PenaltyState state, int remaining, long resetSeconds) {
        var rem   = String.valueOf(Math.max(0, remaining));
        var reset = String.valueOf(resetSeconds > 0 ? resetSeconds : 60);
        response.setHeader("RateLimit-Remaining", rem);
        response.setHeader("RateLimit-Reset",     reset);
        response.setHeader("X-RateLimit-Remaining", rem);
        response.setHeader("X-RateLimit-State",     state.name());
    }

    private static void sendDenyResponse(HttpServletResponse response, int statusCode, long retryAfter, PenaltyState state) throws IOException {
        response.setStatus(statusCode);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        if (statusCode == 429 && retryAfter > 0) {
            response.setHeader("Retry-After", String.valueOf(retryAfter));
        }
        var message = statusCode == 403
            ? "Your IP has been blocked due to repeated policy violations."
            : "Too many requests. Please slow down.";
        var body = """
                {"error":"%s","state":"%s","retryAfter":%d}
                """.formatted(message, state.name(), retryAfter).strip();
        response.getWriter().write(body);
    }

    protected String extractUserId(HttpServletRequest request) {
        var secUserId = SecurityContextExtractor.extractPrincipalName();
        if (secUserId != null) return secUserId;
        for (var attr : new String[]{"userId", "user_id", "sub", "principal"}) {
            var val = request.getAttribute(attr);
            if (val instanceof String s && !s.isBlank()) return s;
        }
        var header = request.getHeader("X-User-ID");
        return (header != null && !header.isBlank()) ? header : null;
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(Duration.ofMillis(ms));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.debug("SLOW sleep interrupted");
        }
    }
}
