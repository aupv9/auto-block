package io.autoblock.spring.filter;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Extracts the real client IP from an HTTP request.
 *
 * When behind a reverse proxy, the real IP is typically in X-Forwarded-For.
 * The {@code depth} parameter controls how many proxy hops to trust:
 *   - depth=1: trust the last XFF entry (single proxy)
 *   - depth=2: trust the second-to-last entry (two proxies), etc.
 *
 * Mirrors the TypeScript extractIP() in packages/express/src/extractors.ts.
 */
public final class IpExtractor {

    private IpExtractor() {}

    /**
     * Extract client IP.
     *
     * @param request     the incoming request
     * @param trustProxy  whether to honour X-Forwarded-For
     * @param depth       number of trusted proxy hops (ignored when trustProxy=false)
     * @return IP string, never null; falls back to remote address
     */
    public static String extract(HttpServletRequest request, boolean trustProxy, int depth) {
        if (!trustProxy) {
            return sanitize(request.getRemoteAddr());
        }

        var xff = request.getHeader("X-Forwarded-For");
        if (xff == null || xff.isBlank()) {
            return sanitize(request.getRemoteAddr());
        }

        // XFF is a comma-separated list: client, proxy1, proxy2...
        // The rightmost N entries were added by trusted proxies; skip them.
        var parts = xff.split(",");
        var targetIndex = parts.length - depth;
        if (targetIndex < 0) targetIndex = 0;

        return sanitize(parts[targetIndex].trim());
    }

    /** Strip IPv6 zone IDs and brackets (e.g. [::1] → ::1). */
    private static String sanitize(String ip) {
        if (ip == null) return "unknown";
        // Strip brackets from IPv6 literals
        if (ip.startsWith("[") && ip.contains("]")) {
            ip = ip.substring(1, ip.indexOf(']'));
        }
        // Strip IPv6 zone ID (%eth0)
        var zoneIdx = ip.indexOf('%');
        if (zoneIdx > 0) ip = ip.substring(0, zoneIdx);
        return ip.trim();
    }
}
