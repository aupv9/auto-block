package io.autoblock.spring.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;

/**
 * Reads the authenticated principal name from Spring Security's
 * {@code SecurityContextHolder} without creating a compile-time dependency
 * on {@code spring-security-core}.
 *
 * <p>When Spring Security is not on the classpath, all calls return {@code null}
 * silently after the first failed class-load attempt.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * var auth = SecurityContextHolder.getContext().getAuthentication();
 * return (auth != null && auth.isAuthenticated()) ? auth.getName() : null;
 * }</pre>
 */
final class SecurityContextExtractor {

    private static final Logger log = LoggerFactory.getLogger(SecurityContextExtractor.class);

    /** Tri-state: null = not yet checked, TRUE = available, FALSE = not available. */
    private static Boolean AVAILABLE = null;

    private static Method getContext;
    private static Method getAuthentication;
    private static Method isAuthenticated;
    private static Method getName;

    private SecurityContextExtractor() {}

    /**
     * Returns the authenticated principal name, or {@code null} if:
     * <ul>
     *   <li>Spring Security is not on the classpath</li>
     *   <li>No authentication is present in the current thread's security context</li>
     *   <li>The principal is anonymous or unauthenticated</li>
     * </ul>
     */
    static String extractPrincipalName() {
        if (!isAvailable()) return null;
        try {
            var context        = getContext.invoke(null);
            var authentication = getAuthentication.invoke(context);
            if (authentication == null) return null;
            var authenticated  = (Boolean) isAuthenticated.invoke(authentication);
            if (!Boolean.TRUE.equals(authenticated)) return null;
            var name = (String) getName.invoke(authentication);
            // Treat anonymous user as "not authenticated" for rate-limiting purposes
            if (name == null || name.isBlank() || "anonymousUser".equals(name)) return null;
            return name;
        } catch (Exception e) {
            log.debug("autoblock: SecurityContextHolder read failed: {}", e.getMessage());
            return null;
        }
    }

    // ---- Lazy initialisation via reflection ------------------------------

    private static boolean isAvailable() {
        if (AVAILABLE != null) return AVAILABLE;
        synchronized (SecurityContextExtractor.class) {
            if (AVAILABLE != null) return AVAILABLE;
            try {
                var holderClass   = Class.forName("org.springframework.security.core.context.SecurityContextHolder");
                var contextClass  = Class.forName("org.springframework.security.core.context.SecurityContext");
                var authClass     = Class.forName("org.springframework.security.core.Authentication");

                getContext        = holderClass.getMethod("getContext");
                getAuthentication = contextClass.getMethod("getAuthentication");
                isAuthenticated   = authClass.getMethod("isAuthenticated");
                getName           = authClass.getMethod("getName");

                AVAILABLE = true;
                log.debug("autoblock: Spring Security detected — SecurityContextHolder integration active");
            } catch (ClassNotFoundException e) {
                AVAILABLE = false;
                log.debug("autoblock: Spring Security not on classpath — user ID from SecurityContext disabled");
            } catch (NoSuchMethodException e) {
                AVAILABLE = false;
                log.warn("autoblock: Spring Security API mismatch — SecurityContextHolder integration disabled: {}", e.getMessage());
            }
        }
        return AVAILABLE;
    }
}
