package autoblock

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Middleware returns a standard http.Handler middleware that applies rate
// limiting to every request. Compatible with chi, gorilla/mux, stdlib, etc.
//
//	mux := chi.NewRouter()
//	mux.Use(limiter.Middleware)
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip     := l.extractIP(r)
		userID := r.Header.Get("X-User-ID")
		path   := r.URL.Path

		decision  := l.Evaluate(r.Context(), ip, userID, path)
		remaining := max(0, decision.Remaining)
		reset     := decision.RetryAfter
		if reset <= 0 { reset = 60 }

		// IETF draft-ietf-httpapi-ratelimit-headers
		w.Header().Set("RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("RateLimit-Reset",     fmt.Sprintf("%d", reset))
		// Legacy X- headers for backward compatibility
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("X-RateLimit-State",     string(decision.State))

		if !decision.Allowed {
			if decision.RetryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", decision.RetryAfter))
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(decision.StatusCode)

			msg := "Too many requests. Please slow down."
			if decision.State == StateBlacklist {
				msg = "Your IP has been blocked due to repeated policy violations."
			}
			body, _ := json.Marshal(map[string]any{
				"error":      msg,
				"state":      decision.State,
				"retryAfter": decision.RetryAfter,
			})
			_, _ = w.Write(body)
			return
		}

		if decision.DelayMs > 0 {
			time.Sleep(time.Duration(decision.DelayMs) * time.Millisecond)
		}

		next.ServeHTTP(w, r)
	})
}

// extractIP returns the real client IP, respecting TrustProxy configuration.
func (l *Limiter) extractIP(r *http.Request) string {
	if l.cfg.TrustProxy {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			depth := l.cfg.trustProxyDepth()
			idx := len(parts) - depth
			if idx < 0 {
				idx = 0
			}
			ip := strings.TrimSpace(parts[idx])
			if ip != "" {
				return sanitizeIP(ip)
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return sanitizeIP(r.RemoteAddr)
	}
	return sanitizeIP(host)
}

func sanitizeIP(ip string) string {
	if strings.HasPrefix(ip, "[") {
		if end := strings.Index(ip, "]"); end > 0 {
			ip = ip[1:end]
		}
	}
	if idx := strings.IndexByte(ip, '%'); idx > 0 {
		ip = ip[:idx]
	}
	return strings.TrimSpace(ip)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
