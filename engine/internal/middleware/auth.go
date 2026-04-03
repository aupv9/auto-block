// Package middleware provides HTTP middleware for the management API.
package middleware

import (
	"net/http"
	"strings"

	"github.com/autoblock/autoblock/internal/config"
)

type role string

const (
	RoleAdmin    role = "admin"
	RoleReadonly role = "readonly"

	contextKeyRole = "autoblock:role"
)

// APIKeyAuth validates the Authorization: Bearer <key> header against the
// configured key list. Returns 401 if auth is disabled or key is invalid.
func APIKeyAuth(cfg config.AuthConfig) func(http.Handler) http.Handler {
	// Build lookup map
	keyMap := make(map[string]string, len(cfg.Keys))
	for _, k := range cfg.Keys {
		if k.Key != "" {
			keyMap[k.Key] = k.Role
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			key := strings.TrimPrefix(auth, "Bearer ")
			role, ok := keyMap[key]
			if !ok {
				http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
				return
			}

			// For write operations require admin role
			if r.Method != http.MethodGet && r.Method != http.MethodHead && role != string(RoleAdmin) {
				http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
				return
			}

			_ = role // available if needed downstream via context
			next.ServeHTTP(w, r)
		})
	}
}
