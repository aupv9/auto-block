// Package router wires up the management API routes.
package router

import (
	"net/http"

	"github.com/autoblock/autoblock/internal/config"
	"github.com/autoblock/autoblock/internal/handler"
	"github.com/autoblock/autoblock/internal/middleware"
	"github.com/autoblock/autoblock/internal/store"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

func New(s *store.Store, authCfg config.AuthConfig) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.SetHeader("Content-Type", "application/json"))

	bl := handler.NewBlacklist(s)
	wl := handler.NewWhitelist(s)
	st := handler.NewStatus(s)
	rl := handler.NewRules(s)

	// Health (unauthenticated)
	r.Get("/api/v1/status/health", handler.Health)

	r.Group(func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(authCfg))

		// Blacklist
		r.Get("/api/v1/blacklist/ip", bl.List)
		r.Post("/api/v1/blacklist/ip", bl.Add)
		r.Get("/api/v1/blacklist/ip/{ip}", bl.Get)
		r.Delete("/api/v1/blacklist/ip/{ip}", bl.Remove)

		// Whitelist
		r.Get("/api/v1/whitelist/ip", wl.List)
		r.Post("/api/v1/whitelist/ip", wl.Add)
		r.Delete("/api/v1/whitelist/ip/{ip}", wl.Remove)

		// Status
		r.Get("/api/v1/status/ip/{ip}", st.GetIP)

		// Dynamic rules (admin only enforced in handler via role check)
		r.Get("/api/v1/rules", rl.List)
		r.Post("/api/v1/rules", rl.Create)
		r.Get("/api/v1/rules/{id}", rl.Get)
		r.Put("/api/v1/rules/{id}", rl.Update)
		r.Delete("/api/v1/rules/{id}", rl.Delete)
	})

	return r
}
