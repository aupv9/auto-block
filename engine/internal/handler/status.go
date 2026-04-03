package handler

import (
	"net/http"

	"github.com/autoblock/autoblock/internal/store"
	"github.com/go-chi/chi/v5"
)

type StatusHandler struct {
	store *store.Store
}

func NewStatus(s *store.Store) *StatusHandler {
	return &StatusHandler{store: s}
}

// GET /api/v1/status/ip/{ip}
func (h *StatusHandler) GetIP(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	ctx := r.Context()

	score, err := h.store.GetPenaltyScore(ctx, ip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	state, err := h.store.GetPenaltyState(ctx, ip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	blacklisted, err := h.store.IsBlacklisted(ctx, ip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	whitelisted, err := h.store.IsWhitelisted(ctx, ip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ip":          ip,
		"state":       state,
		"score":       score,
		"blacklisted": blacklisted,
		"whitelisted": whitelisted,
	})
}

// GET /api/v1/status/health
func Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
