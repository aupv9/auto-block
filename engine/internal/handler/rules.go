package handler

import (
	"encoding/json"
	"net/http"

	"github.com/autoblock/autoblock/internal/store"
	"github.com/go-chi/chi/v5"
)

// Rules handles dynamic rate-limit rule CRUD.
// Rules are stored in Redis and hot-reloaded by SDK middlewares.
type Rules struct{ store *store.Store }

func NewRules(s *store.Store) *Rules { return &Rules{store: s} }

// List returns all configured rules.
//
//	GET /api/v1/rules
func (h *Rules) List(w http.ResponseWriter, r *http.Request) {
	rules, err := h.store.ListRules(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rules == nil {
		rules = []*store.Rule{} // return [] not null
	}
	jsonOK(w, map[string]any{"rules": rules, "count": len(rules)})
}

// Get returns one rule by ID.
//
//	GET /api/v1/rules/{id}
func (h *Rules) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, err := h.store.GetRule(r.Context(), id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rule == nil {
		jsonError(w, http.StatusNotFound, "rule not found: "+id)
		return
	}
	jsonOK(w, rule)
}

// Create inserts a new rule.
//
//	POST /api/v1/rules
//	Body: {"id":"login-limit","path":"/api/auth/login","limit":10,"window_seconds":60,"algorithm":"hybrid"}
func (h *Rules) Create(w http.ResponseWriter, r *http.Request) {
	var rule store.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if rule.ID == "" || rule.Path == "" || rule.Limit <= 0 || rule.WindowSeconds <= 0 {
		jsonError(w, http.StatusBadRequest, "id, path, limit, and window_seconds are required")
		return
	}
	if rule.Algorithm == "" {
		rule.Algorithm = "hybrid"
	}
	rule.Enabled = true
	if err := h.store.SetRule(r.Context(), &rule); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, rule)
}

// Update replaces an existing rule. The ID in the URL takes precedence.
//
//	PUT /api/v1/rules/{id}
func (h *Rules) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	existing, err := h.store.GetRule(r.Context(), id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		jsonError(w, http.StatusNotFound, "rule not found: "+id)
		return
	}

	var updated store.Rule
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	updated.ID        = id
	updated.CreatedAt = existing.CreatedAt

	if err := h.store.SetRule(r.Context(), &updated); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, updated)
}

// Delete removes a rule.
//
//	DELETE /api/v1/rules/{id}
func (h *Rules) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.store.DeleteRule(r.Context(), id); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
