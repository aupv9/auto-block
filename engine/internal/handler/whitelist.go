package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/autoblock/autoblock/internal/store"
	"github.com/go-chi/chi/v5"
)

type WhitelistHandler struct {
	store *store.Store
}

func NewWhitelist(s *store.Store) *WhitelistHandler {
	return &WhitelistHandler{store: s}
}

// GET /api/v1/whitelist/ip — returns exact IPs and CIDR ranges combined.
func (h *WhitelistHandler) List(w http.ResponseWriter, r *http.Request) {
	ips, err := h.store.ListWhitelist(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cidrs, err := h.store.ListWhitelistCidrs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := append(ips, cidrs...)
	writeJSON(w, http.StatusOK, map[string]any{"ips": all, "total": len(all)})
}

// POST /api/v1/whitelist/ip — accepts both plain IPs and CIDR ranges (e.g. "10.0.0.0/8").
func (h *WhitelistHandler) Add(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.IP == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}
	var addErr error
	if strings.Contains(body.IP, "/") {
		addErr = h.store.AddCidrToWhitelist(r.Context(), body.IP)
	} else {
		addErr = h.store.AddToWhitelist(r.Context(), body.IP)
	}
	if addErr != nil {
		writeError(w, http.StatusBadRequest, addErr.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ip": body.IP})
}

// DELETE /api/v1/whitelist/ip/{ip} — removes an exact IP or CIDR range.
func (h *WhitelistHandler) Remove(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	var err error
	if strings.Contains(ip, "/") {
		err = h.store.RemoveCidrFromWhitelist(r.Context(), ip)
	} else {
		err = h.store.RemoveFromWhitelist(r.Context(), ip)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
