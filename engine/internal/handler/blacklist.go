package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/autoblock/autoblock/internal/store"
	"github.com/go-chi/chi/v5"
)

type BlacklistHandler struct {
	store *store.Store
}

func NewBlacklist(s *store.Store) *BlacklistHandler {
	return &BlacklistHandler{store: s}
}

// GET /api/v1/blacklist/ip — returns exact IPs and CIDR ranges combined.
func (h *BlacklistHandler) List(w http.ResponseWriter, r *http.Request) {
	entries, err := h.store.ListBlacklist(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cidrs, err := h.store.ListBlacklistCidrs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := append(entries, cidrs...)
	writeJSON(w, http.StatusOK, map[string]any{"entries": all, "total": len(all)})
}

// POST /api/v1/blacklist/ip — accepts both plain IPs and CIDR ranges (e.g. "10.0.0.0/8").
func (h *BlacklistHandler) Add(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP         string `json:"ip"`
		TTLSeconds int    `json:"ttl_seconds"` // 0 = permanent
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.IP == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}

	ttl := time.Duration(body.TTLSeconds) * time.Second
	var addErr error
	if strings.Contains(body.IP, "/") {
		addErr = h.store.AddCidrToBlacklist(r.Context(), body.IP, ttl)
	} else {
		addErr = h.store.AddToBlacklist(r.Context(), body.IP, ttl)
	}
	if addErr != nil {
		writeError(w, http.StatusBadRequest, addErr.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ip": body.IP, "ttl_seconds": body.TTLSeconds})
}

// DELETE /api/v1/blacklist/ip/{ip} — removes an exact IP or CIDR range.
func (h *BlacklistHandler) Remove(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	var err error
	if strings.Contains(ip, "/") {
		err = h.store.RemoveCidrFromBlacklist(r.Context(), ip)
	} else {
		err = h.store.RemoveFromBlacklist(r.Context(), ip)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/v1/blacklist/ip/{ip} — checks exact IP membership or CIDR containment.
func (h *BlacklistHandler) Get(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	blocked, err := h.store.IsBlacklisted(r.Context(), ip)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !blocked {
		blocked, err = h.store.IpInBlacklistedCidr(r.Context(), ip)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "blacklisted": blocked})
}
