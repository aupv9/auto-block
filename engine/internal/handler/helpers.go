package handler

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// aliases used by rules.go
func jsonOK(w http.ResponseWriter, v any)             { writeJSON(w, http.StatusOK, v) }
func jsonError(w http.ResponseWriter, status int, msg string) { writeError(w, status, msg) }
