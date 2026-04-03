// Package audit writes immutable audit log entries to a Redis Stream.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Entry is a single audit event.
type Entry struct {
	Action string // BLACKLIST, WHITELIST_ADD, WHITELIST_REMOVE, MANUAL_BLOCK, MANUAL_UNBLOCK
	IP     string
	UserID string
	Score  int
	Reason string
	Actor  string // "autoblock-engine" | "api-admin" | "api-readonly"
}

// StreamWriter appends audit entries to a Redis Stream with auto-trimming.
type StreamWriter struct {
	rdb       *redis.Client
	streamKey string
	maxLen    int64
}

func NewStreamWriter(rdb *redis.Client, streamKey string) *StreamWriter {
	return &StreamWriter{rdb: rdb, streamKey: streamKey, maxLen: 100_000}
}

// Write appends an entry to the audit stream (fire-and-forget; errors are logged, not returned).
func (w *StreamWriter) Write(ctx context.Context, e Entry) {
	if e.Actor == "" {
		e.Actor = "autoblock-engine"
	}

	values := map[string]any{
		"action":    e.Action,
		"ip":        e.IP,
		"score":     strconv.Itoa(e.Score),
		"reason":    e.Reason,
		"actor":     e.Actor,
		"timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10),
	}
	if e.UserID != "" {
		values["user_id"] = e.UserID
	}

	if err := w.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: w.streamKey,
		MaxLen: w.maxLen,
		Approx: true, // ~ prefix for efficiency
		Values: values,
	}).Err(); err != nil {
		slog.Error("audit: write failed", slog.String("err", err.Error()), slog.String("action", e.Action))
	}
}

// List reads the latest N audit entries (newest first).
func (w *StreamWriter) List(ctx context.Context, count int64) ([]AuditEntry, error) {
	msgs, err := w.rdb.XRevRangeN(ctx, w.streamKey, "+", "-", count).Result()
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}

	entries := make([]AuditEntry, 0, len(msgs))
	for _, msg := range msgs {
		e := AuditEntry{
			ID:     msg.ID,
			Action: msg.Values["action"].(string),
			IP:     fmt.Sprintf("%v", msg.Values["ip"]),
			Reason: fmt.Sprintf("%v", msg.Values["reason"]),
			Actor:  fmt.Sprintf("%v", msg.Values["actor"]),
		}
		if score, ok := msg.Values["score"].(string); ok {
			_ = func() { _, _ = strconv.Atoi(score) }
			if n, err := strconv.Atoi(score); err == nil {
				e.Score = n
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

type AuditEntry struct {
	ID     string
	Action string
	IP     string
	Score  int
	Reason string
	Actor  string
}
