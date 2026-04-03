// Package remediation orchestrates the automated response to penalty state changes.
package remediation

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/autoblock/autoblock/internal/audit"
	"github.com/autoblock/autoblock/internal/metrics"
	"github.com/autoblock/autoblock/internal/notifier"
	"github.com/autoblock/autoblock/internal/store"
	"github.com/autoblock/autoblock/internal/waf"
	"github.com/autoblock/autoblock/internal/watcher"
	"github.com/redis/go-redis/v9"
)

// Config holds all Engine dependencies.
type Config struct {
	Tenant          string
	DebounceSeconds int
	MinScoreForWAF  int
	Store           *store.Store
	WAF             waf.Provider
	Notifier        notifier.Notifier
	Audit           *audit.StreamWriter
}

// Engine processes watcher events and applies remediation actions.
type Engine struct {
	cfg Config
}

func NewEngine(cfg Config) *Engine {
	return &Engine{cfg: cfg}
}

// Run starts the watcher and processes events until ctx is cancelled.
func (e *Engine) Run(ctx context.Context, rdb *redis.Client, mode string, pollInterval int) error {
	events, err := watcher.Run(ctx, rdb, e.cfg.Store.Keys(), mode, pollInterval)
	if err != nil {
		return fmt.Errorf("engine: start watcher: %w", err)
	}

	slog.Info("engine: ready, awaiting events")

	for {
		select {
		case <-ctx.Done():
			return nil
		case evt, ok := <-events:
			if !ok {
				return nil
			}
			go e.handleEvent(ctx, evt)
		}
	}
}

func (e *Engine) handleEvent(ctx context.Context, evt watcher.Event) {
	if evt.NewState != "BLACKLIST" {
		return // Only act on BLACKLIST transitions
	}

	log := slog.With(slog.String("ip", evt.IP))
	log.Info("engine: blacklist event received", slog.String("state", evt.NewState))

	// Debounce — wait before acting to avoid false positives from transient spikes
	if e.cfg.DebounceSeconds > 0 {
		select {
		case <-time.After(time.Duration(e.cfg.DebounceSeconds) * time.Second):
		case <-ctx.Done():
			return
		}
	}

	// Re-verify state and score (may have changed during debounce)
	state, err := e.cfg.Store.GetPenaltyState(ctx, evt.IP)
	if err != nil {
		log.Error("engine: could not re-read state", slog.String("err", err.Error()))
		return
	}
	if state != "BLACKLIST" {
		log.Info("engine: state changed during debounce, aborting", slog.String("state", state))
		return
	}

	score, err := e.cfg.Store.GetPenaltyScore(ctx, evt.IP)
	if err != nil {
		log.Error("engine: could not read score", slog.String("err", err.Error()))
		return
	}
	if score < e.cfg.MinScoreForWAF {
		log.Warn("engine: score below WAF threshold, skipping WAF push",
			slog.Int("score", score), slog.Int("min", e.cfg.MinScoreForWAF))
		return
	}

	// Never block whitelisted IPs
	whitelisted, err := e.cfg.Store.IsWhitelisted(ctx, evt.IP)
	if err != nil {
		log.Error("engine: whitelist check failed", slog.String("err", err.Error()))
		return
	}
	if whitelisted {
		log.Info("engine: ip is whitelisted, skipping WAF push")
		return
	}

	start := time.Now()

	// Push to WAF (idempotent — providers should handle duplicates)
	wafErr := e.cfg.WAF.AddToBlocklist(ctx, evt.IP, 0, fmt.Sprintf("autoblock score=%d", score))
	latency := time.Since(start)

	metrics.WAFActionTotal.WithLabelValues(e.cfg.Tenant, e.cfg.WAF.Name(), "block").Inc()
	metrics.WAFActionLatency.WithLabelValues(e.cfg.Tenant, e.cfg.WAF.Name()).Observe(latency.Seconds())

	if wafErr != nil {
		log.Error("engine: waf push failed", slog.String("err", wafErr.Error()))
		metrics.WAFActionErrors.WithLabelValues(e.cfg.Tenant, e.cfg.WAF.Name()).Inc()
		// Fall through — still write audit log and notify
	} else {
		log.Info("engine: waf push succeeded",
			slog.Duration("latency", latency),
			slog.Int("score", score),
		)
		// Mark as synced in Redis (for idempotency on next run)
		_ = e.cfg.Store.MarkWAFSynced(ctx, evt.IP, e.cfg.WAF.Name())
	}

	// Add to Redis blacklist (persisted even without WAF)
	_ = e.cfg.Store.AddToBlacklist(ctx, evt.IP, time.Hour)

	// Audit log
	e.cfg.Audit.Write(ctx, audit.Entry{
		Action: "BLACKLIST",
		IP:     evt.IP,
		Score:  score,
		Reason: fmt.Sprintf("penalty threshold exceeded (score=%d)", score),
		Actor:  "autoblock-engine",
	})

	// Slack notification
	if notifyErr := e.cfg.Notifier.Send(ctx, notifier.Event{
		Type:  "blacklisted",
		IP:    evt.IP,
		Score: score,
		WAF:   e.cfg.WAF.Name(),
		Error: wafErr,
	}); notifyErr != nil {
		log.Warn("engine: notification failed", slog.String("err", notifyErr.Error()))
	}
}
