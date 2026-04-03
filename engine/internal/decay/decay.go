// Package decay runs a background goroutine that periodically applies
// exponential half-life decay to all active penalty scores in Redis.
//
// Without decay, an IP that triggered BLACKLIST stays at a high score until
// the key TTL expires even if it stopped sending bad traffic. With decay the
// score halves every half_life_minutes so well-behaved IPs recover automatically.
package decay

import (
	"context"
	"log/slog"
	"time"

	"github.com/autoblock/autoblock/internal/store"
)

// Config controls the decay behaviour.
type Config struct {
	// HalfLifeMinutes: time for a penalty score to halve. Default: 30.
	HalfLifeMinutes int
	// IntervalSeconds: how often the decay tick fires. Default: 60.
	IntervalSeconds int
	// FSM thresholds — must match the values used by all SDK middlewares.
	WarnThreshold      int
	SlowThreshold      int
	BlockThreshold     int
	BlacklistThreshold int
}

func (c *Config) halfLifeMs() int64 {
	if c.HalfLifeMinutes <= 0 {
		c.HalfLifeMinutes = 30
	}
	return int64(c.HalfLifeMinutes) * 60 * 1000
}

func (c *Config) interval() time.Duration {
	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = 60
	}
	return time.Duration(c.IntervalSeconds) * time.Second
}

// Worker applies score decay on a regular interval.
type Worker struct {
	store *store.Store
	cfg   Config
}

// New creates a decay Worker.
func New(s *store.Store, cfg Config) *Worker {
	return &Worker{store: s, cfg: cfg}
}

// Run starts the decay loop and blocks until ctx is cancelled.
// Call in a goroutine: go worker.Run(ctx)
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.interval())
	defer ticker.Stop()

	slog.Info("decay worker started",
		slog.Int("half_life_minutes", w.cfg.HalfLifeMinutes),
		slog.Int("interval_seconds", w.cfg.IntervalSeconds),
	)

	for {
		select {
		case <-ctx.Done():
			slog.Info("decay worker stopped")
			return
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	ips, err := w.store.ScanPenaltyIPs(ctx)
	if err != nil {
		slog.Error("decay: scan failed", slog.String("err", err.Error()))
		return
	}
	if len(ips) == 0 {
		return
	}

	halfLifeMs := w.cfg.halfLifeMs()
	var decayed, cleared int

	for _, ip := range ips {
		r, err := w.store.DecayScore(ctx, ip, halfLifeMs,
			w.cfg.WarnThreshold, w.cfg.SlowThreshold,
			w.cfg.BlockThreshold, w.cfg.BlacklistThreshold,
		)
		if err != nil {
			slog.Warn("decay: score failed", slog.String("ip", ip), slog.String("err", err.Error()))
			continue
		}
		if r.Decrement > 0 {
			decayed++
			slog.Debug("decay: applied",
				slog.String("ip", ip),
				slog.Int("decrement", r.Decrement),
				slog.Int("new_score", r.NewScore),
				slog.String("new_state", r.NewState),
			)
		}
		if r.NewScore == 0 {
			cleared++
		}
	}

	if decayed > 0 {
		slog.Info("decay tick",
			slog.Int("ips_scanned", len(ips)),
			slog.Int("decayed", decayed),
			slog.Int("cleared_to_zero", cleared),
		)
	}
}
