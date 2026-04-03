package autoblock

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"
)

const defaultPollInterval = 30 * time.Second

// RulesWatcher polls ab:{tenant}:rules:endpoint every interval and hot-reloads
// the Limiter's rule set without restarting the process.
//
// Usage:
//
//	watcher := limiter.NewWatcher(autoblock.WatcherOptions{})
//	go watcher.Run(ctx)
type RulesWatcher struct {
	limiter  *Limiter
	interval time.Duration
	onReload func([]Rule)
	onError  func(error)
}

// WatcherOptions configure hot-reload behaviour.
type WatcherOptions struct {
	// Interval between Redis polls. Default: 30 s.
	Interval time.Duration
	// OnReload is called after each successful rule swap.
	OnReload func([]Rule)
	// OnError is called when a poll cycle fails.
	OnError func(error)
}

// NewWatcher creates a RulesWatcher attached to this Limiter.
func (l *Limiter) NewWatcher(opts WatcherOptions) *RulesWatcher {
	interval := opts.Interval
	if interval <= 0 {
		interval = defaultPollInterval
	}
	return &RulesWatcher{
		limiter:  l,
		interval: interval,
		onReload: opts.OnReload,
		onError:  opts.OnError,
	}
}

// Run blocks, polls Redis on a ticker, AND subscribes to the
// ab:{tenant}:rules:changed pub/sub channel for instant invalidation.
// Intended to be launched in a goroutine: go watcher.Run(ctx)
func (w *RulesWatcher) Run(ctx context.Context) {
	// Immediate first load before the ticker fires.
	if err := w.Poll(ctx); err != nil {
		w.handleError(err)
	}

	// Subscribe to push notifications from the engine.
	// On any message we poll immediately instead of waiting for the ticker.
	pushCh := w.subscribePush(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.Poll(ctx); err != nil {
				w.handleError(err)
			}
		case _, ok := <-pushCh:
			if !ok {
				// Channel closed — subscription dropped; fall back to ticker only.
				pushCh = nil
				continue
			}
			slog.Debug("autoblock RulesWatcher: push notification received, reloading immediately")
			if err := w.Poll(ctx); err != nil {
				w.handleError(err)
			}
		}
	}
}

// subscribePush subscribes to the rules:changed pub/sub channel and returns a
// channel that receives one value per publish event.  Returns a nil channel if
// the subscription fails (falls back gracefully to ticker-only mode).
func (w *RulesWatcher) subscribePush(ctx context.Context) <-chan struct{} {
	channel := w.limiter.keys.rulesChanged()
	pubsub := w.limiter.cfg.Redis.Subscribe(ctx, channel)

	// Verify subscription is alive.
	if _, err := pubsub.Receive(ctx); err != nil {
		slog.Debug("autoblock RulesWatcher: pub/sub unavailable, using poll-only mode", "error", err)
		pubsub.Close()
		return nil
	}

	slog.Debug("autoblock RulesWatcher: subscribed to push channel", "channel", channel)

	out := make(chan struct{}, 1)
	go func() {
		defer pubsub.Close()
		defer close(out)
		msgCh := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-msgCh:
				if !ok {
					return
				}
				// Non-blocking send: if a reload is already queued, skip duplicate.
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out
}

// Poll performs a single reload cycle. Callable directly in tests.
func (w *RulesWatcher) Poll(ctx context.Context) error {
	raw, err := w.limiter.cfg.Redis.HGetAll(ctx, w.limiter.keys.rules()).Result()
	if err != nil {
		return err
	}

	dynamic := parseDynamicRules(raw)
	w.limiter.mergeRules(dynamic)

	if w.onReload != nil {
		w.onReload(dynamic)
	}
	return nil
}

func (w *RulesWatcher) handleError(err error) {
	slog.Warn("autoblock RulesWatcher poll error", "error", err)
	if w.onError != nil {
		w.onError(err)
	}
}

// ---------------------------------------------------------------------------
// Rule parsing from Redis hash
// ---------------------------------------------------------------------------

type redisRule struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	Limit         int    `json:"limit"`
	WindowSeconds int    `json:"window_seconds"`
	Algorithm     string `json:"algorithm"`
	PerUser       bool   `json:"per_user"`
	PerEndpoint   bool   `json:"per_endpoint"`
	Enabled       bool   `json:"enabled"`
}

func parseDynamicRules(raw map[string]string) []Rule {
	rules := make([]Rule, 0, len(raw))
	for _, jsonStr := range raw {
		var r redisRule
		if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
			continue
		}
		if !r.Enabled {
			continue
		}
		algo := Algorithm(r.Algorithm)
		if algo == "" {
			algo = AlgorithmHybrid
		}
		ws := r.WindowSeconds
		if ws <= 0 {
			ws = 60
		}
		rules = append(rules, Rule{
			Path:          r.Path,
			Limit:         r.Limit,
			WindowSeconds: ws,
			Algorithm:     algo,
			PerUser:       r.PerUser,
			PerEndpoint:   r.PerEndpoint,
		})
	}
	return rules
}

// ---------------------------------------------------------------------------
// Atomic rule swap on Limiter
// ---------------------------------------------------------------------------

// atomicRules is stored in Limiter to allow lock-free rule replacement.
type atomicRules struct {
	v atomic.Pointer[[]compiledRule]
}

func newAtomicRules(rules []compiledRule) *atomicRules {
	a := &atomicRules{}
	a.v.Store(&rules)
	return a
}

func (a *atomicRules) load() []compiledRule {
	return *a.v.Load()
}

func (a *atomicRules) store(rules []compiledRule) {
	a.v.Store(&rules)
}

// mergeRules replaces the live rule set with dynamic rules merged over the
// static config rules.  Thread-safe via atomic.Pointer.
func (l *Limiter) mergeRules(dynamic []Rule) {
	// Build set of dynamic ids to detect which static rules survive.
	dynIDs := make(map[string]bool, len(dynamic))
	for _, r := range dynamic {
		dynIDs[r.Path] = true // use Path as identifier (id not in Rule struct)
	}

	merged := make([]Rule, 0, len(dynamic)+len(l.cfg.Rules))
	merged = append(merged, dynamic...)
	for _, r := range l.cfg.Rules {
		if !dynIDs[r.Path] {
			merged = append(merged, r)
		}
	}

	compiled, err := compileRules(merged)
	if err != nil {
		slog.Warn("autoblock mergeRules compile error", "error", err)
		return
	}
	l.atomicRules.store(compiled)
}
