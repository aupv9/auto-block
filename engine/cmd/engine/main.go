package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/autoblock/autoblock/internal/audit"
	"github.com/autoblock/autoblock/internal/config"
	"github.com/autoblock/autoblock/internal/decay"
	"github.com/autoblock/autoblock/internal/metrics"
	"github.com/autoblock/autoblock/internal/notifier"
	"github.com/autoblock/autoblock/internal/remediation"
	"github.com/autoblock/autoblock/internal/store"
	"github.com/autoblock/autoblock/internal/waf"
	"github.com/redis/go-redis/v9"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfgPath := os.Getenv("AUTOBLOCK_CONFIG")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("failed to load config", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Redis client
	opts, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		slog.Error("invalid redis url", slog.String("err", err.Error()))
		os.Exit(1)
	}
	rdb := redis.NewClient(opts)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("redis unreachable", slog.String("err", err.Error()))
		os.Exit(1)
	}
	slog.Info("redis connected", slog.String("url", cfg.Redis.URL))

	// Enable keyspace notifications (requires CONFIG SET permission)
	if cfg.Redis.KeyspaceNotifications {
		if err := rdb.ConfigSet(ctx, "notify-keyspace-events", "KEA").Err(); err != nil {
			slog.Warn("could not enable keyspace notifications (may need Redis config permission)",
				slog.String("err", err.Error()))
		}
	}

	// Build WAF providers
	providers := waf.BuildProviders(cfg.WAF)
	if len(providers) == 0 {
		slog.Warn("no WAF providers configured — remediation will only update Redis blacklist")
	}
	wafProvider := waf.NewMultiProvider(providers)

	// Notifiers — fan-out to all enabled
	var notifiers []notifier.Notifier
	if cfg.Notifications.Slack.Enabled {
		notifiers = append(notifiers, notifier.NewSlack(
			cfg.Notifications.Slack.WebhookURL, cfg.Notifications.Slack.Channel,
		))
		slog.Info("slack notifier enabled", slog.String("channel", cfg.Notifications.Slack.Channel))
	}
	if cfg.Notifications.PagerDuty.Enabled {
		notifiers = append(notifiers, notifier.NewPagerDuty(cfg.Notifications.PagerDuty.IntegrationKey))
		slog.Info("pagerduty notifier enabled")
	}
	var n notifier.Notifier = notifier.Noop{}
	if len(notifiers) == 1 {
		n = notifiers[0]
	} else if len(notifiers) > 1 {
		n = notifier.NewMulti(notifiers...)
	}

	// Build audit writer
	redisStore := store.New(rdb, cfg.Tenant, cfg.Redis.KeyPrefix)
	auditWriter := audit.NewStreamWriter(rdb, redisStore.AuditStreamKey())

	// Metrics
	metrics.Register()

	// Score decay worker (disabled by default; enable via remediation.decay.enabled)
	if cfg.Remediation.Decay.Enabled {
		d := cfg.Remediation.Decay
		go decay.New(redisStore, decay.Config{
			HalfLifeMinutes:    d.HalfLifeMinutes,
			IntervalSeconds:    d.IntervalSeconds,
			WarnThreshold:      d.WarnThreshold,
			SlowThreshold:      d.SlowThreshold,
			BlockThreshold:     d.BlockThreshold,
			BlacklistThreshold: d.BlacklistThreshold,
		}).Run(ctx)
		slog.Info("score decay enabled",
			slog.Int("half_life_minutes", d.HalfLifeMinutes),
			slog.Int("interval_seconds", d.IntervalSeconds),
		)
	}

	// Remediation engine
	eng := remediation.NewEngine(remediation.Config{
		Tenant:          cfg.Tenant,
		DebounceSeconds: cfg.Remediation.DebounceSeconds,
		MinScoreForWAF:  cfg.Remediation.MinScoreForWAF,
		Store:           redisStore,
		WAF:             wafProvider,
		Notifier:        n,
		Audit:           auditWriter,
	})

	slog.Info("autoblock engine starting",
		slog.String("watcher_mode", cfg.Remediation.WatcherMode),
		slog.Int("debounce_seconds", cfg.Remediation.DebounceSeconds),
		slog.Int("min_score_for_waf", cfg.Remediation.MinScoreForWAF),
	)

	if err := eng.Run(ctx, rdb, cfg.Remediation.WatcherMode, cfg.Remediation.PollIntervalSeconds); err != nil {
		slog.Error("engine stopped with error", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = rdb.Shutdown(shutdownCtx).Err()
	slog.Info("engine shutdown complete")
}
