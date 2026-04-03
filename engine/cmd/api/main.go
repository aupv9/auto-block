package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/autoblock/autoblock/internal/config"
	"github.com/autoblock/autoblock/internal/metrics"
	"github.com/autoblock/autoblock/internal/router"
	"github.com/autoblock/autoblock/internal/store"
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

	redisStore := store.New(rdb, cfg.Tenant, cfg.Redis.KeyPrefix)
	metrics.Register()

	r := router.New(redisStore, cfg.API.Auth)

	// Prometheus metrics server (separate port)
	if cfg.Metrics.Prometheus.Enabled {
		go func() {
			mux := http.NewServeMux()
			mux.Handle(cfg.Metrics.Prometheus.Path, metrics.Handler())
			srv := &http.Server{Addr: cfg.Metrics.Prometheus.Listen, Handler: mux}
			slog.Info("metrics server listening", slog.String("addr", cfg.Metrics.Prometheus.Listen))
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("metrics server error", slog.String("err", err.Error()))
			}
		}()
	}

	srv := &http.Server{Addr: cfg.API.Listen, Handler: r}
	slog.Info("api server listening", slog.String("addr", cfg.API.Listen))

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("api server error", slog.String("err", err.Error()))
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down api server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", slog.String("err", err.Error()))
	}
	slog.Info("api shutdown complete")
}
