// Package waf defines the WAFProvider interface and provider registry.
package waf

import (
	"context"
	"log/slog"
	"time"

	"github.com/autoblock/autoblock/internal/config"
)

// Provider is the interface all WAF backends must implement.
type Provider interface {
	// AddToBlocklist adds an IP to the WAF deny list with an optional TTL (0 = permanent).
	AddToBlocklist(ctx context.Context, ip string, ttl time.Duration, reason string) error
	// RemoveFromBlocklist removes an IP from the WAF deny list.
	RemoveFromBlocklist(ctx context.Context, ip string) error
	// IsBlocked reports whether an IP is currently blocked in this WAF.
	IsBlocked(ctx context.Context, ip string) (bool, error)
	// HealthCheck verifies connectivity to the WAF provider.
	HealthCheck(ctx context.Context) error
	// Name returns the unique identifier for this provider.
	Name() string
}

// BuildProviders constructs enabled WAF providers from config.
func BuildProviders(cfg config.WAFConfig) []Provider {
	var providers []Provider
	for _, pc := range cfg.Providers {
		if !pc.Enabled {
			continue
		}
		p, err := newProvider(pc)
		if err != nil {
			slog.Error("failed to init waf provider",
				slog.String("name", pc.Name),
				slog.String("type", pc.Type),
				slog.String("err", err.Error()),
			)
			continue
		}
		providers = append(providers, p)
		slog.Info("waf provider registered", slog.String("name", pc.Name), slog.String("type", pc.Type))
	}
	return providers
}

func newProvider(pc config.WAFProviderConfig) (Provider, error) {
	switch pc.Type {
	case "aws_waf":
		return newAWSWAF(pc)
	case "cloudflare":
		return newCloudflareWAF(pc)
	case "nginx":
		return newNginxWAF(pc)
	default:
		slog.Warn("unknown waf provider type, skipping", slog.String("type", pc.Type))
		return nil, nil
	}
}
