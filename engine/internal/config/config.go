package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Tenant        string              `mapstructure:"tenant"`
	Redis         RedisConfig         `mapstructure:"redis"`
	Remediation   RemediationConfig   `mapstructure:"remediation"`
	WAF           WAFConfig           `mapstructure:"waf"`
	Notifications NotificationsConfig `mapstructure:"notifications"`
	API           APIConfig           `mapstructure:"api"`
	Metrics       MetricsConfig       `mapstructure:"metrics"`
}

type RedisConfig struct {
	URL                   string `mapstructure:"url"`
	KeyPrefix             string `mapstructure:"key_prefix"`
	KeyspaceNotifications bool   `mapstructure:"keyspace_notifications"`
}

type RemediationConfig struct {
	Enabled             bool        `mapstructure:"enabled"`
	WatcherMode         string      `mapstructure:"watcher_mode"` // pubsub | poll
	PollIntervalSeconds int         `mapstructure:"poll_interval_seconds"`
	DebounceSeconds     int         `mapstructure:"debounce_seconds"`
	MinScoreForWAF      int         `mapstructure:"min_score_for_waf"`
	TargetSeconds       int         `mapstructure:"target_remediation_seconds"`
	Decay               DecayConfig `mapstructure:"decay"`
}

type DecayConfig struct {
	Enabled             bool `mapstructure:"enabled"`
	HalfLifeMinutes     int  `mapstructure:"half_life_minutes"`
	IntervalSeconds     int  `mapstructure:"interval_seconds"`
	WarnThreshold       int  `mapstructure:"warn_threshold"`
	SlowThreshold       int  `mapstructure:"slow_threshold"`
	BlockThreshold      int  `mapstructure:"block_threshold"`
	BlacklistThreshold  int  `mapstructure:"blacklist_threshold"`
}

type WAFConfig struct {
	Providers []WAFProviderConfig `mapstructure:"providers"`
}

type WAFProviderConfig struct {
	Name    string         `mapstructure:"name"`
	Enabled bool           `mapstructure:"enabled"`
	Type    string         `mapstructure:"type"`
	Config  map[string]any `mapstructure:"config"`
}

type NotificationsConfig struct {
	Slack     SlackConfig     `mapstructure:"slack"`
	PagerDuty PagerDutyConfig `mapstructure:"pagerduty"`
}

type PagerDutyConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	IntegrationKey string `mapstructure:"integration_key"`
}

type SlackConfig struct {
	Enabled        bool     `mapstructure:"enabled"`
	WebhookURL     string   `mapstructure:"webhook_url"`
	Channel        string   `mapstructure:"channel"`
	SeverityFilter []string `mapstructure:"severity_filter"`
	MaxPerMinute   int      `mapstructure:"max_per_minute"`
}

type APIConfig struct {
	Listen string     `mapstructure:"listen"`
	Auth   AuthConfig `mapstructure:"auth"`
}

type AuthConfig struct {
	Enabled bool      `mapstructure:"enabled"`
	Keys    []APIKey  `mapstructure:"keys"`
}

type APIKey struct {
	Key  string `mapstructure:"key"`
	Role string `mapstructure:"role"` // admin | readonly
}

type MetricsConfig struct {
	Prometheus PrometheusConfig `mapstructure:"prometheus"`
}

type PrometheusConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Listen  string `mapstructure:"listen"`
	Path    string `mapstructure:"path"`
}

func Load(path string) (*Config, error) {
	v := viper.New()

	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.SetConfigName("autoblock")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/autoblock")
	}

	v.SetEnvPrefix("AUTOBLOCK")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Defaults
	v.SetDefault("tenant", "default")
	v.SetDefault("redis.url", "redis://localhost:6379")
	v.SetDefault("redis.key_prefix", "ab")
	v.SetDefault("redis.keyspace_notifications", true)
	v.SetDefault("remediation.enabled", true)
	v.SetDefault("remediation.watcher_mode", "pubsub")
	v.SetDefault("remediation.poll_interval_seconds", 5)
	v.SetDefault("remediation.debounce_seconds", 3)
	v.SetDefault("remediation.min_score_for_waf", 15)
	v.SetDefault("remediation.target_remediation_seconds", 60)
	v.SetDefault("remediation.decay.enabled", false)
	v.SetDefault("remediation.decay.half_life_minutes", 30)
	v.SetDefault("remediation.decay.interval_seconds", 60)
	v.SetDefault("remediation.decay.warn_threshold", 3)
	v.SetDefault("remediation.decay.slow_threshold", 6)
	v.SetDefault("remediation.decay.block_threshold", 10)
	v.SetDefault("remediation.decay.blacklist_threshold", 15)
	v.SetDefault("api.listen", ":8080")
	v.SetDefault("api.auth.enabled", true)
	v.SetDefault("metrics.prometheus.enabled", true)
	v.SetDefault("metrics.prometheus.listen", ":9090")
	v.SetDefault("metrics.prometheus.path", "/metrics")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("config: read: %w", err)
		}
		// No config file is fine — use defaults + env vars
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	return &cfg, nil
}
