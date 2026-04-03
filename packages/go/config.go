// Package autoblock provides adaptive multi-layer rate limiting middleware
// for Go HTTP servers (net/http, chi, gin, echo, etc.).
//
// Usage:
//
//	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
//	limiter, _ := autoblock.New(autoblock.Config{
//	    Tenant:   "my-app",
//	    Redis:    rdb,
//	    Rules: []autoblock.Rule{
//	        {Path: "/api/auth/login", Limit: 10, WindowSeconds: 60, Algorithm: AlgorithmHybrid},
//	    },
//	})
//	http.Handle("/", limiter.Middleware(myHandler))
package autoblock

import "github.com/redis/go-redis/v9"

// Algorithm selects the rate-limiting algorithm for a rule.
type Algorithm string

const (
	AlgorithmSlidingWindow Algorithm = "sliding_window"
	AlgorithmTokenBucket   Algorithm = "token_bucket"
	// AlgorithmHybrid requires both sliding-window AND token-bucket to pass.
	// Catches sustained abuse AND bursts. Recommended for auth endpoints.
	AlgorithmHybrid Algorithm = "hybrid"
)

// Config configures the AutoBlock rate limiter.
type Config struct {
	// Tenant namespaces all Redis keys. Required.
	Tenant string
	// Redis is the go-redis client. Required.
	Redis *redis.Client
	// KeyPrefix is the Redis key prefix. Defaults to "ab".
	KeyPrefix string
	// Rules is the list of rate-limit rules evaluated in order; first match wins.
	Rules []Rule
	// Thresholds for the penalty FSM. Defaults: WARN=3, SLOW=6, BLOCK=10, BLACKLIST=15.
	Thresholds Thresholds
	// FailOpen allows requests through when Redis is unavailable. Default: true.
	FailOpen *bool
	// TrustProxy enables reading client IP from X-Forwarded-For. Default: false.
	TrustProxy bool
	// TrustProxyDepth: number of trusted proxy hops. Default: 1.
	TrustProxyDepth int
}

// Rule defines a rate-limit policy for a path pattern.
type Rule struct {
	// Path is an Ant-style pattern, e.g. "/api/auth/login" or "/api/**".
	Path          string
	Limit         int
	WindowSeconds int
	Algorithm     Algorithm
	// PerUser evaluates an additional dimension per authenticated user ID.
	PerUser bool
	// PerEndpoint scopes the counter to the exact path (prevents cross-path sharing).
	PerEndpoint bool
}

func (r Rule) windowMs() int64 { return int64(r.WindowSeconds) * 1000 }

// Thresholds define the penalty score at which each FSM state is entered.
type Thresholds struct {
	Warn      int // Default 3
	Slow      int // Default 6
	Block     int // Default 10
	Blacklist int // Default 15
}

func (t *Thresholds) withDefaults() Thresholds {
	out := *t
	if out.Warn == 0      { out.Warn = 3 }
	if out.Slow == 0      { out.Slow = 6 }
	if out.Block == 0     { out.Block = 10 }
	if out.Blacklist == 0 { out.Blacklist = 15 }
	return out
}

func (c *Config) failOpen() bool {
	if c.FailOpen == nil {
		return true
	}
	return *c.FailOpen
}

func (c *Config) keyPrefix() string {
	if c.KeyPrefix == "" {
		return "ab"
	}
	return c.KeyPrefix
}

func (c *Config) trustProxyDepth() int {
	if c.TrustProxyDepth <= 0 {
		return 1
	}
	return c.TrustProxyDepth
}
