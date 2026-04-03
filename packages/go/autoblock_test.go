package autoblock

import (
	"context"
	"fmt"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// startRedis spins up a real Redis 7 container and returns a connected client.
// The container is stopped in t.Cleanup so the test binary handles teardown.
func startRedis(t *testing.T) *redis.Client {
	t.Helper()
	ctx := context.Background()

	container, err := tcredis.Run(ctx, "redis:7-alpine")
	require.NoError(t, err, "start Redis container")

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("terminate Redis container: %v", err)
		}
	})

	addr, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{Addr: addr[len("redis://"):]})
	t.Cleanup(func() { rdb.Close() })

	return rdb
}

func newLimiter(t *testing.T, rdb *redis.Client, rules ...Rule) *Limiter {
	t.Helper()
	l, err := New(Config{
		Tenant: "test",
		Redis:  rdb,
		Rules:  rules,
		Thresholds: Thresholds{
			Warn: 3, Slow: 6, Block: 10, Blacklist: 15,
		},
	})
	require.NoError(t, err)
	return l
}

func loginRule() Rule {
	return Rule{
		Path:          "/api/auth/login",
		Limit:         5,
		WindowSeconds: 60,
		Algorithm:     AlgorithmSlidingWindow,
	}
}

// ---------------------------------------------------------------------------
// New / config validation
// ---------------------------------------------------------------------------

func TestNew_RequiresTenant(t *testing.T) {
	rdb := startRedis(t)
	_, err := New(Config{Redis: rdb})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant")
}

func TestNew_RequiresRedis(t *testing.T) {
	_, err := New(Config{Tenant: "t"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redis")
}

func TestNew_InvalidRulePattern(t *testing.T) {
	rdb := startRedis(t)
	_, err := New(Config{
		Tenant: "t",
		Redis:  rdb,
		Rules:  []Rule{{Path: "[invalid", Limit: 10, WindowSeconds: 60}},
	})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Allow / deny basics
// ---------------------------------------------------------------------------

func TestEvaluate_AllowsUnmatchedPath(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())

	d := l.Evaluate(context.Background(), "1.2.3.4", "", "/api/products")
	assert.True(t, d.Allowed)
	assert.Equal(t, StateClean, d.State)
}

func TestEvaluate_AllowsUnderLimit(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())

	d := l.Evaluate(context.Background(), "1.2.3.4", "", "/api/auth/login")
	assert.True(t, d.Allowed)
	assert.Equal(t, 0, d.StatusCode)
}

func TestEvaluate_DeniesOverLimit(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())

	ctx := context.Background()
	ip := "10.0.0.1"

	// Exhaust the 5-request limit
	for i := 0; i < 5; i++ {
		l.Evaluate(ctx, ip, "", "/api/auth/login")
	}

	// 6th request: over limit → penalty incremented → eventually denied
	var gotDenied bool
	for i := 0; i < 15; i++ {
		d := l.Evaluate(ctx, ip, "", "/api/auth/login")
		if !d.Allowed {
			gotDenied = true
			assert.Greater(t, d.StatusCode, 0)
			break
		}
	}
	assert.True(t, gotDenied, "expected at least one denied response")
}

func TestEvaluate_WhitelistedIPAlwaysAllowed(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())

	ctx := context.Background()
	ip := "192.168.1.100"
	err := rdb.SAdd(ctx, "ab:test:whitelist:ip", ip).Err()
	require.NoError(t, err)

	// Exhaust well past limit
	for i := 0; i < 30; i++ {
		d := l.Evaluate(ctx, ip, "", "/api/auth/login")
		assert.True(t, d.Allowed, "whitelisted IP should always be allowed (iteration %d)", i)
	}
}

func TestEvaluate_BlacklistedIPReturns403(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())

	ctx := context.Background()
	ip := "5.5.5.5"
	// Add to blacklist with far-future expiry
	expiry := int64(9999999999)
	err := rdb.ZAdd(ctx, "ab:test:blacklist:ip", redis.Z{Score: float64(expiry), Member: ip}).Err()
	require.NoError(t, err)

	d := l.Evaluate(ctx, ip, "", "/api/auth/login")
	assert.False(t, d.Allowed)
	assert.Equal(t, 403, d.StatusCode)
	assert.Equal(t, StateBlacklist, d.State)
}

func TestEvaluate_PenaltyEscalatesAfterViolations(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())

	ctx := context.Background()
	ip := "10.1.0.1"

	states := map[PenaltyState]bool{}
	for i := 0; i < 40; i++ {
		d := l.Evaluate(ctx, ip, "", "/api/auth/login")
		states[d.State] = true
	}

	// Should have seen at least WARN and BLOCK
	assert.True(t, states[StateWarn] || states[StateSlow] || states[StateBlock],
		"expected penalty escalation beyond CLEAN, got states: %v", states)
}

func TestEvaluate_TokenBucketAlgorithm(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, Rule{
		Path:          "/api/token",
		Limit:         3,
		WindowSeconds: 60,
		Algorithm:     AlgorithmTokenBucket,
	})

	ctx := context.Background()
	ip := "10.2.0.1"

	for i := 0; i < 3; i++ {
		d := l.Evaluate(ctx, ip, "", "/api/token")
		assert.True(t, d.Allowed, "request %d should be allowed", i+1)
	}
}

func TestEvaluate_HybridAlgorithm(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, Rule{
		Path:          "/api/hybrid",
		Limit:         5,
		WindowSeconds: 60,
		Algorithm:     AlgorithmHybrid,
	})

	ctx := context.Background()
	ip := "10.3.0.1"

	d := l.Evaluate(ctx, ip, "", "/api/hybrid")
	assert.True(t, d.Allowed)
}

func TestEvaluate_MultipleRules_FirstMatchWins(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb,
		Rule{Path: "/api/auth/login", Limit: 3, WindowSeconds: 60, Algorithm: AlgorithmSlidingWindow},
		Rule{Path: "/api/**", Limit: 100, WindowSeconds: 60, Algorithm: AlgorithmSlidingWindow},
	)

	ctx := context.Background()
	ip := "10.4.0.1"

	// Login endpoint uses tight limit (3)
	for i := 0; i < 3; i++ {
		l.Evaluate(ctx, ip, "", "/api/auth/login")
	}
	// 4th on login → over limit
	got429 := false
	for i := 0; i < 10; i++ {
		d := l.Evaluate(ctx, ip, "", "/api/auth/login")
		if !d.Allowed {
			got429 = true
			break
		}
	}
	assert.True(t, got429)

	// Products endpoint uses loose limit (100) — same IP should still be OK
	d := l.Evaluate(ctx, ip, "", "/api/products")
	assert.True(t, d.Allowed, "/api/products should use the 100-req rule")
}

// ---------------------------------------------------------------------------
// Per-user dimension
// ---------------------------------------------------------------------------

func TestEvaluate_PerUserDimension(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, Rule{
		Path:          "/api/search",
		Limit:         5,
		WindowSeconds: 60,
		Algorithm:     AlgorithmSlidingWindow,
		PerUser:       true,
	})

	ctx := context.Background()

	// user-A exhausts their quota
	for i := 0; i < 10; i++ {
		l.Evaluate(ctx, "10.5.0.1", "user-A", "/api/search")
	}

	// user-B on the same IP should still be allowed initially
	d := l.Evaluate(ctx, "10.5.0.1", "user-B", "/api/search")
	assert.True(t, d.Allowed, "user-B should not be penalised for user-A's violations")
}

// ---------------------------------------------------------------------------
// AntToRegexp patterns
// ---------------------------------------------------------------------------

func TestEvaluate_AntPatterns(t *testing.T) {
	rdb := startRedis(t)

	tests := []struct {
		pattern string
		path    string
		wantHit bool
	}{
		{"/api/auth/login", "/api/auth/login", true},
		{"/api/auth/login", "/api/auth/logout", false},
		{"/api/**", "/api/users/123/orders", true},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/123", false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s~%s", tc.pattern, tc.path), func(t *testing.T) {
			l := newLimiter(t, rdb, Rule{
				Path:          tc.pattern,
				Limit:         1,
				WindowSeconds: 60,
				Algorithm:     AlgorithmSlidingWindow,
			})

			// First call: if pattern matches, remaining will be < Infinity
			d := l.Evaluate(context.Background(), "unique-ip-"+tc.path, "", tc.path)

			if tc.wantHit {
				// matched: remaining is finite (< MaxInt)
				assert.Less(t, d.Remaining, 1<<30, "expected rule to match path %q", tc.path)
			} else {
				// no match: unlimited remaining
				assert.Greater(t, d.Remaining, 1<<20, "expected rule NOT to match path %q", tc.path)
			}
		})
	}
}
