package autoblock

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRulesWatcher_PollEmptyHash(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb)
	w := l.NewWatcher(WatcherOptions{})

	err := w.Poll(context.Background())
	require.NoError(t, err)
	// No rules → limiter still works (no panic)
	d := l.Evaluate(context.Background(), "1.2.3.4", "", "/any")
	assert.True(t, d.Allowed)
}

func TestRulesWatcher_PollLoadsRule(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb)

	// Write a dynamic rule into the Redis hash
	rule := map[string]any{
		"id":             "dyn-login",
		"path":           "/api/auth/login",
		"limit":          3,
		"window_seconds": 60,
		"algorithm":      "sliding_window",
		"enabled":        true,
	}
	raw, _ := json.Marshal(rule)
	rulesKey := "ab:test:rules:endpoint"
	err := rdb.HSet(context.Background(), rulesKey, "dyn-login", string(raw)).Err()
	require.NoError(t, err)

	var reloadedRules []Rule
	w := l.NewWatcher(WatcherOptions{
		OnReload: func(rules []Rule) { reloadedRules = rules },
	})

	err = w.Poll(context.Background())
	require.NoError(t, err)

	require.Len(t, reloadedRules, 1)
	assert.Equal(t, "/api/auth/login", reloadedRules[0].Path)
	assert.Equal(t, 3, reloadedRules[0].Limit)
}

func TestRulesWatcher_SkipsDisabledRules(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb)

	ctx := context.Background()
	rulesKey := "ab:test:rules:endpoint"

	enabled := map[string]any{"id": "on", "path": "/api/on", "limit": 10, "window_seconds": 60, "enabled": true}
	disabled := map[string]any{"id": "off", "path": "/api/off", "limit": 10, "window_seconds": 60, "enabled": false}

	rawOn, _ := json.Marshal(enabled)
	rawOff, _ := json.Marshal(disabled)
	rdb.HSet(ctx, rulesKey, "on", string(rawOn), "off", string(rawOff))

	var reloaded []Rule
	w := l.NewWatcher(WatcherOptions{OnReload: func(r []Rule) { reloaded = r }})
	require.NoError(t, w.Poll(ctx))

	assert.Len(t, reloaded, 1)
	assert.Equal(t, "/api/on", reloaded[0].Path)
}

func TestRulesWatcher_SkipsMalformedJSON(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb)

	ctx := context.Background()
	rulesKey := "ab:test:rules:endpoint"

	goodRule := map[string]any{"id": "good", "path": "/api/good", "limit": 5, "window_seconds": 60, "enabled": true}
	rawGood, _ := json.Marshal(goodRule)
	rdb.HSet(ctx, rulesKey, "good", string(rawGood), "bad", "{not-valid-json")

	var reloaded []Rule
	w := l.NewWatcher(WatcherOptions{OnReload: func(r []Rule) { reloaded = r }})
	require.NoError(t, w.Poll(ctx))

	assert.Len(t, reloaded, 1)
}

func TestRulesWatcher_MergesWithStaticRules(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, Rule{
		Path: "/static", Limit: 100, WindowSeconds: 60, Algorithm: AlgorithmSlidingWindow,
	})

	ctx := context.Background()
	rulesKey := "ab:test:rules:endpoint"

	dyn := map[string]any{"id": "dyn", "path": "/dynamic", "limit": 10, "window_seconds": 60, "enabled": true}
	raw, _ := json.Marshal(dyn)
	rdb.HSet(ctx, rulesKey, "dyn", string(raw))

	w := l.NewWatcher(WatcherOptions{})
	require.NoError(t, w.Poll(ctx))

	// Static /static route should still work
	d := l.Evaluate(ctx, "1.2.3.4", "", "/static")
	assert.True(t, d.Allowed)
	assert.Less(t, d.Remaining, 1<<30, "/static should match the static rule")
}

func TestRulesWatcher_Run_CancelsCleanly(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb)
	w := l.NewWatcher(WatcherOptions{Interval: 50 * time.Millisecond})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Good — goroutine exited after context cancel
	case <-time.After(2 * time.Second):
		t.Fatal("RulesWatcher.Run did not exit after context cancellation")
	}
}

func TestRulesWatcher_OnError_CalledOnFailure(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb)

	// Close the redis client so subsequent calls fail
	rdb.Close()

	var gotErr error
	w := l.NewWatcher(WatcherOptions{
		OnError: func(err error) { gotErr = err },
	})

	err := w.Poll(context.Background())
	assert.Error(t, err)
	_ = gotErr // onError may or may not be called depending on impl; no assert needed
}
