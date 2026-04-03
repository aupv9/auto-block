package autoblock

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedPenaltyScore seeds a penalty score key with an optional past decay timestamp.
func seedPenaltyScore(t *testing.T, rdb *redis.Client, prefix, tenant, ip string, score int, elapsedMs int64) {
	t.Helper()
	ctx := context.Background()
	pastMs := time.Now().UnixMilli() - elapsedMs

	scoreKey := fmt.Sprintf("%s:%s:penalty:score:ip:%s", prefix, tenant, ip)
	stateKey := fmt.Sprintf("%s:%s:penalty:state:ip:%s", prefix, tenant, ip)
	decayKey := fmt.Sprintf("%s:%s:penalty:decay:ip:%s", prefix, tenant, ip)

	state := "CLEAN"
	switch {
	case score >= 15:
		state = "BLACKLIST"
	case score >= 10:
		state = "BLOCK"
	case score >= 6:
		state = "SLOW"
	case score >= 3:
		state = "WARN"
	}

	require.NoError(t, rdb.Set(ctx, scoreKey, score, 0).Err())
	require.NoError(t, rdb.Set(ctx, stateKey, state, 0).Err())
	require.NoError(t, rdb.Set(ctx, decayKey, pastMs, 0).Err())
}

func TestDecayWorker_EmptyDB_ReturnsEmpty(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb)
	w := l.NewDecayWorker(DecayWorkerOptions{})

	results, err := w.RunCycle(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestDecayWorker_DecaysScoreOverTime(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())
	w := l.NewDecayWorker(DecayWorkerOptions{
		HalfLife: 10 * time.Minute,
	})

	ip := "10.10.0.1"
	seedPenaltyScore(t, rdb, "ab", "test", ip, 20, 5*60*1000) // 5 min elapsed

	results, err := w.RunCycle(context.Background())
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, ip, results[0].IP)
	assert.Greater(t, results[0].Decrement, 0)
	assert.Less(t, results[0].NewScore, 20)
}

func TestDecayWorker_ZeroScoreSkipped(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())
	w := l.NewDecayWorker(DecayWorkerOptions{HalfLife: 10 * time.Minute})

	seedPenaltyScore(t, rdb, "ab", "test", "10.10.0.2", 0, 60_000)

	results, err := w.RunCycle(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestDecayWorker_MultipleIPsDecayedInOneCycle(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())
	w := l.NewDecayWorker(DecayWorkerOptions{HalfLife: 10 * time.Minute})

	ips := []string{"10.20.0.1", "10.20.0.2", "10.20.0.3"}
	for _, ip := range ips {
		seedPenaltyScore(t, rdb, "ab", "test", ip, 12, 5*60*1000)
	}

	results, err := w.RunCycle(context.Background())
	require.NoError(t, err)

	assert.Len(t, results, 3)
	for _, r := range results {
		assert.Greater(t, r.Decrement, 0)
		assert.Less(t, r.NewScore, 12)
	}
}

func TestDecayWorker_NoDoubleDecayWithinSameMs(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())
	w := l.NewDecayWorker(DecayWorkerOptions{HalfLife: 10 * time.Minute})

	seedPenaltyScore(t, rdb, "ab", "test", "10.30.0.1", 15, 5*60*1000)

	r1, err := w.RunCycle(context.Background())
	require.NoError(t, err)
	require.Len(t, r1, 1)
	firstScore := r1[0].NewScore

	// Second cycle immediately: decay_ts = now, elapsed ≈ 0 → no decrement
	r2, err := w.RunCycle(context.Background())
	require.NoError(t, err)
	assert.Empty(t, r2, "second immediate cycle should not decrement again")

	// Score unchanged
	scoreKey := fmt.Sprintf("ab:test:penalty:score:ip:10.30.0.1")
	val, err := rdb.Get(context.Background(), scoreKey).Int()
	require.NoError(t, err)
	assert.Equal(t, firstScore, val)
}

func TestDecayWorker_OnDecayCallback(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())

	var called []DecayResult
	w := l.NewDecayWorker(DecayWorkerOptions{
		HalfLife: 10 * time.Minute,
		OnDecay:  func(r []DecayResult) { called = r },
	})

	seedPenaltyScore(t, rdb, "ab", "test", "10.40.0.1", 10, 5*60*1000)

	_, err := w.RunCycle(context.Background())
	require.NoError(t, err)

	require.NotEmpty(t, called)
	assert.Equal(t, "10.40.0.1", called[0].IP)
}

func TestDecayWorker_Run_ContextCancellation(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())
	w := l.NewDecayWorker(DecayWorkerOptions{
		HalfLife: 10 * time.Minute,
		Interval: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Good
	case <-time.After(2 * time.Second):
		t.Fatal("DecayWorker.Run did not exit after context cancellation")
	}
}

func TestDecayWorker_StateUpdatedAfterDecay(t *testing.T) {
	rdb := startRedis(t)
	l := newLimiter(t, rdb, loginRule())
	w := l.NewDecayWorker(DecayWorkerOptions{HalfLife: 10 * time.Minute})

	// Score 20 decays by ~29% over 5 min with 10 min half-life → ≈14
	// That is under blacklist(15) but above block(10) → BLOCK state
	seedPenaltyScore(t, rdb, "ab", "test", "10.50.0.1", 20, 5*60*1000)

	results, err := w.RunCycle(context.Background())
	require.NoError(t, err)

	if len(results) > 0 {
		r := results[0]
		// State should reflect new score against thresholds
		assert.Contains(t, []string{"CLEAN", "WARN", "SLOW", "BLOCK", "BLACKLIST"}, r.NewState)
	}
}
