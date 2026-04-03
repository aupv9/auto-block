package autoblock

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// luaDecay is the score-decay Lua script — identical to engine/internal/store/decay.go.
const luaDecay = `
local score_key    = KEYS[1]
local state_key    = KEYS[2]
local decay_ts_key = KEYS[3]
local now          = tonumber(ARGV[1])
local half_life_ms = tonumber(ARGV[2])
local warn_t       = tonumber(ARGV[3])
local slow_t       = tonumber(ARGV[4])
local block_t      = tonumber(ARGV[5])
local blacklist_t  = tonumber(ARGV[6])

local raw = redis.call('GET', score_key)
if not raw then return {0, 'CLEAN', 0} end
local score = tonumber(raw)
if score <= 0 then return {0, 'CLEAN', 0} end

local last_decay = tonumber(redis.call('GET', decay_ts_key) or tostring(now))
local elapsed = now - last_decay
if elapsed <= 0 then
  return {score, redis.call('GET', state_key) or 'CLEAN', 0}
end

local factor    = math.exp(-0.693147 * elapsed / half_life_ms)
local new_score = math.floor(score * factor)
if new_score < 0 then new_score = 0 end
local decrement = score - new_score

redis.call('SET', decay_ts_key, now)

if decrement <= 0 then
  return {score, redis.call('GET', state_key) or 'CLEAN', 0}
end

redis.call('SET', score_key, new_score)

local state
if     new_score >= blacklist_t then state = 'BLACKLIST'
elseif new_score >= block_t     then state = 'BLOCK'
elseif new_score >= slow_t      then state = 'SLOW'
elseif new_score >= warn_t      then state = 'WARN'
else                                  state = 'CLEAN'
end

redis.call('SET', state_key, state)
return {new_score, state, decrement}
`

const (
	defaultDecayHalfLife = 10 * time.Minute
	defaultDecayInterval = 60 * time.Second
)

// DecayResult holds the outcome of a single score decay operation.
type DecayResult struct {
	IP        string
	NewScore  int
	NewState  string
	Decrement int
}

// DecayWorkerOptions configures the standalone decay worker.
type DecayWorkerOptions struct {
	// HalfLife is the exponential decay half-life. Default: 10 minutes.
	HalfLife time.Duration
	// Interval between decay scans. Default: 60 s.
	Interval time.Duration
	// OnDecay is called after each cycle with all IPs that had score changes.
	OnDecay func([]DecayResult)
	// OnError is called when a cycle fails.
	OnError func(error)
}

// DecayWorker periodically scans penalty score keys and applies exponential
// decay so IPs "cool down" over time without requiring the Go engine.
// Create one via NewDecayWorker and run it in a goroutine: go w.Run(ctx)
type DecayWorker struct {
	rdb        *redis.Client
	keys       *keyBuilder
	thresholds Thresholds
	halfLifeMs int64
	interval   time.Duration
	onDecay    func([]DecayResult)
	onError    func(error)
	script     *redis.Script
}

// NewDecayWorker creates a DecayWorker for a Limiter. Shares the same Redis
// client and key builder, so keys are always compatible.
func (l *Limiter) NewDecayWorker(opts DecayWorkerOptions) *DecayWorker {
	hl := opts.HalfLife
	if hl <= 0 {
		hl = defaultDecayHalfLife
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = defaultDecayInterval
	}
	return &DecayWorker{
		rdb:        l.cfg.Redis,
		keys:       l.keys,
		thresholds: l.thresholds,
		halfLifeMs: hl.Milliseconds(),
		interval:   interval,
		onDecay:    opts.OnDecay,
		onError:    opts.OnError,
		script:     redis.NewScript(luaDecay),
	}
}

// Run blocks and runs decay cycles until ctx is cancelled.
func (w *DecayWorker) Run(ctx context.Context) {
	if results, err := w.RunCycle(ctx); err != nil {
		w.handleError(err)
	} else if w.onDecay != nil && len(results) > 0 {
		w.onDecay(results)
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			results, err := w.RunCycle(ctx)
			if err != nil {
				w.handleError(err)
				continue
			}
			if w.onDecay != nil && len(results) > 0 {
				w.onDecay(results)
			}
		}
	}
}

// RunCycle performs a single decay pass. Callable directly in tests.
func (w *DecayWorker) RunCycle(ctx context.Context) ([]DecayResult, error) {
	ips, err := w.scanIPs(ctx)
	if err != nil {
		return nil, err
	}

	var results []DecayResult
	for _, ip := range ips {
		r, err := w.decayOne(ctx, ip)
		if err != nil {
			slog.Warn("autoblock DecayWorker: decay failed", "ip", ip, "error", err)
			continue
		}
		if r.Decrement > 0 {
			results = append(results, r)
		}
	}
	return results, nil
}

func (w *DecayWorker) scanIPs(ctx context.Context) ([]string, error) {
	pattern := w.keys.penaltyScorePattern("ip")
	prefix  := w.keys.penaltyScore("ip", "")
	var ips  []string

	iter := w.rdb.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		ip  := strings.TrimPrefix(key, prefix)
		if ip != "" && ip != key {
			ips = append(ips, ip)
		}
	}
	return ips, iter.Err()
}

func (w *DecayWorker) decayOne(ctx context.Context, ip string) (DecayResult, error) {
	t     := w.thresholds
	nowMs := time.Now().UnixMilli()

	res, err := w.script.Run(ctx, w.rdb,
		[]string{
			w.keys.penaltyScore("ip", ip),
			w.keys.penaltyState("ip", ip),
			w.keys.penaltyDecayTs("ip", ip),
		},
		nowMs, w.halfLifeMs, t.Warn, t.Slow, t.Block, t.Blacklist,
	).Slice()
	if err != nil {
		return DecayResult{}, err
	}
	if len(res) < 3 {
		return DecayResult{IP: ip}, nil
	}

	newScore,  _ := res[0].(int64)
	newState,  _ := res[1].(string)
	decrement, _ := res[2].(int64)

	return DecayResult{
		IP:        ip,
		NewScore:  int(newScore),
		NewState:  newState,
		Decrement: int(decrement),
	}, nil
}

func (w *DecayWorker) handleError(err error) {
	slog.Warn("autoblock DecayWorker cycle error", "error", err)
	if w.onError != nil {
		w.onError(err)
	}
}
