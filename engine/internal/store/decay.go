package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// scoreDecayLua atomically applies exponential half-life decay to a penalty score.
//
// Formula: new_score = floor(current_score * exp(-ln(2) * elapsed_ms / half_life_ms))
// math.exp is available in Redis Lua 5.1 (bundled with Redis 5.0+).
//
// KEYS[1] = penalty score key   (ab:tenant:penalty:score:ip:x.x.x.x)
// KEYS[2] = penalty state key   (ab:tenant:penalty:state:ip:x.x.x.x)
// KEYS[3] = last decay ts key   (ab:tenant:penalty:decay:ip:x.x.x.x)
// ARGV[1] = current time ms
// ARGV[2] = half life ms
// ARGV[3] = warn threshold
// ARGV[4] = slow threshold
// ARGV[5] = block threshold
// ARGV[6] = blacklist threshold
//
// Returns: {new_score (int), new_state (string), decrement (int)}
const scoreDecayLua = `
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

-- Exponential decay: score * 0.5^(elapsed/half_life) = score * exp(-ln(2)*elapsed/half_life)
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

var decayScript = redis.NewScript(scoreDecayLua)

// DecayResult holds the outcome of a single score decay operation.
type DecayResult struct {
	IP        string
	NewScore  int
	NewState  string
	Decrement int
}

// DecayScore applies exponential half-life decay to one IP's penalty score.
// Returns nil when the score is already zero or the key does not exist.
func (s *Store) DecayScore(
	ctx context.Context,
	ip string,
	halfLifeMs int64,
	warnT, slowT, blockT, blacklistT int,
) (*DecayResult, error) {
	scoreKey   := s.keys.PenaltyScore("ip", ip)
	stateKey   := s.keys.PenaltyState("ip", ip)
	decayTsKey := s.keys.PenaltyDecayTs("ip", ip)

	nowMs := time.Now().UnixMilli()

	res, err := decayScript.Run(ctx, s.rdb,
		[]string{scoreKey, stateKey, decayTsKey},
		nowMs, halfLifeMs, warnT, slowT, blockT, blacklistT,
	).Slice()
	if err != nil {
		return nil, fmt.Errorf("store: decay score ip=%s: %w", ip, err)
	}
	if len(res) < 3 {
		return nil, fmt.Errorf("store: decay score: unexpected result len=%d", len(res))
	}

	newScore, _  := res[0].(int64)
	newState, _  := res[1].(string)
	decrement, _ := res[2].(int64)

	return &DecayResult{
		IP:        ip,
		NewScore:  int(newScore),
		NewState:  newState,
		Decrement: int(decrement),
	}, nil
}

// ScanPenaltyIPs returns all IPs that currently have a penalty score key in Redis.
// Uses SCAN to avoid blocking the server.
func (s *Store) ScanPenaltyIPs(ctx context.Context) ([]string, error) {
	pattern := s.keys.PenaltyScorePattern()
	// prefix to strip: "ab:{tenant}:penalty:score:ip:"
	prefix := s.keys.PenaltyScore("ip", "") // ends with ":"
	var ips []string

	iter := s.rdb.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		ip  := strings.TrimPrefix(key, prefix)
		if ip != "" && ip != key {
			ips = append(ips, ip)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("store: scan penalty ips: %w", err)
	}
	return ips, nil
}
