package autoblock

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const penaltyTTLMs = 24 * 60 * 60 * 1000 // 24 h

// cidrStore caches parsed CIDR ranges from Redis for fast in-memory subnet checks.
type cidrStore struct {
	mu        sync.RWMutex
	blacklist []*net.IPNet
	whitelist []*net.IPNet
}

// Limiter is the main rate-limit evaluator. Create one per application and
// reuse it across requests — it holds compiled rules and pre-loaded scripts.
// Rules can be hot-reloaded without restarting via NewWatcher.
// Call Close() to release background goroutines.
type Limiter struct {
	cfg         Config
	keys        *keyBuilder
	thresholds  Thresholds
	atomicRules *atomicRules // replaced atomically by RulesWatcher
	cidrs       cidrStore

	swScript *redis.Script
	tbScript *redis.Script
	ptScript *redis.Script
	blScript *redis.Script

	stopCh chan struct{}
}

// New creates a Limiter. Returns an error if cfg.Tenant or cfg.Redis is empty.
func New(cfg Config) (*Limiter, error) {
	if cfg.Tenant == "" {
		return nil, fmt.Errorf("autoblock: tenant is required")
	}
	if cfg.Redis == nil {
		return nil, fmt.Errorf("autoblock: redis client is required")
	}

	rules, err := compileRules(cfg.Rules)
	if err != nil {
		return nil, fmt.Errorf("autoblock: compile rules: %w", err)
	}

	l := &Limiter{
		cfg:         cfg,
		keys:        newKeyBuilder(cfg.Tenant, cfg.keyPrefix()),
		thresholds:  cfg.Thresholds.withDefaults(),
		atomicRules: newAtomicRules(rules),
		swScript:    redis.NewScript(luaSlidingWindow),
		tbScript:    redis.NewScript(luaTokenBucket),
		ptScript:    redis.NewScript(luaPenaltyTransition),
		blScript:    redis.NewScript(luaBlacklistCheck),
		stopCh:      make(chan struct{}),
	}
	l.refreshCidrCache(context.Background())
	go l.cidrRefreshLoop()
	return l, nil
}

// Close stops background goroutines started by New.
func (l *Limiter) Close() {
	select {
	case <-l.stopCh:
	default:
		close(l.stopCh)
	}
}

func (l *Limiter) cidrRefreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.refreshCidrCache(context.Background())
		}
	}
}

func (l *Limiter) refreshCidrCache(ctx context.Context) {
	if bl, err := l.cfg.Redis.SMembers(ctx, l.keys.blacklistCidr()).Result(); err == nil {
		nets := parseCIDRs(bl)
		l.cidrs.mu.Lock()
		l.cidrs.blacklist = nets
		l.cidrs.mu.Unlock()
	}
	if wl, err := l.cfg.Redis.SMembers(ctx, l.keys.whitelistCidr()).Result(); err == nil {
		nets := parseCIDRs(wl)
		l.cidrs.mu.Lock()
		l.cidrs.whitelist = nets
		l.cidrs.mu.Unlock()
	}
}

func parseCIDRs(strs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(strs))
	for _, s := range strs {
		if _, ipNet, err := net.ParseCIDR(s); err == nil {
			out = append(out, ipNet)
		}
	}
	return out
}

// Evaluate returns the rate-limit decision for a request.
// ip and endpoint are required; userID may be empty.
// If an OpenTelemetry TracerProvider is registered (via otel.SetTracerProvider),
// a span named "autoblock.evaluate" is recorded automatically.
func (l *Limiter) Evaluate(ctx context.Context, ip, userID, endpoint string) Decision {
	ctx, span := otel.Tracer("autoblock").Start(ctx, "autoblock.evaluate",
		trace.WithAttributes(
			attribute.String("autoblock.tenant", l.cfg.Tenant),
			attribute.String("autoblock.ip", ip),
			attribute.String("autoblock.endpoint", endpoint),
		),
	)
	decision := l.evaluate(ctx, ip, userID, endpoint)
	span.SetAttributes(
		attribute.Bool("autoblock.allowed", decision.Allowed),
		attribute.String("autoblock.state", string(decision.State)),
	)
	if !decision.Allowed {
		span.SetStatus(otelcodes.Error, "request blocked by autoblock")
	}
	span.End()
	return decision
}

func (l *Limiter) evaluate(ctx context.Context, ip, userID, endpoint string) Decision {
	// 1. Whitelist — always allow
	if l.isWhitelisted(ctx, ip) {
		return allowDecision(StateClean, int(^uint(0)>>1))
	}

	// 2. Blacklist — fast reject
	if blocked, retryAfter := l.isBlacklisted(ctx, ip); blocked {
		return denyDecision(StateBlacklist, retryAfter)
	}

	// 3. Rule match
	rule := l.matchRule(endpoint)
	if rule == nil {
		return allowDecision(StateClean, int(^uint(0)>>1))
	}

	// 4. IP dimension
	ipDecision := l.evaluateDimension(ctx, "ip", ip, endpoint, rule)

	// 5. User dimension (if rule.PerUser and userID present)
	if rule.PerUser && userID != "" {
		userDecision := l.evaluateDimension(ctx, "uid", userID, endpoint, rule)
		return l.worstCase(ipDecision, userDecision, rule)
	}

	return l.toDecision(ipDecision, rule)
}

// evaluateDimension runs the algorithm for one dimension and applies penalty on violation.
func (l *Limiter) evaluateDimension(ctx context.Context, dim, value, endpoint string, rule *compiledRule) dimResult {
	ep := ""
	if rule.PerEndpoint {
		ep = endpoint
	}

	swKey := l.keys.slidingWindow(dim, value, ep)
	tbKey := l.keys.tokenBucket(dim, value, ep)

	allowed, remaining := l.runAlgorithm(ctx, rule, swKey, tbKey)

	scoreKey   := l.keys.penaltyScore(dim, value)
	stateKey   := l.keys.penaltyState(dim, value)
	historyKey := l.keys.penaltyHistory(dim, value)

	if !allowed {
		state := l.incrementPenalty(ctx, scoreKey, stateKey, historyKey,
			fmt.Sprintf("rate_exceeded:%s:%s", dim, value))
		return dimResult{allowed: false, state: state, remaining: remaining}
	}

	state := l.currentState(ctx, stateKey)
	return dimResult{allowed: true, state: state, remaining: remaining}
}

// runAlgorithm executes the configured algorithm and returns (allowed, remaining).
func (l *Limiter) runAlgorithm(ctx context.Context, rule *compiledRule, swKey, tbKey string) (bool, int) {
	rdb   := l.cfg.Redis
	now   := time.Now().UnixMilli()
	r     := rule.Rule
	wMs   := r.windowMs()
	rate  := float64(r.Limit) / float64(r.WindowSeconds)

	switch r.Algorithm {
	case AlgorithmTokenBucket:
		res := l.runTB(ctx, rdb, tbKey, now, r.Limit, rate, float64(wMs))
		return res[0] == 1, int(res[1])

	case AlgorithmSlidingWindow:
		res := l.runSW(ctx, rdb, swKey, now, wMs, r.Limit)
		return res[0] == 1, int(res[2])

	default: // hybrid
		sw := l.runSW(ctx, rdb, swKey, now, wMs, r.Limit)
		tb := l.runTB(ctx, rdb, tbKey, now, r.Limit, rate, float64(wMs))
		remaining := min(int(sw[2]), int(tb[1]))
		return sw[0] == 1 && tb[0] == 1, remaining
	}
}

func (l *Limiter) runSW(ctx context.Context, rdb *redis.Client, key string, now, windowMs int64, limit int) []int64 {
	res, err := l.swScript.Run(ctx, rdb, []string{key},
		now, windowMs, limit, fmt.Sprintf("%d", now),
	).Int64Slice()
	if err != nil {
		if l.cfg.failOpen() {
			return []int64{1, 0, int64(limit)}
		}
		return []int64{0, int64(limit), 0}
	}
	return res
}

func (l *Limiter) runTB(ctx context.Context, rdb *redis.Client, key string, now int64, capacity int, rate, windowMs float64) []int64 {
	res, err := l.tbScript.Run(ctx, rdb, []string{key},
		now, capacity, rate, int64(windowMs),
	).Int64Slice()
	if err != nil {
		if l.cfg.failOpen() {
			return []int64{1, int64(capacity), int64(capacity)}
		}
		return []int64{0, 0, int64(capacity)}
	}
	return res
}

func (l *Limiter) incrementPenalty(ctx context.Context, scoreKey, stateKey, historyKey, reason string) PenaltyState {
	t := l.thresholds
	res, err := l.ptScript.Run(ctx, l.cfg.Redis,
		[]string{scoreKey, stateKey, historyKey},
		1, t.Warn, t.Slow, t.Block, t.Blacklist,
		reason, penaltyTTLMs,
	).Slice()
	if err != nil || len(res) < 2 {
		return StateBlock
	}
	if s, ok := res[1].(string); ok {
		return penaltyStateFromString(s)
	}
	return StateBlock
}

func (l *Limiter) currentState(ctx context.Context, stateKey string) PenaltyState {
	val, err := l.cfg.Redis.Get(ctx, stateKey).Result()
	if err != nil {
		return StateClean
	}
	return penaltyStateFromString(val)
}

func (l *Limiter) isBlacklisted(ctx context.Context, ip string) (bool, int64) {
	now := time.Now().Unix()
	res, err := l.blScript.Run(ctx, l.cfg.Redis,
		[]string{l.keys.blacklist("ip")}, ip, now,
	).Int64Slice()
	if err == nil && len(res) >= 2 && res[0] == 1 {
		return true, res[1]
	}
	// CIDR check: scan in-memory cache
	if parsed := net.ParseIP(ip); parsed != nil {
		l.cidrs.mu.RLock()
		defer l.cidrs.mu.RUnlock()
		for _, cidr := range l.cidrs.blacklist {
			if cidr.Contains(parsed) {
				return true, 3600
			}
		}
	}
	return false, 0
}

func (l *Limiter) isWhitelisted(ctx context.Context, ip string) bool {
	if ok, err := l.cfg.Redis.SIsMember(ctx, l.keys.whitelist("ip"), ip).Result(); err == nil && ok {
		return true
	}
	// CIDR check: scan in-memory cache
	if parsed := net.ParseIP(ip); parsed != nil {
		l.cidrs.mu.RLock()
		defer l.cidrs.mu.RUnlock()
		for _, cidr := range l.cidrs.whitelist {
			if cidr.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

func (l *Limiter) toDecision(r dimResult, rule *compiledRule) Decision {
	if !r.allowed || r.state == StateBlock || r.state == StateBlacklist {
		retryAfter := int64(0)
		if rule != nil {
			retryAfter = int64(rule.WindowSeconds)
		}
		return denyDecision(r.state, retryAfter)
	}
	return allowDecision(r.state, r.remaining)
}

func (l *Limiter) worstCase(a, b dimResult, rule *compiledRule) Decision {
	worst := a
	if b.state.ordinal() > a.state.ordinal() {
		worst = b
	}
	return l.toDecision(worst, rule)
}

// ---- Rule compilation ----------------------------------------------------

type compiledRule struct {
	Rule
	pattern *regexp.Regexp
}

func compileRules(rules []Rule) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		pat, err := antToRegexp(r.Path)
		if err != nil {
			return nil, fmt.Errorf("rule path %q: %w", r.Path, err)
		}
		if r.Algorithm == "" {
			r.Algorithm = AlgorithmHybrid
		}
		if r.WindowSeconds <= 0 {
			r.WindowSeconds = 60
		}
		out = append(out, compiledRule{Rule: r, pattern: pat})
	}
	return out, nil
}

func (l *Limiter) matchRule(path string) *compiledRule {
	rules := l.atomicRules.load()
	for i := range rules {
		if rules[i].pattern.MatchString(path) {
			return &rules[i]
		}
	}
	return nil
}

// antToRegexp converts an Ant-style path pattern to a compiled regexp.
// /api/** → matches /api/anything/deep
// /api/*  → matches /api/single-segment
func antToRegexp(ant string) (*regexp.Regexp, error) {
	var sb strings.Builder
	sb.WriteByte('^')
	i := 0
	for i < len(ant) {
		ch := ant[i]
		switch {
		case ch == '*' && i+1 < len(ant) && ant[i+1] == '*':
			sb.WriteString(".+")
			i += 2
		case ch == '*':
			sb.WriteString("[^/]+")
			i++
		case ch == '.':
			sb.WriteString("\\.")
			i++
		default:
			sb.WriteByte(ch)
			i++
		}
	}
	sb.WriteByte('$')
	return regexp.Compile(sb.String())
}

// ---- helpers -------------------------------------------------------------

type dimResult struct {
	allowed   bool
	state     PenaltyState
	remaining int
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
