// Package store centralises all Redis operations shared between engine and api.
package store

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/autoblock/autoblock/internal/keys"
	"github.com/redis/go-redis/v9"
)

type Store struct {
	rdb    *redis.Client
	keys   *keys.Builder
	tenant string
}

func New(rdb *redis.Client, tenant, keyPrefix string) *Store {
	return &Store{
		rdb:    rdb,
		keys:   keys.New(tenant, keyPrefix),
		tenant: tenant,
	}
}

func (s *Store) Keys() *keys.Builder { return s.keys }

func (s *Store) AuditStreamKey() string { return s.keys.AuditStream() }

// ---------------------------------------------------------------------------
// Penalty
// ---------------------------------------------------------------------------

func (s *Store) GetPenaltyScore(ctx context.Context, ip string) (int, error) {
	val, err := s.rdb.Get(ctx, s.keys.PenaltyScore("ip", ip)).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: get penalty score: %w", err)
	}
	score, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("store: parse penalty score: %w", err)
	}
	return score, nil
}

func (s *Store) GetPenaltyState(ctx context.Context, ip string) (string, error) {
	val, err := s.rdb.Get(ctx, s.keys.PenaltyState("ip", ip)).Result()
	if err == redis.Nil {
		return "CLEAN", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: get penalty state: %w", err)
	}
	return val, nil
}

// ---------------------------------------------------------------------------
// Blacklist (sorted set: score = 0 permanent, score > 0 = expiry unix ts)
// ---------------------------------------------------------------------------

func (s *Store) AddToBlacklist(ctx context.Context, ip string, ttl time.Duration) error {
	var score float64
	if ttl == 0 {
		score = 0 // permanent
	} else {
		score = float64(time.Now().Add(ttl).Unix())
	}
	return s.rdb.ZAdd(ctx, s.keys.Blacklist("ip"), redis.Z{Score: score, Member: ip}).Err()
}

func (s *Store) RemoveFromBlacklist(ctx context.Context, ip string) error {
	return s.rdb.ZRem(ctx, s.keys.Blacklist("ip"), ip).Err()
}

func (s *Store) IsBlacklisted(ctx context.Context, ip string) (bool, error) {
	score, err := s.rdb.ZScore(ctx, s.keys.Blacklist("ip"), ip).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: is blacklisted: %w", err)
	}
	if score == 0 {
		return true, nil // permanent
	}
	if float64(time.Now().Unix()) < score {
		return true, nil // not yet expired
	}
	// Expired — lazy clean up
	_ = s.rdb.ZRem(ctx, s.keys.Blacklist("ip"), ip)
	return false, nil
}

func (s *Store) ListBlacklist(ctx context.Context) ([]BlacklistEntry, error) {
	now := float64(time.Now().Unix())
	// permanent entries (score=0) + non-expired entries (score > now)
	permanent, err := s.rdb.ZRangeByScoreWithScores(ctx, s.keys.Blacklist("ip"), &redis.ZRangeBy{
		Min: "0", Max: "0",
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("store: list blacklist permanent: %w", err)
	}
	active, err := s.rdb.ZRangeByScoreWithScores(ctx, s.keys.Blacklist("ip"), &redis.ZRangeBy{
		Min: fmt.Sprintf("%f", now), Max: "+inf",
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("store: list blacklist active: %w", err)
	}

	entries := make([]BlacklistEntry, 0, len(permanent)+len(active))
	for _, z := range append(permanent, active...) {
		e := BlacklistEntry{IP: z.Member.(string)}
		if z.Score > 0 {
			e.ExpiresAt = time.Unix(int64(z.Score), 0)
			e.Permanent = false
		} else {
			e.Permanent = true
		}
		entries = append(entries, e)
	}
	return entries, nil
}

type BlacklistEntry struct {
	IP        string
	ExpiresAt time.Time
	Permanent bool
}

// ---------------------------------------------------------------------------
// Whitelist (set)
// ---------------------------------------------------------------------------

func (s *Store) AddToWhitelist(ctx context.Context, ip string) error {
	return s.rdb.SAdd(ctx, s.keys.Whitelist("ip"), ip).Err()
}

func (s *Store) RemoveFromWhitelist(ctx context.Context, ip string) error {
	return s.rdb.SRem(ctx, s.keys.Whitelist("ip"), ip).Err()
}

func (s *Store) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	result, err := s.rdb.SIsMember(ctx, s.keys.Whitelist("ip"), ip).Result()
	if err != nil {
		return false, fmt.Errorf("store: is whitelisted: %w", err)
	}
	return result, nil
}

func (s *Store) ListWhitelist(ctx context.Context) ([]string, error) {
	members, err := s.rdb.SMembers(ctx, s.keys.Whitelist("ip")).Result()
	if err != nil {
		return nil, fmt.Errorf("store: list whitelist: %w", err)
	}
	return members, nil
}

// ---------------------------------------------------------------------------
// Blacklist CIDR (sorted set: same TTL schema as blacklist:ip)
// ---------------------------------------------------------------------------

func (s *Store) AddCidrToBlacklist(ctx context.Context, cidr string, ttl time.Duration) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("store: invalid CIDR %q: %w", cidr, err)
	}
	var score float64
	if ttl == 0 {
		score = 0
	} else {
		score = float64(time.Now().Add(ttl).Unix())
	}
	return s.rdb.ZAdd(ctx, s.keys.BlacklistCidr(), redis.Z{Score: score, Member: cidr}).Err()
}

func (s *Store) RemoveCidrFromBlacklist(ctx context.Context, cidr string) error {
	return s.rdb.ZRem(ctx, s.keys.BlacklistCidr(), cidr).Err()
}

func (s *Store) ListBlacklistCidrs(ctx context.Context) ([]BlacklistEntry, error) {
	now := float64(time.Now().Unix())
	permanent, err := s.rdb.ZRangeByScoreWithScores(ctx, s.keys.BlacklistCidr(), &redis.ZRangeBy{Min: "0", Max: "0"}).Result()
	if err != nil {
		return nil, fmt.Errorf("store: list blacklist cidrs permanent: %w", err)
	}
	active, err := s.rdb.ZRangeByScoreWithScores(ctx, s.keys.BlacklistCidr(), &redis.ZRangeBy{
		Min: fmt.Sprintf("%f", now), Max: "+inf",
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("store: list blacklist cidrs active: %w", err)
	}
	entries := make([]BlacklistEntry, 0, len(permanent)+len(active))
	for _, z := range append(permanent, active...) {
		e := BlacklistEntry{IP: z.Member.(string)}
		if z.Score > 0 {
			e.ExpiresAt = time.Unix(int64(z.Score), 0)
		} else {
			e.Permanent = true
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// IpInBlacklistedCidr checks whether ip falls inside any active CIDR range in the blacklist.
func (s *Store) IpInBlacklistedCidr(ctx context.Context, ip string) (bool, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, nil
	}
	cidrs, err := s.ListBlacklistCidrs(ctx)
	if err != nil {
		return false, err
	}
	for _, entry := range cidrs {
		_, ipNet, parseErr := net.ParseCIDR(entry.IP)
		if parseErr == nil && ipNet.Contains(parsed) {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// Whitelist CIDR (set — no TTL, same as whitelist:ip)
// ---------------------------------------------------------------------------

func (s *Store) AddCidrToWhitelist(ctx context.Context, cidr string) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("store: invalid CIDR %q: %w", cidr, err)
	}
	return s.rdb.SAdd(ctx, s.keys.WhitelistCidr(), cidr).Err()
}

func (s *Store) RemoveCidrFromWhitelist(ctx context.Context, cidr string) error {
	return s.rdb.SRem(ctx, s.keys.WhitelistCidr(), cidr).Err()
}

func (s *Store) ListWhitelistCidrs(ctx context.Context) ([]string, error) {
	members, err := s.rdb.SMembers(ctx, s.keys.WhitelistCidr()).Result()
	if err != nil {
		return nil, fmt.Errorf("store: list whitelist cidrs: %w", err)
	}
	return members, nil
}

// IpInWhitelistedCidr checks whether ip falls inside any CIDR range in the whitelist.
func (s *Store) IpInWhitelistedCidr(ctx context.Context, ip string) (bool, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, nil
	}
	cidrs, err := s.ListWhitelistCidrs(ctx)
	if err != nil {
		return false, err
	}
	for _, cidr := range cidrs {
		_, ipNet, parseErr := net.ParseCIDR(cidr)
		if parseErr == nil && ipNet.Contains(parsed) {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// WAF sync state
// ---------------------------------------------------------------------------

func (s *Store) MarkWAFSynced(ctx context.Context, ip, provider string) error {
	key := s.keys.WAFSynced(ip)
	return s.rdb.HSet(ctx, key, provider, time.Now().UTC().Format(time.RFC3339)).Err()
}

func (s *Store) IsWAFSynced(ctx context.Context, ip, provider string) (bool, error) {
	val, err := s.rdb.HGet(ctx, s.keys.WAFSynced(ip), provider).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: is waf synced: %w", err)
	}
	return val != "", nil
}
