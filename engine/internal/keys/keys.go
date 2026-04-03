// Package keys mirrors the TypeScript KeyBuilder — single source of truth
// for all Redis key names used across engine, api, and the Go SDK.
package keys

import (
	"fmt"
	"strings"
)

type Builder struct {
	tenant string
	prefix string
}

func New(tenant, prefix string) *Builder {
	if prefix == "" {
		prefix = "ab"
	}
	return &Builder{tenant: tenant, prefix: prefix}
}

// base builds the canonical key prefix + optional segments.
// base() → "ab:acme"
// base("penalty","score","ip","1.2.3.4") → "ab:acme:penalty:score:ip:1.2.3.4"
func (b *Builder) base(parts ...string) string {
	result := b.prefix + ":" + b.tenant
	for _, p := range parts {
		result += ":" + p
	}
	return result
}

// ---------------------------------------------------------------------------
// Rate limit counters
// ---------------------------------------------------------------------------

func (b *Builder) SlidingWindow(dim, value, epHash string) string {
	if epHash == "" {
		return b.base("sw", dim, value)
	}
	return b.base("sw", dim, value, epHash)
}

func (b *Builder) TokenBucket(dim, value, epHash string) string {
	if epHash == "" {
		return b.base("tb", dim, value)
	}
	return b.base("tb", dim, value, epHash)
}

// ---------------------------------------------------------------------------
// Penalty FSM
// ---------------------------------------------------------------------------

func (b *Builder) PenaltyScore(dim, value string) string {
	return b.base("penalty", "score", dim, value)
}

func (b *Builder) PenaltyState(dim, value string) string {
	return b.base("penalty", "state", dim, value)
}

func (b *Builder) PenaltyHistory(dim, value string) string {
	return b.base("penalty", "history", dim, value)
}

// PenaltyDecayTs stores the unix-ms timestamp of the last decay tick for one IP.
func (b *Builder) PenaltyDecayTs(dim, value string) string {
	return b.base("penalty", "decay", dim, value)
}

// PenaltyScorePattern is a SCAN glob matching all IP penalty score keys.
func (b *Builder) PenaltyScorePattern() string {
	return b.base("penalty", "score", "ip", "*")
}

// PenaltyStatePattern is the pub-sub keyspace glob for IP penalty state changes.
func (b *Builder) PenaltyStatePattern() string {
	return fmt.Sprintf("__keyspace@0__:%s:penalty:state:ip:*", b.base())
}

// ExtractIPFromStateKey parses the IP from a penalty:state key.
// "ab:acme:penalty:state:ip:1.2.3.4" → "1.2.3.4"
func (b *Builder) ExtractIPFromStateKey(key string) string {
	return b.ExtractDimValue(b.base("penalty", "state", "ip"), key)
}

// ExtractDimValue strips the provided prefix from key and returns what follows.
func (b *Builder) ExtractDimValue(prefix, key string) string {
	full := prefix + ":"
	if strings.HasPrefix(key, full) && len(key) > len(full) {
		return key[len(full):]
	}
	return ""
}

// ---------------------------------------------------------------------------
// Allow / deny lists
// ---------------------------------------------------------------------------

func (b *Builder) Blacklist(typ string) string     { return b.base("blacklist", typ) }
func (b *Builder) BlacklistCidr() string           { return b.base("blacklist", "cidr") }
func (b *Builder) Whitelist(typ string) string     { return b.base("whitelist", typ) }
func (b *Builder) WhitelistCidr() string           { return b.base("whitelist", "cidr") }

// ---------------------------------------------------------------------------
// WAF sync state
// ---------------------------------------------------------------------------

// WAFSynced is a hash per IP; field = provider name, value = ISO timestamp.
func (b *Builder) WAFSynced(ip string) string { return b.base("waf", "synced", "ip", ip) }

// ---------------------------------------------------------------------------
// Dynamic rules (hash: field=rule_id, value=JSON)
// ---------------------------------------------------------------------------

func (b *Builder) Rules() string        { return b.base("rules", "endpoint") }
func (b *Builder) RulesChanged() string { return b.base("rules", "changed") }

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func (b *Builder) AuditStream() string { return b.base("audit", "stream") }
