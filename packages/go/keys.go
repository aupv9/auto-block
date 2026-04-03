package autoblock

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// keyBuilder mirrors the canonical AutoBlock key schema.
// Keys produced here are identical to TypeScript/Python/Java/Go engine keys.
type keyBuilder struct {
	tenant string
	prefix string
}

func newKeyBuilder(tenant, prefix string) *keyBuilder {
	return &keyBuilder{tenant: tenant, prefix: prefix}
}

func (b *keyBuilder) base(parts ...string) string {
	sb := strings.Builder{}
	sb.WriteString(b.prefix)
	sb.WriteByte(':')
	sb.WriteString(b.tenant)
	for _, p := range parts {
		sb.WriteByte(':')
		sb.WriteString(p)
	}
	return sb.String()
}

func (b *keyBuilder) slidingWindow(dim, value, endpoint string) string {
	if endpoint != "" {
		return b.base("sw", dim, value, epHash(endpoint))
	}
	return b.base("sw", dim, value)
}

func (b *keyBuilder) tokenBucket(dim, value, endpoint string) string {
	if endpoint != "" {
		return b.base("tb", dim, value, epHash(endpoint))
	}
	return b.base("tb", dim, value)
}

func (b *keyBuilder) penaltyScore(dim, value string) string {
	return b.base("penalty", "score", dim, value)
}

func (b *keyBuilder) penaltyState(dim, value string) string {
	return b.base("penalty", "state", dim, value)
}

func (b *keyBuilder) penaltyHistory(dim, value string) string {
	return b.base("penalty", "history", dim, value)
}

func (b *keyBuilder) blacklist(typ string) string             { return b.base("blacklist", typ) }
func (b *keyBuilder) blacklistCidr() string                  { return b.base("blacklist", "cidr") }
func (b *keyBuilder) whitelist(typ string) string             { return b.base("whitelist", typ) }
func (b *keyBuilder) whitelistCidr() string                  { return b.base("whitelist", "cidr") }
func (b *keyBuilder) rules() string                           { return b.base("rules", "endpoint") }
func (b *keyBuilder) rulesChanged() string                    { return b.base("rules", "changed") }
func (b *keyBuilder) penaltyDecayTs(dim, value string) string { return b.base("penalty", "decay", dim, value) }
func (b *keyBuilder) penaltyScorePattern(dim string) string   { return b.base("penalty", "score", dim, "*") }

// epHash returns the first 8 hex chars of SHA-256(endpoint) — identical to TypeScript/Java.
func epHash(endpoint string) string {
	h := sha256.Sum256([]byte(endpoint))
	return fmt.Sprintf("%x", h[:4]) // 4 bytes = 8 hex chars
}
