package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Rule is a dynamic rate-limit rule stored in Redis and hot-reloaded by SDKs.
type Rule struct {
	ID             string    `json:"id"`
	Path           string    `json:"path"`
	Limit          int       `json:"limit"`
	WindowSeconds  int       `json:"window_seconds"`
	Algorithm      string    `json:"algorithm"` // sliding_window | token_bucket | hybrid
	PerUser        bool      `json:"per_user"`
	PerEndpoint    bool      `json:"per_endpoint"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// SetRule upserts a rule into the rules hash.
func (s *Store) SetRule(ctx context.Context, rule *Rule) error {
	now := time.Now().UTC()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	rule.UpdatedAt = now

	data, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("store: marshal rule %s: %w", rule.ID, err)
	}
	if err := s.rdb.HSet(ctx, s.keys.Rules(), rule.ID, data).Err(); err != nil {
		return fmt.Errorf("store: set rule %s: %w", rule.ID, err)
	}
	// Notify SDK watchers so they reload immediately instead of waiting for the poll interval.
	_ = s.rdb.Publish(ctx, s.keys.RulesChanged(), rule.ID).Err()
	return nil
}

// GetRule fetches a single rule by ID. Returns nil, nil when not found.
func (s *Store) GetRule(ctx context.Context, id string) (*Rule, error) {
	data, err := s.rdb.HGet(ctx, s.keys.Rules(), id).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get rule %s: %w", id, err)
	}
	var rule Rule
	if err := json.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("store: unmarshal rule %s: %w", id, err)
	}
	return &rule, nil
}

// ListRules returns all rules, sorted by creation time.
func (s *Store) ListRules(ctx context.Context) ([]*Rule, error) {
	fields, err := s.rdb.HGetAll(ctx, s.keys.Rules()).Result()
	if err != nil {
		return nil, fmt.Errorf("store: list rules: %w", err)
	}
	rules := make([]*Rule, 0, len(fields))
	for id, data := range fields {
		var rule Rule
		if err := json.Unmarshal([]byte(data), &rule); err != nil {
			return nil, fmt.Errorf("store: unmarshal rule %s: %w", id, err)
		}
		rules = append(rules, &rule)
	}
	return rules, nil
}

// DeleteRule removes a rule by ID. Returns nil if the rule did not exist.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	if err := s.rdb.HDel(ctx, s.keys.Rules(), id).Err(); err != nil {
		return fmt.Errorf("store: delete rule %s: %w", id, err)
	}
	_ = s.rdb.Publish(ctx, s.keys.RulesChanged(), id).Err()
	return nil
}
