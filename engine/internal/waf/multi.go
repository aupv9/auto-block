package waf

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// MultiProvider fans out WAF operations to all configured providers concurrently.
// All errors are collected and returned as a single combined error.
type MultiProvider struct {
	providers []Provider
}

func NewMultiProvider(providers []Provider) *MultiProvider {
	return &MultiProvider{providers: providers}
}

func (m *MultiProvider) Name() string { return "multi" }

func (m *MultiProvider) AddToBlocklist(ctx context.Context, ip string, ttl time.Duration, reason string) error {
	return m.fanOut(func(p Provider) error {
		return p.AddToBlocklist(ctx, ip, ttl, reason)
	})
}

func (m *MultiProvider) RemoveFromBlocklist(ctx context.Context, ip string) error {
	return m.fanOut(func(p Provider) error {
		return p.RemoveFromBlocklist(ctx, ip)
	})
}

func (m *MultiProvider) IsBlocked(ctx context.Context, ip string) (bool, error) {
	for _, p := range m.providers {
		blocked, err := p.IsBlocked(ctx, ip)
		if err != nil {
			return false, fmt.Errorf("multi waf [%s]: %w", p.Name(), err)
		}
		if blocked {
			return true, nil
		}
	}
	return false, nil
}

func (m *MultiProvider) HealthCheck(ctx context.Context) error {
	return m.fanOut(func(p Provider) error {
		return p.HealthCheck(ctx)
	})
}

func (m *MultiProvider) Providers() []Provider { return m.providers }

func (m *MultiProvider) fanOut(fn func(Provider) error) error {
	if len(m.providers) == 0 {
		return nil
	}

	errs := make([]string, 0, len(m.providers))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range m.providers {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(p); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("[%s] %v", p.Name(), err))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("waf multi-provider errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
