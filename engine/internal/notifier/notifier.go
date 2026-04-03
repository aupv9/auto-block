// Package notifier defines the Notifier interface and built-in implementations.
package notifier

import "context"

// Event carries the data for a notification.
type Event struct {
	Type  string // "blacklisted", "waf_action", "state_changed"
	IP    string
	Score int
	WAF   string
	Error error // non-nil if the WAF push failed
}

// Notifier sends alerts for significant security events.
type Notifier interface {
	Send(ctx context.Context, event Event) error
}

// Noop discards all events (default when no notifier is configured).
type Noop struct{}

func (Noop) Send(_ context.Context, _ Event) error { return nil }

// multi fans out to all notifiers; collects and returns the last non-nil error.
type multi struct{ notifiers []Notifier }

// NewMulti returns a Notifier that sends to all provided notifiers in order.
// A failure in one does not prevent subsequent notifiers from being called.
func NewMulti(nn ...Notifier) Notifier { return &multi{notifiers: nn} }

func (m *multi) Send(ctx context.Context, event Event) error {
	var last error
	for _, n := range m.notifiers {
		if err := n.Send(ctx, event); err != nil {
			last = err
		}
	}
	return last
}
