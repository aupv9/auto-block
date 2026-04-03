// Package watcher listens for Redis keyspace notifications and forwards
// penalty state change events to the remediation engine.
package watcher

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/autoblock/autoblock/internal/keys"
	"github.com/redis/go-redis/v9"
)

// Event is emitted when a penalty:state key changes to a new value.
type Event struct {
	IP       string
	NewState string
	Key      string
}

// Run subscribes to Redis keyspace notifications for penalty state keys.
// It sends events to the returned channel until ctx is cancelled.
//
// mode: "pubsub" (real-time, requires notify-keyspace-events KEA)
//
//	"poll" (fallback — scans for BLACKLIST keys every interval)
func Run(
	ctx context.Context,
	rdb *redis.Client,
	kb *keys.Builder,
	mode string,
	pollInterval int,
) (<-chan Event, error) {
	ch := make(chan Event, 64)

	if mode == "poll" {
		go runPoller(ctx, rdb, kb, pollInterval, ch)
	} else {
		if err := runPubSub(ctx, rdb, kb, ch); err != nil {
			return nil, err
		}
	}
	return ch, nil
}

// ---------------------------------------------------------------------------
// Pub/sub mode (preferred — ~realtime, 60s SLO)
// ---------------------------------------------------------------------------

func runPubSub(ctx context.Context, rdb *redis.Client, kb *keys.Builder, out chan<- Event) error {
	pattern := kb.PenaltyStatePattern()
	pubsub := rdb.PSubscribe(ctx, pattern)

	// Verify subscription
	if _, err := pubsub.Receive(ctx); err != nil {
		pubsub.Close()
		return err
	}

	slog.Info("watcher: subscribed to keyspace notifications", slog.String("pattern", pattern))

	go func() {
		defer pubsub.Close()
		msgCh := pubsub.Channel()

		for {
			select {
			case <-ctx.Done():
				slog.Info("watcher: pub/sub shutting down")
				return
			case msg, ok := <-msgCh:
				if !ok {
					slog.Warn("watcher: pub/sub channel closed, trying reconnect in 5s")
					time.Sleep(5 * time.Second)
					// Reconnect
					pubsub = rdb.PSubscribe(ctx, pattern)
					msgCh = pubsub.Channel()
					continue
				}

				// msg.Channel: "__keyspace@0__:ab:acme:penalty:state:ip:1.2.3.4"
				// msg.Payload: "set" (the Redis command that fired this)
				if msg.Payload != "set" {
					continue // only care about SET events
				}

				key := strings.TrimPrefix(msg.Channel, "__keyspace@0__:")
				ip := kb.ExtractIPFromStateKey(key)
				if ip == "" {
					continue
				}

				// Read the new state value
				state, err := rdb.Get(ctx, key).Result()
				if err != nil {
					slog.Warn("watcher: could not read state after notification",
						slog.String("key", key), slog.String("err", err.Error()))
					continue
				}

				slog.Debug("watcher: state change detected",
					slog.String("ip", ip), slog.String("state", state))

				select {
				case out <- Event{IP: ip, NewState: state, Key: key}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return nil
}

// ---------------------------------------------------------------------------
// Poll mode (fallback when keyspace notifications are unavailable)
// ---------------------------------------------------------------------------

func runPoller(ctx context.Context, rdb *redis.Client, kb *keys.Builder, intervalSec int, out chan<- Event) {
	interval := time.Duration(intervalSec) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Info("watcher: polling mode", slog.Duration("interval", interval))

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scanBlacklists(ctx, rdb, kb, out)
		}
	}
}

func scanBlacklists(ctx context.Context, rdb *redis.Client, kb *keys.Builder, out chan<- Event) {
	// Scan for all penalty state keys that are in BLACKLIST state
	pattern := strings.Replace(kb.PenaltyStatePattern(), "__keyspace@0__:", "", 1)
	var cursor uint64

	for {
		keys, nextCursor, err := rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			slog.Warn("watcher: scan error", slog.String("err", err.Error()))
			return
		}

		for _, key := range keys {
			state, err := rdb.Get(ctx, key).Result()
			if err != nil || state != "BLACKLIST" {
				continue
			}
			ip := kb.ExtractIPFromStateKey(key)
			if ip == "" {
				continue
			}
			select {
			case out <- Event{IP: ip, NewState: state, Key: key}:
			case <-ctx.Done():
				return
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}
