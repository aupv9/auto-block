package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const pdEventsURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDuty sends critical alerts via PagerDuty Events API v2.
type PagerDuty struct {
	integrationKey string
	client         *http.Client
}

func NewPagerDuty(integrationKey string) *PagerDuty {
	return &PagerDuty{
		integrationKey: integrationKey,
		client:         &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *PagerDuty) Send(ctx context.Context, evt Event) error {
	severity := "error"
	summary := fmt.Sprintf("AutoBlock: IP %s blacklisted (score %d)", evt.IP, evt.Score)
	if evt.Error != nil {
		severity = "critical"
		summary += fmt.Sprintf(" — WAF push FAILED: %v", evt.Error)
	}

	payload := map[string]any{
		"routing_key":  p.integrationKey,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":   summary,
			"severity":  severity,
			"source":    "autoblock-engine",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"custom_details": map[string]any{
				"ip":         evt.IP,
				"score":      evt.Score,
				"waf":        evt.WAF,
				"event_type": evt.Type,
			},
		},
		"dedup_key": fmt.Sprintf("autoblock-%s", evt.IP), // dedup within 24h
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("pagerduty: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pdEventsURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pagerduty: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty: post: %w", err)
	}
	defer resp.Body.Close()

	// 202 Accepted is success
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("pagerduty: unexpected status %d", resp.StatusCode)
	}
	return nil
}
