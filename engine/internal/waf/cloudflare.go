package waf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/autoblock/autoblock/internal/config"
)

const cfBaseURL = "https://api.cloudflare.com/client/v4"

type cloudflareWAF struct {
	client    *http.Client
	accountID string
	listID    string
	apiToken  string
	name      string
}

func newCloudflareWAF(pc config.WAFProviderConfig) (*cloudflareWAF, error) {
	accountID, _ := pc.Config["account_id"].(string)
	listID, _ := pc.Config["list_id"].(string)
	apiToken, _ := pc.Config["api_token"].(string)

	if accountID == "" || listID == "" || apiToken == "" {
		return nil, fmt.Errorf("cloudflare: account_id, list_id, and api_token are required")
	}

	return &cloudflareWAF{
		client:    &http.Client{Timeout: 15 * time.Second},
		accountID: accountID,
		listID:    listID,
		apiToken:  apiToken,
		name:      pc.Name,
	}, nil
}

func (c *cloudflareWAF) Name() string { return c.name }

func (c *cloudflareWAF) AddToBlocklist(ctx context.Context, ip string, _ time.Duration, reason string) error {
	body := []map[string]string{{"ip": ip, "comment": "autoblock: " + reason}}
	data, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", cfBaseURL, c.accountID, c.listID)
	resp, err := c.do(ctx, http.MethodPost, url, data)
	if err != nil {
		return fmt.Errorf("cloudflare: add to blocklist: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("cloudflare: add failed: %v", resp.Errors)
	}

	slog.Info("cloudflare: ip added to list", slog.String("ip", ip))
	return nil
}

func (c *cloudflareWAF) RemoveFromBlocklist(ctx context.Context, ip string) error {
	// Must find the item ID first
	items, err := c.listItems(ctx)
	if err != nil {
		return fmt.Errorf("cloudflare: list items for removal: %w", err)
	}

	var targetID string
	for _, item := range items {
		if item.IP == ip {
			targetID = item.ID
			break
		}
	}
	if targetID == "" {
		return nil // not present — idempotent
	}

	body := map[string][]map[string]string{"items": {{"id": targetID}}}
	data, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", cfBaseURL, c.accountID, c.listID)
	resp, err := c.do(ctx, http.MethodDelete, url, data)
	if err != nil {
		return fmt.Errorf("cloudflare: remove from blocklist: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("cloudflare: remove failed: %v", resp.Errors)
	}

	slog.Info("cloudflare: ip removed from list", slog.String("ip", ip))
	return nil
}

func (c *cloudflareWAF) IsBlocked(ctx context.Context, ip string) (bool, error) {
	items, err := c.listItems(ctx)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.IP == ip {
			return true, nil
		}
	}
	return false, nil
}

func (c *cloudflareWAF) HealthCheck(ctx context.Context) error {
	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s", cfBaseURL, c.accountID, c.listID)
	resp, err := c.do(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("cloudflare: health check: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("cloudflare: health check failed: %v", resp.Errors)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type cfResponse struct {
	Success bool        `json:"success"`
	Errors  []cfError   `json:"errors"`
	Result  interface{} `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfListItem struct {
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

func (c *cloudflareWAF) listItems(ctx context.Context) ([]cfListItem, error) {
	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", cfBaseURL, c.accountID, c.listID)

	type listResp struct {
		Success bool         `json:"success"`
		Errors  []cfError    `json:"errors"`
		Result  []cfListItem `json:"result"`
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	var result listResp
	if err := json.NewDecoder(httpResp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("cloudflare: decode list response: %w", err)
	}
	if !result.Success {
		return nil, fmt.Errorf("cloudflare: list items failed: %v", result.Errors)
	}
	return result.Result, nil
}

func (c *cloudflareWAF) do(ctx context.Context, method, url string, body []byte) (*cfResponse, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result cfResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("cloudflare: decode response: %w", err)
	}
	return &result, nil
}
