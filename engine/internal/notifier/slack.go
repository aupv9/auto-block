package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Slack struct {
	webhookURL string
	channel    string
	client     *http.Client
}

func NewSlack(webhookURL, channel string) *Slack {
	return &Slack{
		webhookURL: webhookURL,
		channel:    channel,
		client:     &http.Client{Timeout: 5 * time.Second},
	}
}

func (s *Slack) Send(ctx context.Context, evt Event) error {
	msg := s.buildMessage(evt)

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("slack: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack: unexpected status %d", resp.StatusCode)
	}
	return nil
}

type slackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Title  string       `json:"title"`
	Fields []slackField `json:"fields"`
	Footer string       `json:"footer"`
	Ts     int64        `json:"ts"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func (s *Slack) buildMessage(evt Event) slackMessage {
	color := "#FF0000" // red for blacklist
	title := fmt.Sprintf("🚨 IP Blacklisted: %s", evt.IP)
	status := "WAF push succeeded"
	if evt.Error != nil {
		color = "#FF8C00" // orange for WAF failure
		title = fmt.Sprintf("⚠️ IP Blacklisted (WAF push failed): %s", evt.IP)
		status = fmt.Sprintf("WAF push FAILED: %v", evt.Error)
	}

	fields := []slackField{
		{Title: "IP", Value: evt.IP, Short: true},
		{Title: "Score", Value: fmt.Sprintf("%d", evt.Score), Short: true},
		{Title: "WAF", Value: evt.WAF, Short: true},
		{Title: "Status", Value: status, Short: true},
	}

	return slackMessage{
		Channel: s.channel,
		Attachments: []slackAttachment{
			{
				Color:  color,
				Title:  title,
				Fields: fields,
				Footer: "AutoBlock Engine",
				Ts:     time.Now().Unix(),
			},
		},
	}
}
