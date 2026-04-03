package waf

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/autoblock/autoblock/internal/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

type awsWAF struct {
	client    *wafv2.Client
	ipSetID   string
	ipSetName string
	scope     types.Scope
	name      string
}

func newAWSWAF(pc config.WAFProviderConfig) (*awsWAF, error) {
	region, _ := pc.Config["region"].(string)
	ipSetID, _ := pc.Config["ip_set_id"].(string)
	ipSetName, _ := pc.Config["ip_set_name"].(string)
	scopeStr, _ := pc.Config["scope"].(string)

	if region == "" {
		region = "us-east-1"
	}
	if ipSetName == "" {
		ipSetName = "autoblock-blacklist"
	}

	var scope types.Scope
	if strings.EqualFold(scopeStr, "CLOUDFRONT") {
		scope = types.ScopeCloudfront
	} else {
		scope = types.ScopeRegional
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws_waf: load config: %w", err)
	}

	return &awsWAF{
		client:    wafv2.NewFromConfig(cfg),
		ipSetID:   ipSetID,
		ipSetName: ipSetName,
		scope:     scope,
		name:      pc.Name,
	}, nil
}

func (w *awsWAF) Name() string { return w.name }

func (w *awsWAF) AddToBlocklist(ctx context.Context, ip string, _ time.Duration, reason string) error {
	cidr := toCIDR(ip)

	// AWS WAF IP sets replace the entire set — must read-modify-write atomically with lock token
	getOut, err := w.client.GetIPSet(ctx, &wafv2.GetIPSetInput{
		Id:    aws.String(w.ipSetID),
		Name:  aws.String(w.ipSetName),
		Scope: w.scope,
	})
	if err != nil {
		return fmt.Errorf("aws_waf: get ip set: %w", err)
	}

	// Deduplicate
	existing := getOut.IPSet.Addresses
	for _, addr := range existing {
		if addr == cidr {
			slog.Debug("aws_waf: ip already in set", slog.String("ip", ip))
			return nil
		}
	}

	updated := append(existing, cidr)
	_, err = w.client.UpdateIPSet(ctx, &wafv2.UpdateIPSetInput{
		Id:          aws.String(w.ipSetID),
		Name:        aws.String(w.ipSetName),
		Scope:       w.scope,
		Addresses:   updated,
		LockToken:   getOut.LockToken,
		Description: aws.String(fmt.Sprintf("autoblock: %s", reason)),
	})
	if err != nil {
		return fmt.Errorf("aws_waf: update ip set: %w", err)
	}

	slog.Info("aws_waf: ip added to blocklist", slog.String("ip", ip), slog.String("cidr", cidr))
	return nil
}

func (w *awsWAF) RemoveFromBlocklist(ctx context.Context, ip string) error {
	cidr := toCIDR(ip)

	getOut, err := w.client.GetIPSet(ctx, &wafv2.GetIPSetInput{
		Id:    aws.String(w.ipSetID),
		Name:  aws.String(w.ipSetName),
		Scope: w.scope,
	})
	if err != nil {
		return fmt.Errorf("aws_waf: get ip set: %w", err)
	}

	filtered := make([]string, 0, len(getOut.IPSet.Addresses))
	for _, addr := range getOut.IPSet.Addresses {
		if addr != cidr {
			filtered = append(filtered, addr)
		}
	}

	if len(filtered) == len(getOut.IPSet.Addresses) {
		return nil // not in set
	}

	_, err = w.client.UpdateIPSet(ctx, &wafv2.UpdateIPSetInput{
		Id:        aws.String(w.ipSetID),
		Name:      aws.String(w.ipSetName),
		Scope:     w.scope,
		Addresses: filtered,
		LockToken: getOut.LockToken,
	})
	if err != nil {
		return fmt.Errorf("aws_waf: update ip set (remove): %w", err)
	}

	slog.Info("aws_waf: ip removed from blocklist", slog.String("ip", ip))
	return nil
}

func (w *awsWAF) IsBlocked(ctx context.Context, ip string) (bool, error) {
	cidr := toCIDR(ip)
	getOut, err := w.client.GetIPSet(ctx, &wafv2.GetIPSetInput{
		Id:    aws.String(w.ipSetID),
		Name:  aws.String(w.ipSetName),
		Scope: w.scope,
	})
	if err != nil {
		return false, fmt.Errorf("aws_waf: is blocked: %w", err)
	}
	for _, addr := range getOut.IPSet.Addresses {
		if addr == cidr {
			return true, nil
		}
	}
	return false, nil
}

func (w *awsWAF) HealthCheck(ctx context.Context) error {
	_, err := w.client.GetIPSet(ctx, &wafv2.GetIPSetInput{
		Id:    aws.String(w.ipSetID),
		Name:  aws.String(w.ipSetName),
		Scope: w.scope,
	})
	if err != nil {
		return fmt.Errorf("aws_waf: health check: %w", err)
	}
	return nil
}

// toCIDR converts a bare IP to CIDR notation required by AWS WAF.
func toCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip // pass through — WAF will reject if invalid
	}
	if parsed.To4() != nil {
		return ip + "/32"
	}
	return ip + "/128"
}
