package waf

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/autoblock/autoblock/internal/config"
)

// nginxWAF maintains a geo-module ban file and triggers nginx reload.
//
// Expected nginx config:
//
//	geo $autoblock_banned {
//	    default 0;
//	    include /etc/nginx/autoblock-ban.conf;
//	}
//	server { if ($autoblock_banned) { return 403; } }
type nginxWAF struct {
	banFilePath   string
	reloadCommand string
	name          string
	mu            sync.Mutex
}

func newNginxWAF(pc config.WAFProviderConfig) (*nginxWAF, error) {
	banFilePath, _ := pc.Config["ban_file_path"].(string)
	reloadCmd, _ := pc.Config["reload_command"].(string)

	if banFilePath == "" {
		banFilePath = "/etc/nginx/autoblock-ban.conf"
	}
	if reloadCmd == "" {
		reloadCmd = "nginx -s reload"
	}

	return &nginxWAF{
		banFilePath:   banFilePath,
		reloadCommand: reloadCmd,
		name:          pc.Name,
	}, nil
}

func (n *nginxWAF) Name() string { return n.name }

func (n *nginxWAF) AddToBlocklist(ctx context.Context, ip string, _ time.Duration, _ string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ips, err := n.readBanFile()
	if err != nil {
		return err
	}

	// Idempotent — skip if already present
	for _, existing := range ips {
		if existing == ip {
			return nil
		}
	}

	ips = append(ips, ip)
	if err := n.writeBanFile(ips); err != nil {
		return err
	}

	if err := n.reload(ctx); err != nil {
		return err
	}

	slog.Info("nginx: ip added to ban file", slog.String("ip", ip), slog.String("file", n.banFilePath))
	return nil
}

func (n *nginxWAF) RemoveFromBlocklist(ctx context.Context, ip string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	ips, err := n.readBanFile()
	if err != nil {
		return err
	}

	filtered := make([]string, 0, len(ips))
	found := false
	for _, existing := range ips {
		if existing == ip {
			found = true
			continue
		}
		filtered = append(filtered, existing)
	}
	if !found {
		return nil // idempotent
	}

	if err := n.writeBanFile(filtered); err != nil {
		return err
	}

	if err := n.reload(ctx); err != nil {
		return err
	}

	slog.Info("nginx: ip removed from ban file", slog.String("ip", ip))
	return nil
}

func (n *nginxWAF) IsBlocked(_ context.Context, ip string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	ips, err := n.readBanFile()
	if err != nil {
		return false, err
	}
	for _, existing := range ips {
		if existing == ip {
			return true, nil
		}
	}
	return false, nil
}

func (n *nginxWAF) HealthCheck(_ context.Context) error {
	// Verify ban file is writable
	f, err := os.OpenFile(n.banFilePath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("nginx: ban file not writable: %w", err)
	}
	f.Close()
	return nil
}

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

// readBanFile reads IP entries from the nginx geo ban file.
// Expected format (one IP per line, lines starting with # are comments):
//
//	# AutoBlock ban file - do not edit manually
//	1.2.3.4 1;
//	5.6.7.8 1;
func (n *nginxWAF) readBanFile() ([]string, error) {
	f, err := os.Open(n.banFilePath)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("nginx: read ban file: %w", err)
	}
	defer f.Close()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Parse "1.2.3.4 1;" → "1.2.3.4"
		ip := strings.TrimSuffix(strings.Fields(line)[0], ";")
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips, scanner.Err()
}

func (n *nginxWAF) writeBanFile(ips []string) error {
	f, err := os.Create(n.banFilePath)
	if err != nil {
		return fmt.Errorf("nginx: write ban file: %w", err)
	}
	defer f.Close()

	fmt.Fprintf(f, "# AutoBlock ban file — managed automatically, do not edit\n")
	fmt.Fprintf(f, "# Last updated: %s\n", time.Now().UTC().Format(time.RFC3339))
	for _, ip := range ips {
		fmt.Fprintf(f, "%s 1;\n", ip)
	}
	return nil
}

func (n *nginxWAF) reload(ctx context.Context) error {
	parts := strings.Fields(n.reloadCommand)
	if len(parts) == 0 {
		return fmt.Errorf("nginx: empty reload command")
	}
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx: reload failed (%s): %w", strings.TrimSpace(string(out)), err)
	}
	slog.Debug("nginx: reload triggered")
	return nil
}
