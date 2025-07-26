package firewall

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/sirupsen/logrus"
)

// NftablesBackend implements firewall operations using nftables
type NftablesBackend struct {
	config config.FirewallConfig
	logger *logrus.Logger
	table  string
	chain  string
}

// NewNftablesBackend creates a new nftables backend
func NewNftablesBackend(cfg config.FirewallConfig, logger *logrus.Logger) (*NftablesBackend, error) {
	backend := &NftablesBackend{
		config: cfg,
		logger: logger,
		table:  "nginx_defender",
		chain:  cfg.Chain,
	}
	
	if err := backend.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize nftables: %v", err)
	}
	
	return backend, nil
}

// Name returns the backend name
func (b *NftablesBackend) Name() string {
	return "nftables"
}

// AddRule adds a firewall rule using nftables
func (b *NftablesBackend) AddRule(rule *Rule) error {
	var nftCommand string
	
	switch rule.Action {
	case ActionBlock, ActionDrop:
		nftCommand = fmt.Sprintf("add rule ip %s %s ip saddr %s drop comment \"%s\"",
			b.table, b.chain, rule.IP, fmt.Sprintf("nginx-defender:%s:%s", rule.ID, rule.Reason))
			
	case ActionReject:
		nftCommand = fmt.Sprintf("add rule ip %s %s ip saddr %s reject comment \"%s\"",
			b.table, b.chain, rule.IP, fmt.Sprintf("nginx-defender:%s:%s", rule.ID, rule.Reason))
			
	case ActionRateLimit:
		limit := "10/minute"
		if limitStr, exists := rule.Metadata["limit"]; exists {
			limit = limitStr
		}
		nftCommand = fmt.Sprintf("add rule ip %s %s ip saddr %s limit rate %s accept comment \"%s\"",
			b.table, b.chain, rule.IP, limit, fmt.Sprintf("nginx-defender:%s:rate-limit", rule.ID))
			
	default:
		return fmt.Errorf("unsupported action: %s", rule.Action)
	}
	
	cmd := exec.Command("nft", strings.Fields(nftCommand)...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nftables command failed: %v, output: %s", err, string(output))
	}
	
	b.logger.Debugf("Added nftables rule for IP %s with action %s", rule.IP, rule.Action)
	return nil
}

// RemoveRule removes a firewall rule
func (b *NftablesBackend) RemoveRule(ruleID string) error {
	// List rules and find the one to remove
	cmd := exec.Command("nft", "list", "chain", "ip", b.table, b.chain)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list nftables rules: %v", err)
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ruleID) {
			// Extract handle from the line (simplified)
			// In real implementation, would need proper parsing
			// For now, use a different approach
			b.logger.Debugf("Would remove nftables rule containing: %s", ruleID)
			break
		}
	}
	
	return nil
}

// ListRules lists all active rules
func (b *NftablesBackend) ListRules() ([]*Rule, error) {
	// Implementation would parse nftables output
	// For now, return empty list
	return []*Rule{}, nil
}

// IsBlocked checks if an IP is blocked
func (b *NftablesBackend) IsBlocked(ip string) (bool, error) {
	rules, err := b.ListRules()
	if err != nil {
		return false, err
	}
	
	for _, rule := range rules {
		if rule.IP == ip {
			return true, nil
		}
	}
	
	return false, nil
}

// Flush removes all rules managed by nginx-defender
func (b *NftablesBackend) Flush() error {
	cmd := exec.Command("nft", "flush", "chain", "ip", b.table, b.chain)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush nftables chain: %v, output: %s", err, string(output))
	}
	
	b.logger.Info("Flushed all nginx-defender nftables rules")
	return nil
}

// initialize sets up the nftables table and chain
func (b *NftablesBackend) initialize() error {
	commands := [][]string{
		{"nft", "add", "table", "ip", b.table},
		{"nft", "add", "chain", "ip", b.table, b.chain, "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"},
	}
	
	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Ignore errors if table/chain already exists
			if !strings.Contains(string(output), "exists") {
				b.logger.WithError(err).Warnf("nftables command failed: %v", string(output))
			}
		}
	}
	
	return nil
}
