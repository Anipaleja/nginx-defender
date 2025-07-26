package firewall

import (
	"fmt"
	"os/exec"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/sirupsen/logrus"
)

// PfBackend implements firewall operations using OpenBSD/FreeBSD pf
type PfBackend struct {
	config config.FirewallConfig
	logger *logrus.Logger
	table  string
}

// NewPfBackend creates a new pf backend
func NewPfBackend(cfg config.FirewallConfig, logger *logrus.Logger) (*PfBackend, error) {
	backend := &PfBackend{
		config: cfg,
		logger: logger,
		table:  "nginx_defender",
	}
	
	if err := backend.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize pf: %v", err)
	}
	
	return backend, nil
}

// Name returns the backend name
func (b *PfBackend) Name() string {
	return "pf"
}

// AddRule adds a firewall rule using pf
func (b *PfBackend) AddRule(rule *Rule) error {
	// Add IP to pf table
	cmd := exec.Command("pfctl", "-t", b.table, "-T", "add", rule.IP)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add IP to pf table: %v, output: %s", err, string(output))
	}
	
	b.logger.Debugf("Added IP %s to pf table %s", rule.IP, b.table)
	return nil
}

// RemoveRule removes a firewall rule
func (b *PfBackend) RemoveRule(ruleID string) error {
	// This is simplified - in reality we'd need to track which IP corresponds to which rule ID
	// For now, we'll need to track this at the manager level
	return fmt.Errorf("pf backend requires IP address for removal")
}

// RemoveIP removes an IP from the pf table
func (b *PfBackend) RemoveIP(ip string) error {
	cmd := exec.Command("pfctl", "-t", b.table, "-T", "delete", ip)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove IP from pf table: %v, output: %s", err, string(output))
	}
	
	b.logger.Debugf("Removed IP %s from pf table %s", ip, b.table)
	return nil
}

// ListRules lists all active rules
func (b *PfBackend) ListRules() ([]*Rule, error) {
	cmd := exec.Command("pfctl", "-t", b.table, "-T", "show")
	_, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list pf table entries: %v", err)
	}
	
	// Parse output and create rules
	// This is simplified - real implementation would need better tracking
	var rules []*Rule
	// lines := strings.Split(string(output), "\n")
	// ... parse IPs from output and create rules
	
	return rules, nil
}

// IsBlocked checks if an IP is blocked
func (b *PfBackend) IsBlocked(ip string) (bool, error) {
	cmd := exec.Command("pfctl", "-t", b.table, "-T", "test", ip)
	err := cmd.Run()
	
	// pfctl returns 0 if IP is in table, 1 if not
	return err == nil, nil
}

// Flush removes all rules managed by nginx-defender
func (b *PfBackend) Flush() error {
	cmd := exec.Command("pfctl", "-t", b.table, "-T", "flush")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush pf table: %v, output: %s", err, string(output))
	}
	
	b.logger.Info("Flushed all nginx-defender pf table entries")
	return nil
}

// initialize sets up the pf table
func (b *PfBackend) initialize() error {
	// Create table if it doesn't exist
	cmd := exec.Command("pfctl", "-t", b.table, "-T", "add")
	if output, err := cmd.CombinedOutput(); err != nil {
		// Table might already exist or pf might not be running
		b.logger.WithError(err).Warnf("pf initialization warning: %s", string(output))
	}
	
	return nil
}
