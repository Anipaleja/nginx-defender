package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/sirupsen/logrus"
)

// NftablesBackend implements firewall operations using nftables
type NftablesBackend struct {
	config config.FirewallConfig
	logger *logrus.Logger
	table  string
	chain  string

	ipv4Set string
	ipv6Set string

	rules map[string]*Rule
	mutex sync.RWMutex
}

// NewNftablesBackend creates a new nftables backend
func NewNftablesBackend(cfg config.FirewallConfig, logger *logrus.Logger) (*NftablesBackend, error) {
	backend := &NftablesBackend{
		config:  cfg,
		logger:  logger,
		table:   "nginx_defender",
		chain:   normalizeNFTChain(cfg.Chain),
		ipv4Set: "blocked_ipv4",
		ipv6Set: "blocked_ipv6",
		rules:   make(map[string]*Rule),
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
	if rule == nil {
		return fmt.Errorf("cannot add nil rule")
	}

	if rule.Duration <= 0 {
		rule.Duration = 24 * time.Hour
		rule.ExpiresAt = time.Now().Add(rule.Duration)
	}

	parsedIP := net.ParseIP(rule.IP)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", rule.IP)
	}

	if rule.Action != ActionBlock && rule.Action != ActionDrop && rule.Action != ActionReject && rule.Action != ActionTarpit {
		return fmt.Errorf("unsupported action for nftables set backend: %s", rule.Action)
	}

	setName := b.ipv4Set
	if parsedIP.To4() == nil {
		setName = b.ipv6Set
	}

	// Replace existing element to refresh timeout.
	_ = b.execute("delete", "element", "inet", b.table, setName, "{", rule.IP, "}")

	timeout := rule.Duration.Truncate(time.Second)
	if timeout < time.Second {
		timeout = time.Second
	}

	if err := b.execute("add", "element", "inet", b.table, setName, "{", rule.IP, "timeout", timeout.String(), "}"); err != nil {
		return fmt.Errorf("failed to add element to nftables set %s: %w", setName, err)
	}

	b.mutex.Lock()
	b.rules[rule.ID] = rule
	b.mutex.Unlock()

	b.logger.Debugf("Added nftables set entry for IP %s with action %s", rule.IP, rule.Action)
	return nil
}

// RemoveRule removes a firewall rule
func (b *NftablesBackend) RemoveRule(ruleID string) error {
	b.mutex.RLock()
	rule, exists := b.rules[ruleID]
	b.mutex.RUnlock()

	if !exists {
		return nil
	}

	parsedIP := net.ParseIP(rule.IP)
	if parsedIP == nil {
		return fmt.Errorf("invalid stored IP for rule %s", ruleID)
	}

	setName := b.ipv4Set
	if parsedIP.To4() == nil {
		setName = b.ipv6Set
	}

	if err := b.execute("delete", "element", "inet", b.table, setName, "{", rule.IP, "}"); err != nil {
		if !isNFTNoSuchElementError(err) {
			return fmt.Errorf("failed to remove IP %s from set %s: %w", rule.IP, setName, err)
		}
	}

	b.mutex.Lock()
	delete(b.rules, ruleID)
	b.mutex.Unlock()

	return nil
}

// ListRules lists all active rules
func (b *NftablesBackend) ListRules() ([]*Rule, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	rules := make([]*Rule, 0, len(b.rules))
	now := time.Now()
	for _, rule := range b.rules {
		if rule.ExpiresAt.After(now) {
			ruleCopy := *rule
			rules = append(rules, &ruleCopy)
		}
	}

	return rules, nil
}

// IsBlocked checks if an IP is blocked
func (b *NftablesBackend) IsBlocked(ip string) (bool, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	now := time.Now()
	for _, rule := range b.rules {
		if rule.IP == ip && rule.ExpiresAt.After(now) {
			return true, nil
		}
	}

	return false, nil
}

// Flush removes all rules managed by nginx-defender
func (b *NftablesBackend) Flush() error {
	if err := b.execute("flush", "set", "inet", b.table, b.ipv4Set); err != nil && !isNFTNoSuchElementError(err) {
		return fmt.Errorf("failed to flush nftables set %s: %w", b.ipv4Set, err)
	}

	if err := b.execute("flush", "set", "inet", b.table, b.ipv6Set); err != nil && !isNFTNoSuchElementError(err) {
		return fmt.Errorf("failed to flush nftables set %s: %w", b.ipv6Set, err)
	}

	b.mutex.Lock()
	b.rules = make(map[string]*Rule)
	b.mutex.Unlock()

	b.logger.Info("Flushed all nginx-defender nftables rules")
	return nil
}

// initialize sets up the nftables table and chain
func (b *NftablesBackend) initialize() error {
	commands := [][]string{
		{"add", "table", "inet", b.table},
		{"add", "set", "inet", b.table, b.ipv4Set, "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"},
		{"add", "set", "inet", b.table, b.ipv6Set, "{", "type", "ipv6_addr", ";", "flags", "timeout", ";", "}"},
		{"add", "chain", "inet", b.table, b.chain, "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"},
		{"add", "rule", "inet", b.table, b.chain, "ip", "saddr", "@" + b.ipv4Set, "drop", "comment", "nginx-defender-ipv4"},
		{"add", "rule", "inet", b.table, b.chain, "ip6", "saddr", "@" + b.ipv6Set, "drop", "comment", "nginx-defender-ipv6"},
	}

	for _, command := range commands {
		if err := b.execute(command...); err != nil && !isNFTAlreadyExistsError(err) {
			return err
		}
	}

	return nil
}

func (b *NftablesBackend) execute(args ...string) error {
	cmd := exec.Command("nft", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s failed: %v, output: %s", strings.Join(args, " "), err, string(output))
	}

	return nil
}

func normalizeNFTChain(chain string) string {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		return "input"
	}

	chain = strings.ToLower(chain)
	if regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(chain) {
		return chain
	}

	return "input"
}

func isNFTAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}

	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "file exists") || strings.Contains(errText, "exists")
}

func isNFTNoSuchElementError(err error) bool {
	if err == nil {
		return false
	}

	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "no such file") || strings.Contains(errText, "no such element")
}
