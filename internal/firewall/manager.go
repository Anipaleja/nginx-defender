package firewall

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/sirupsen/logrus"
)

// Action represents the type of firewall action
type Action string

const (
	ActionBlock     Action = "BLOCK"
	ActionDrop      Action = "DROP"
	ActionReject    Action = "REJECT"
	ActionRateLimit Action = "RATE_LIMIT"
	ActionTarpit    Action = "TARPIT"
	ActionAllow     Action = "ALLOW"
	ActionUnblock   Action = "UNBLOCK"
)

// Rule represents a firewall rule
type Rule struct {
	ID          string            `json:"id"`
	IP          string            `json:"ip"`
	Action      Action            `json:"action"`
	Duration    time.Duration     `json:"duration"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Reason      string            `json:"reason"`
	ThreatLevel string            `json:"threat_level"`
	Metadata    map[string]string `json:"metadata"`
}

// Manager manages firewall rules and backends
type Manager struct {
	config   config.FirewallConfig
	backend  Backend
	rules    map[string]*Rule
	mutex    sync.RWMutex
	logger   *logrus.Logger
	
	// Channels for async operations
	ruleChan   chan *Rule
	unblockChan chan string
	
	// Cleanup
	ctx    context.Context
	cancel context.CancelFunc
}

// Backend interface for different firewall implementations
type Backend interface {
	AddRule(rule *Rule) error
	RemoveRule(ruleID string) error
	ListRules() ([]*Rule, error)
	IsBlocked(ip string) (bool, error)
	Flush() error
	Name() string
}

// NewManager creates a new firewall manager
func NewManager(cfg config.FirewallConfig, logger *logrus.Logger) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &Manager{
		config:      cfg,
		rules:       make(map[string]*Rule),
		logger:      logger,
		ruleChan:    make(chan *Rule, 1000),
		unblockChan: make(chan string, 1000),
		ctx:         ctx,
		cancel:      cancel,
	}
	
	// Initialize backend
	backend, err := manager.createBackend()
	if err != nil {
		return nil, fmt.Errorf("failed to create firewall backend: %v", err)
	}
	manager.backend = backend
	
	// Start worker goroutines
	go manager.ruleWorker()
	go manager.unblockWorker()
	go manager.cleanupWorker()
	
	// Load existing rules
	if err := manager.loadExistingRules(); err != nil {
		logger.WithError(err).Warn("Failed to load existing firewall rules")
	}
	
	logger.Infof("Firewall manager initialized with backend: %s", backend.Name())
	return manager, nil
}

// createBackend creates the appropriate firewall backend
func (m *Manager) createBackend() (Backend, error) {
	switch m.config.Backend {
	case "iptables":
		return NewIptablesBackend(m.config, m.logger)
	case "nftables":
		return NewNftablesBackend(m.config, m.logger)
	case "pf":
		return NewPfBackend(m.config, m.logger)
	case "mock":
		return NewMockBackend(), nil
	default:
		return NewIptablesBackend(m.config, m.logger) // Default to iptables
	}
}

// BlockIP blocks an IP address
func (m *Manager) BlockIP(ip string, action Action, duration time.Duration, reason string, metadata map[string]string) error {
	// Validate IP
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	
	// Check whitelist
	if m.isWhitelisted(ip) {
		m.logger.Infof("IP %s is whitelisted, skipping block", ip)
		return nil
	}
	
	// Check if already blocked
	m.mutex.RLock()
	existingRule, exists := m.rules[ip]
	m.mutex.RUnlock()
	
	if exists && existingRule.ExpiresAt.After(time.Now()) {
		m.logger.Infof("IP %s is already blocked until %v", ip, existingRule.ExpiresAt)
		return nil
	}
	
	// Create rule
	rule := &Rule{
		ID:          generateRuleID(),
		IP:          ip,
		Action:      action,
		Duration:    duration,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(duration),
		Reason:      reason,
		Metadata:    metadata,
	}
	
	// Add to pending rules
	select {
	case m.ruleChan <- rule:
		m.logger.Infof("Queued %s action for IP %s (duration: %v, reason: %s)", action, ip, duration, reason)
		return nil
	default:
		return fmt.Errorf("rule queue is full")
	}
}

// UnblockIP unblocks an IP address
func (m *Manager) UnblockIP(ip string) error {
	select {
	case m.unblockChan <- ip:
		m.logger.Infof("Queued unblock for IP %s", ip)
		return nil
	default:
		return fmt.Errorf("unblock queue is full")
	}
}

// IsBlocked checks if an IP is currently blocked
func (m *Manager) IsBlocked(ip string) (bool, *Rule) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	rule, exists := m.rules[ip]
	if !exists {
		return false, nil
	}
	
	// Check if rule has expired
	if rule.ExpiresAt.Before(time.Now()) {
		return false, nil
	}
	
	return true, rule
}

// GetRules returns all active rules
func (m *Manager) GetRules() []*Rule {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	rules := make([]*Rule, 0, len(m.rules))
	now := time.Now()
	
	for _, rule := range m.rules {
		if rule.ExpiresAt.After(now) {
			rules = append(rules, rule)
		}
	}
	
	return rules
}

// GetStats returns firewall statistics
func (m *Manager) GetStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	stats := map[string]interface{}{
		"backend":      m.backend.Name(),
		"total_rules":  len(m.rules),
		"active_rules": 0,
		"expired_rules": 0,
		"actions": map[Action]int{
			ActionBlock:     0,
			ActionDrop:      0,
			ActionReject:    0,
			ActionRateLimit: 0,
			ActionTarpit:    0,
		},
	}
	
	now := time.Now()
	for _, rule := range m.rules {
		if rule.ExpiresAt.After(now) {
			stats["active_rules"] = stats["active_rules"].(int) + 1
			actionStats := stats["actions"].(map[Action]int)
			actionStats[rule.Action]++
		} else {
			stats["expired_rules"] = stats["expired_rules"].(int) + 1
		}
	}
	
	return stats
}

// ruleWorker processes pending firewall rules
func (m *Manager) ruleWorker() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case rule := <-m.ruleChan:
			if err := m.processRule(rule); err != nil {
				m.logger.WithError(err).Errorf("Failed to process rule for IP %s", rule.IP)
			}
		}
	}
}

// unblockWorker processes pending unblock requests
func (m *Manager) unblockWorker() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case ip := <-m.unblockChan:
			if err := m.processUnblock(ip); err != nil {
				m.logger.WithError(err).Errorf("Failed to unblock IP %s", ip)
			}
		}
	}
}

// cleanupWorker periodically cleans up expired rules
func (m *Manager) cleanupWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanupExpiredRules()
		}
	}
}

// processRule processes a single firewall rule
func (m *Manager) processRule(rule *Rule) error {
	// Add rule to backend
	if err := m.backend.AddRule(rule); err != nil {
		return fmt.Errorf("backend failed to add rule: %v", err)
	}
	
	// Store rule
	m.mutex.Lock()
	m.rules[rule.IP] = rule
	m.mutex.Unlock()
	
	m.logger.Infof("Applied %s action to IP %s (expires: %v)", rule.Action, rule.IP, rule.ExpiresAt)
	
	// Schedule automatic unblock
	if rule.Duration > 0 {
		go func() {
			time.Sleep(rule.Duration)
			m.UnblockIP(rule.IP)
		}()
	}
	
	return nil
}

// processUnblock processes an unblock request
func (m *Manager) processUnblock(ip string) error {
	m.mutex.RLock()
	rule, exists := m.rules[ip]
	m.mutex.RUnlock()
	
	if !exists {
		return fmt.Errorf("no rule found for IP %s", ip)
	}
	
	// Remove from backend
	if err := m.backend.RemoveRule(rule.ID); err != nil {
		return fmt.Errorf("backend failed to remove rule: %v", err)
	}
	
	// Remove from local storage
	m.mutex.Lock()
	delete(m.rules, ip)
	m.mutex.Unlock()
	
	m.logger.Infof("Unblocked IP %s", ip)
	return nil
}

// cleanupExpiredRules removes expired rules
func (m *Manager) cleanupExpiredRules() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	now := time.Now()
	expiredIPs := []string{}
	
	for ip, rule := range m.rules {
		if rule.ExpiresAt.Before(now) {
			expiredIPs = append(expiredIPs, ip)
		}
	}
	
	for _, ip := range expiredIPs {
		rule := m.rules[ip]
		
		// Remove from backend
		if err := m.backend.RemoveRule(rule.ID); err != nil {
			m.logger.WithError(err).Errorf("Failed to remove expired rule for IP %s", ip)
			continue
		}
		
		// Remove from local storage
		delete(m.rules, ip)
		m.logger.Infof("Cleaned up expired rule for IP %s", ip)
	}
}

// isWhitelisted checks if an IP is whitelisted
func (m *Manager) isWhitelisted(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	for _, whitelistEntry := range m.config.Whitelist {
		// Check if it's a CIDR range
		if strings.Contains(whitelistEntry, "/") {
			_, network, err := net.ParseCIDR(whitelistEntry)
			if err != nil {
				continue
			}
			if network.Contains(parsedIP) {
				return true
			}
		} else {
			// Direct IP comparison
			if whitelistEntry == ip {
				return true
			}
		}
	}
	
	return false
}

// loadExistingRules loads existing rules from the backend
func (m *Manager) loadExistingRules() error {
	rules, err := m.backend.ListRules()
	if err != nil {
		return err
	}
	
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	now := time.Now()
	for _, rule := range rules {
		if rule.ExpiresAt.After(now) {
			m.rules[rule.IP] = rule
		}
	}
	
	m.logger.Infof("Loaded %d existing firewall rules", len(rules))
	return nil
}

// Shutdown gracefully shuts down the firewall manager
func (m *Manager) Shutdown() error {
	m.logger.Info("Shutting down firewall manager")
	
	// Cancel context to stop workers
	m.cancel()
	
	// Process remaining rules in channels
	close(m.ruleChan)
	close(m.unblockChan)
	
	// Process any remaining rules
	for rule := range m.ruleChan {
		m.processRule(rule)
	}
	
	for ip := range m.unblockChan {
		m.processUnblock(ip)
	}
	
	return nil
}

// generateRuleID generates a unique rule ID
func generateRuleID() string {
	return fmt.Sprintf("nginx-defender-%d", time.Now().UnixNano())
}
