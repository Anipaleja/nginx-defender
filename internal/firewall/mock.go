package firewall

import (
	"sync"
	"time"
)

// MockBackend implements a mock firewall backend for testing
type MockBackend struct {
	rules map[string]*Rule
	mutex sync.RWMutex
}

// NewMockBackend creates a new mock backend
func NewMockBackend() *MockBackend {
	return &MockBackend{
		rules: make(map[string]*Rule),
	}
}

// Name returns the backend name
func (b *MockBackend) Name() string {
	return "mock"
}

// AddRule adds a rule to the mock backend
func (b *MockBackend) AddRule(rule *Rule) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	
	b.rules[rule.ID] = rule
	return nil
}

// RemoveRule removes a rule from the mock backend
func (b *MockBackend) RemoveRule(ruleID string) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	
	delete(b.rules, ruleID)
	return nil
}

// ListRules lists all rules in the mock backend
func (b *MockBackend) ListRules() ([]*Rule, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	
	rules := make([]*Rule, 0, len(b.rules))
	for _, rule := range b.rules {
		rules = append(rules, rule)
	}
	
	return rules, nil
}

// IsBlocked will check if an IP is blocked in the mock backend
func (b *MockBackend) IsBlocked(ip string) (bool, error) {
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

// Flush removes all rules from the mock backend
func (b *MockBackend) Flush() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	
	b.rules = make(map[string]*Rule)
	return nil
}
