package firewall

import (
	"testing"
	"time"
	
	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/sirupsen/logrus"
)

func TestManagerCreation(t *testing.T) {
	cfg := config.FirewallConfig{
		Backend: "mock",
		Whitelist: []string{"127.0.0.1", "::1"},
	}
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests
	
	manager, err := NewManager(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	
	if manager == nil {
		t.Fatal("Manager should not be nil")
	}
	
	// Clean up
	manager.Shutdown()
}

func TestRuleCreation(t *testing.T) {
	rule := &Rule{
		ID:        "test-rule",
		IP:        "192.168.1.100",
		Action:    ActionBlock,
		Duration:  time.Hour,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Reason:    "Test block",
	}
	
	if rule.IP != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", rule.IP)
	}
	
	if rule.Action != ActionBlock {
		t.Errorf("Expected action BLOCK, got %s", rule.Action)
	}
}
