package firewall

import (
	"testing"
	"time"
	
	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestBlockIP(t *testing.T) {
	cfg := config.FirewallConfig{
		Backend:   "mock",
		Whitelist: []string{"127.0.0.1"},
	}
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewManager(cfg, logger)
	require.NoError(t, err)
	defer manager.Shutdown()
	
	// Test blocking a valid IP
	err = manager.BlockIP("192.168.1.100", ActionBlock, 5*time.Minute, "test block", nil)
	assert.NoError(t, err)
	
	// Give the worker time to process
	time.Sleep(100 * time.Millisecond)
	
	// Check if IP is blocked
	blocked, rule := manager.IsBlocked("192.168.1.100")
	assert.True(t, blocked)
	assert.NotNil(t, rule)
	assert.Equal(t, ActionBlock, rule.Action)
	assert.Equal(t, "test block", rule.Reason)
}

func TestWhitelistedIP(t *testing.T) {
	cfg := config.FirewallConfig{
		Backend:   "mock",
		Whitelist: []string{"127.0.0.1", "192.168.1.0/24"},
	}
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewManager(cfg, logger)
	require.NoError(t, err)
	defer manager.Shutdown()
	
	// Test blocking a whitelisted IP (should be ignored)
	err = manager.BlockIP("127.0.0.1", ActionBlock, 5*time.Minute, "test block", nil)
	assert.NoError(t, err)
	
	time.Sleep(100 * time.Millisecond)
	
	// Should not be blocked
	blocked, _ := manager.IsBlocked("127.0.0.1")
	assert.False(t, blocked)
	
	// Test blocking IP in whitelisted CIDR range
	err = manager.BlockIP("192.168.1.50", ActionBlock, 5*time.Minute, "test block", nil)
	assert.NoError(t, err)
	
	time.Sleep(100 * time.Millisecond)
	
	blocked, _ = manager.IsBlocked("192.168.1.50")
	assert.False(t, blocked)
}

func TestUnblockIP(t *testing.T) {
	cfg := config.FirewallConfig{
		Backend: "mock",
	}
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewManager(cfg, logger)
	require.NoError(t, err)
	defer manager.Shutdown()
	
	// Block an IP first
	err = manager.BlockIP("192.168.1.100", ActionBlock, 10*time.Minute, "test block", nil)
	assert.NoError(t, err)
	
	time.Sleep(100 * time.Millisecond)
	
	// Verify it's blocked
	blocked, _ := manager.IsBlocked("192.168.1.100")
	assert.True(t, blocked)
	
	// Unblock it
	err = manager.UnblockIP("192.168.1.100")
	assert.NoError(t, err)
	
	time.Sleep(100 * time.Millisecond)
	
	// Verify it's no longer blocked
	blocked, _ = manager.IsBlocked("192.168.1.100")
	assert.False(t, blocked)
}

func TestInvalidIP(t *testing.T) {
	cfg := config.FirewallConfig{
		Backend: "mock",
	}
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewManager(cfg, logger)
	require.NoError(t, err)
	defer manager.Shutdown()
	
	// Test blocking invalid IP
	err = manager.BlockIP("invalid-ip", ActionBlock, 5*time.Minute, "test block", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address")
}

func TestGetStats(t *testing.T) {
	cfg := config.FirewallConfig{
		Backend: "mock",
	}
	
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	
	manager, err := NewManager(cfg, logger)
	require.NoError(t, err)
	defer manager.Shutdown()
	
	// Block a few IPs with different actions
	manager.BlockIP("192.168.1.1", ActionBlock, 10*time.Minute, "test", nil)
	manager.BlockIP("192.168.1.2", ActionDrop, 10*time.Minute, "test", nil)
	manager.BlockIP("192.168.1.3", ActionRateLimit, 10*time.Minute, "test", nil)
	
	time.Sleep(200 * time.Millisecond)
	
	stats := manager.GetStats()
	assert.Equal(t, "mock", stats["backend"])
	assert.Equal(t, 3, stats["total_rules"])
	assert.Equal(t, 3, stats["active_rules"])
	
	actions := stats["actions"].(map[Action]int)
	assert.Equal(t, 1, actions[ActionBlock])
	assert.Equal(t, 1, actions[ActionDrop])
	assert.Equal(t, 1, actions[ActionRateLimit])
}
