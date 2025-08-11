package firewall

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
	
	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSuite provides isolated test environment
type TestSuite struct {
	manager *Manager
	logger  *logrus.Logger
	cleanup func()
}

// NewTestSuite creates a secure, isolated test environment
func NewTestSuite(t *testing.T) *TestSuite {
	t.Helper()
	
	// Create isolated logger for testing
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	logger.SetOutput(os.Stderr) // Ensure logs don't leak to stdout
	
	// Use secure test configuration with minimal privileges
	cfg := config.FirewallConfig{
		Backend: "mock", // Always use mock backend for security
		Whitelist: []string{
			"127.0.0.1",
			"::1",
			"169.254.0.0/16", // Link-local addresses
			"192.168.0.0/16", // Private range for testing
			"10.0.0.0/8",     // Private range for testing
		},
	}
	
	manager, err := NewManager(cfg, logger)
	require.NoError(t, err, "Failed to create secure test manager")
	require.NotNil(t, manager, "Manager should not be nil")
	
	return &TestSuite{
		manager: manager,
		logger:  logger,
		cleanup: func() {
			if manager != nil {
				manager.Shutdown()
			}
		},
	}
}

// Cleanup safely destroys the test environment
func (ts *TestSuite) Cleanup() {
	if ts.cleanup != nil {
		ts.cleanup()
	}
}

// generateSecureTestIP generates a cryptographically secure test IP
func generateSecureTestIP(t *testing.T) string {
	t.Helper()
	
	// Use 192.168.x.x range for testing (safe private range)
	buf := make([]byte, 2)
	_, err := rand.Read(buf)
	require.NoError(t, err, "Failed to generate secure random bytes")
	
	return fmt.Sprintf("192.168.%d.%d", buf[0], buf[1])
}

// validateTestIP ensures IP is in safe test range
func validateTestIP(t *testing.T, ip string) {
	t.Helper()
	
	parsedIP := net.ParseIP(ip)
	require.NotNil(t, parsedIP, "Invalid IP address: %s", ip)
	
	// Ensure IP is in private ranges only
	privateRanges := []*net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
		{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)}, // localhost
	}
	
	for _, privateRange := range privateRanges {
		if privateRange.Contains(parsedIP) {
			return // Safe IP
		}
	}
	
	t.Fatalf("Test IP %s is not in safe private range", ip)
}

func TestManagerCreation(t *testing.T) {
	ts := NewTestSuite(t)
	defer ts.Cleanup()
	
	// Verify secure initialization
	assert.Equal(t, "mock", ts.manager.backend.Name(), "Should use mock backend for security")
	
	// Test backend security
	backend := ts.manager.backend
	assert.NotNil(t, backend, "Backend should be initialized")
	
	// Verify no real firewall operations in test mode
	rules, err := backend.ListRules()
	assert.NoError(t, err, "Should be able to list rules safely")
	assert.Empty(t, rules, "Should start with no rules")
}

func TestRuleCreation(t *testing.T) {
	// Use secure test IP generation
	testIP := generateSecureTestIP(t)
	validateTestIP(t, testIP)
	
	rule := &Rule{
		ID:        "test-rule-" + fmt.Sprintf("%d", time.Now().UnixNano()), // Unique ID
		IP:        testIP,
		Action:    ActionBlock,
		Duration:  time.Hour,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Reason:    "Automated security test",
		Metadata: map[string]string{
			"test_type": "security",
			"safe_mode": "true",
		},
	}
	
	// Validate rule security
	assert.NotEmpty(t, rule.ID, "Rule ID should not be empty")
	assert.Equal(t, testIP, rule.IP, "Rule IP should match generated test IP")
	assert.Equal(t, ActionBlock, rule.Action, "Rule action should be BLOCK")
	assert.Contains(t, rule.Reason, "security test", "Rule should indicate test purpose")
	assert.Equal(t, "true", rule.Metadata["safe_mode"], "Rule should be marked as safe mode")
	
	// Ensure rule expiration is reasonable
	assert.True(t, rule.ExpiresAt.After(rule.CreatedAt), "Rule should expire after creation")
	assert.True(t, rule.Duration > 0, "Rule duration should be positive")
}

func TestBlockIP_SecureImplementation(t *testing.T) {
	// Create a separate test manager with limited whitelist for this test
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	logger.SetOutput(os.Stderr)
	
	// Use minimal whitelist to allow blocking test
	cfg := config.FirewallConfig{
		Backend: "mock",
		Whitelist: []string{
			"127.0.0.1", // Only localhost whitelisted
		},
	}
	
	manager, err := NewManager(cfg, logger)
	require.NoError(t, err, "Failed to create test manager")
	defer manager.Shutdown()
	
	// Generate secure test IP (not whitelisted)
	testIP := generateSecureTestIP(t)
	validateTestIP(t, testIP)
	
	// Create context with timeout for security
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Test blocking with security metadata
	metadata := map[string]string{
		"test_id":    fmt.Sprintf("test-%d", time.Now().UnixNano()),
		"test_type":  "security_validation",
		"safe_mode":  "true",
		"context":    "automated_testing",
	}
	
	err = manager.BlockIP(testIP, ActionBlock, 5*time.Minute, "Security test block", metadata)
	require.NoError(t, err, "Should successfully block test IP")
	
	// Wait for processing with timeout protection
	select {
	case <-time.After(200 * time.Millisecond):
		// Processing complete
	case <-ctx.Done():
		t.Fatal("Test timed out - potential security issue")
	}
	
	// Verify blocking worked securely
	blocked, rule := manager.IsBlocked(testIP)
	assert.True(t, blocked, "IP should be blocked")
	require.NotNil(t, rule, "Rule should exist")
	
	// Validate rule security metadata
	assert.Equal(t, ActionBlock, rule.Action, "Action should be BLOCK")
	assert.Equal(t, "Security test block", rule.Reason, "Reason should match")
	assert.Equal(t, "true", rule.Metadata["safe_mode"], "Should be marked as safe mode")
	assert.Equal(t, "automated_testing", rule.Metadata["context"], "Should have test context")
	
	// Ensure rule has proper expiration
	assert.True(t, rule.ExpiresAt.After(time.Now()), "Rule should not be expired")
	assert.True(t, rule.ExpiresAt.Before(time.Now().Add(6*time.Minute)), "Rule should expire within expected time")
}

func TestWhitelistedIP_SecurityValidation(t *testing.T) {
	ts := NewTestSuite(t)
	defer ts.Cleanup()
	
	// Test with known safe IPs only
	whitelistedIPs := []string{
		"127.0.0.1",           // localhost
		"192.168.1.50",        // private range
		"10.0.0.1",            // private range
	}
	
	for _, ip := range whitelistedIPs {
		validateTestIP(t, ip)
		
		// Attempt to block whitelisted IP (should be safely ignored)
		err := ts.manager.BlockIP(ip, ActionBlock, 5*time.Minute, "Security whitelist test", map[string]string{
			"test_type": "whitelist_validation",
			"safe_mode": "true",
		})
		assert.NoError(t, err, "Whitelist blocking should not error for IP: %s", ip)
		
		// Verify IP is not blocked (whitelist protection working)
		time.Sleep(100 * time.Millisecond)
		blocked, _ := ts.manager.IsBlocked(ip)
		assert.False(t, blocked, "Whitelisted IP should not be blocked: %s", ip)
	}
	
	// Test CIDR range protection
	cidrTestIP := "192.168.100.200" // Should be in 192.168.0.0/16 if configured
	validateTestIP(t, cidrTestIP)
	
	err := ts.manager.BlockIP(cidrTestIP, ActionBlock, 5*time.Minute, "CIDR test", nil)
	assert.NoError(t, err, "CIDR blocking test should not error")
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
