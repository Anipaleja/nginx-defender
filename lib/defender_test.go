package defender

import (
	"testing"
	"time"
)

func TestDefenderCreation(t *testing.T) {
	// Test default config
	def, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create defender with default config: %v", err)
	}
	defer def.Close()

	if def == nil {
		t.Fatal("Defender instance is nil")
	}
}

func TestDefenderStartStop(t *testing.T) {
	def, err := New(DevelopmentConfig())
	if err != nil {
		t.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	// Test start
	if err := def.Start(); err != nil {
		t.Fatalf("Failed to start defender: %v", err)
	}

	if !def.IsStarted() {
		t.Error("Defender should be started")
	}

	// Test stop
	if err := def.Stop(); err != nil {
		t.Fatalf("Failed to stop defender: %v", err)
	}

	if def.IsStarted() {
		t.Error("Defender should be stopped")
	}
}

func TestIPValidation(t *testing.T) {
	def, err := New(DevelopmentConfig())
	if err != nil {
		t.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	// Start defender
	if err := def.Start(); err != nil {
		t.Fatalf("Failed to start defender: %v", err)
	}

	// Test valid IPs
	validIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"203.0.113.1",
		"127.0.0.1",
	}

	for _, ip := range validIPs {
		score := def.GetThreatScore(ip)
		if score < 0 {
			t.Errorf("Threat score should be non-negative for valid IP %s, got %d", ip, score)
		}

		// Should not block by default in development mode
		if def.ShouldBlock(ip) {
			t.Errorf("IP %s should not be blocked by default in development mode", ip)
		}
	}

	// Test invalid IPs
	invalidIPs := []string{
		"invalid-ip",
		"999.999.999.999",
		"",
		"not.an.ip",
	}

	for _, ip := range invalidIPs {
		score := def.GetThreatScore(ip)
		if score != 0 {
			t.Errorf("Invalid IP %s should have score 0, got %d", ip, score)
		}

		if def.ShouldBlock(ip) {
			t.Errorf("Invalid IP %s should not trigger blocking", ip)
		}
	}
}

func TestManualBlocking(t *testing.T) {
	def, err := New(DevelopmentConfig())
	if err != nil {
		t.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	if err := def.Start(); err != nil {
		t.Fatalf("Failed to start defender: %v", err)
	}

	testIP := "203.0.113.1"

	// Test blocking
	err = def.BlockIP(testIP, 5*time.Minute, "Test blocking")
	if err != nil {
		t.Fatalf("Failed to block IP: %v", err)
	}

	// Test unblocking
	err = def.UnblockIP(testIP)
	if err != nil {
		t.Fatalf("Failed to unblock IP: %v", err)
	}

	// Test invalid IP blocking
	err = def.BlockIP("invalid-ip", time.Minute, "Test")
	if err == nil {
		t.Error("Should fail to block invalid IP")
	}
}

func TestLogMonitoring(t *testing.T) {
	def, err := New(DevelopmentConfig())
	if err != nil {
		t.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	if err := def.Start(); err != nil {
		t.Fatalf("Failed to start defender: %v", err)
	}

	// Test monitoring a file (even if it doesn't exist for testing)
	err = def.MonitorLogFile("/tmp/test.log", CombinedFormat)
	if err != nil {
		t.Errorf("Failed to monitor log file: %v", err)
	}

	// Test monitoring the same file again (should fail)
	err = def.MonitorLogFile("/tmp/test.log", CombinedFormat)
	if err == nil {
		t.Error("Should fail to monitor the same file twice")
	}
}

func TestEventHandlers(t *testing.T) {
	def, err := New(DevelopmentConfig())
	if err != nil {
		t.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	// Test setting event handlers
	blockDecision := false

	def.OnThreatDetected(func(event ThreatEvent) {
		// Threat detected callback for testing
	})

	def.OnBlockDecision(func(event BlockEvent) {
		blockDecision = true
	})

	if err := def.Start(); err != nil {
		t.Fatalf("Failed to start defender: %v", err)
	}

	// Trigger a block event
	testIP := "203.0.113.1"
	def.BlockIP(testIP, time.Minute, "Test event")

	if !blockDecision {
		t.Error("Block decision event handler was not called")
	}
}

func TestMetrics(t *testing.T) {
	def, err := New(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	metrics := def.GetMetrics()
	if metrics == nil {
		t.Error("Metrics should not be nil")
	}

	// Check for expected metric keys
	expectedKeys := []string{"threats_detected", "ips_blocked", "requests_analyzed", "library_version"}
	for _, key := range expectedKeys {
		if _, exists := metrics[key]; !exists {
			t.Errorf("Expected metric key %s not found", key)
		}
	}
}

func TestConfigurations(t *testing.T) {
	// Test default config
	defaultCfg := DefaultConfig()
	if defaultCfg.LogLevel != "info" {
		t.Errorf("Default log level should be 'info', got '%s'", defaultCfg.LogLevel)
	}

	// Test production config
	prodCfg := ProductionConfig()
	if prodCfg.LogLevel != "warn" {
		t.Errorf("Production log level should be 'warn', got '%s'", prodCfg.LogLevel)
	}

	// Test development config
	devCfg := DevelopmentConfig()
	if !devCfg.DryRun {
		t.Error("Development config should have DryRun enabled")
	}

	if devCfg.LogLevel != "debug" {
		t.Errorf("Development log level should be 'debug', got '%s'", devCfg.LogLevel)
	}
}

func TestVersion(t *testing.T) {
	version := Version()
	if version == "" {
		t.Error("Version should not be empty")
	}

	if version != "2.0.0" {
		t.Errorf("Expected version '2.0.0', got '%s'", version)
	}
}

// Benchmark tests
func BenchmarkThreatScoring(b *testing.B) {
	def, err := New(DefaultConfig())
	if err != nil {
		b.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	def.Start()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		def.GetThreatScore("192.168.1.100")
	}
}

func BenchmarkShouldBlock(b *testing.B) {
	def, err := New(DefaultConfig())
	if err != nil {
		b.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	def.Start()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		def.ShouldBlock("192.168.1.100")
	}
}
