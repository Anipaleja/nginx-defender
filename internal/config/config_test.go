package config

import (
	"testing"
)

func TestConfigStruct(t *testing.T) {
	// Test that basic config structures work
	cfg := &Config{
		Server: ServerConfig{
			BindAddress: "0.0.0.0",
			Port:        8080,
		},
		Logs: LogsConfig{
			Level:  "info",
			Format: "json",
		},
	}
	
	if cfg.Server.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", cfg.Server.Port)
	}
	
	if cfg.Logs.Level != "info" {
		t.Errorf("Expected log level 'info', got %s", cfg.Logs.Level)
	}
}

func TestFirewallConfig(t *testing.T) {
	cfg := FirewallConfig{
		Backend: "iptables",
		Chain:   "INPUT",
		Whitelist: []string{"127.0.0.1", "10.0.0.0/8"},
	}
	
	if cfg.Backend != "iptables" {
		t.Errorf("Expected backend 'iptables', got %s", cfg.Backend)
	}
	
	if len(cfg.Whitelist) != 2 {
		t.Errorf("Expected 2 whitelist entries, got %d", len(cfg.Whitelist))
	}
}
