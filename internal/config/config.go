package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Logs           LogsConfig           `yaml:"logs"`
	Monitoring     MonitoringConfig     `yaml:"monitoring"`
	Detection      DetectionConfig      `yaml:"detection"`
	Firewall       FirewallConfig       `yaml:"firewall"`
	Notifications  NotificationsConfig  `yaml:"notifications"`
	Metrics        MetricsConfig        `yaml:"metrics"`
	MachineLearning MLConfig            `yaml:"machine_learning"`
	Clustering     ClusteringConfig     `yaml:"clustering"`
	Performance    PerformanceConfig    `yaml:"performance"`
	Honeypot       HoneypotConfig       `yaml:"honeypot"`
}

type ServerConfig struct {
	BindAddress string    `yaml:"bind_address"`
	Port        int       `yaml:"port"`
	TLS         TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type LogsConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	FilePath   string `yaml:"file_path"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
}

type MonitoringConfig struct {
	NginxLogs  []LogConfig `yaml:"nginx_logs"`
	ApacheLogs []LogConfig `yaml:"apache_logs"`
}

type LogConfig struct {
	Path        string `yaml:"path"`
	Format      string `yaml:"format"`
	CustomRegex string `yaml:"custom_regex"`
}

type DetectionConfig struct {
	RateLimiting      RateLimitingConfig      `yaml:"rate_limiting"`
	BruteForce        BruteForceConfig        `yaml:"brute_force"`
	DDosProtection    DDosProtectionConfig    `yaml:"ddos_protection"`
	Geographic        GeographicConfig        `yaml:"geographic"`
	UserAgentBlocking UserAgentBlockingConfig `yaml:"user_agent_blocking"`
	SuspiciousPatterns SuspiciousPatternsConfig `yaml:"suspicious_patterns"`
}

type RateLimitingConfig struct {
	Enabled       bool `yaml:"enabled"`
	Threshold     int  `yaml:"threshold"`
	WindowSeconds int  `yaml:"window_seconds"`
	BlockDuration int  `yaml:"block_duration"`
}

type BruteForceConfig struct {
	Enabled        bool `yaml:"enabled"`
	FailedAttempts int  `yaml:"failed_attempts"`
	WindowSeconds  int  `yaml:"window_seconds"`
	BlockDuration  int  `yaml:"block_duration"`
}

type DDosProtectionConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerSecond int  `yaml:"requests_per_second"`
	BurstThreshold    int  `yaml:"burst_threshold"`
	BlockDuration     int  `yaml:"block_duration"`
}

type GeographicConfig struct {
	Enabled           bool     `yaml:"enabled"`
	BlockedCountries  []string `yaml:"blocked_countries"`
	AllowedCountries  []string `yaml:"allowed_countries"`
}

type UserAgentBlockingConfig struct {
	Enabled         bool     `yaml:"enabled"`
	BlockedPatterns []string `yaml:"blocked_patterns"`
	AllowedPatterns []string `yaml:"allowed_patterns"`
}

type SuspiciousPatternsConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Patterns []string `yaml:"patterns"`
}

type FirewallConfig struct {
	Backend     string              `yaml:"backend"`
	Chain       string              `yaml:"chain"`
	JumpTarget  string              `yaml:"jump_target"`
	IPv6Support bool                `yaml:"ipv6_support"`
	Whitelist   []string            `yaml:"whitelist"`
	Persistence PersistenceConfig   `yaml:"persistence"`
}

type PersistenceConfig struct {
	Enabled      bool   `yaml:"enabled"`
	SaveInterval int    `yaml:"save_interval"`
	RulesFile    string `yaml:"rules_file"`
}

type NotificationsConfig struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Slack    SlackConfig    `yaml:"slack"`
	Email    EmailConfig    `yaml:"email"`
	Webhook  WebhookConfig  `yaml:"webhook"`
}

type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
}

type EmailConfig struct {
	Enabled  bool     `yaml:"enabled"`
	SMTPHost string   `yaml:"smtp_host"`
	SMTPPort int      `yaml:"smtp_port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	Secret  string `yaml:"secret"`
}

type MetricsConfig struct {
	Prometheus       PrometheusConfig `yaml:"prometheus"`
	GrafanaDashboard bool             `yaml:"grafana_dashboard"`
	ExportInterval   int              `yaml:"export_interval"`
}

type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

type MLConfig struct {
	Enabled               bool   `yaml:"enabled"`
	ModelPath             string `yaml:"model_path"`
	TrainingDataRetention int    `yaml:"training_data_retention"`
	AnomalyThreshold      float64 `yaml:"anomaly_threshold"`
	UpdateInterval        int    `yaml:"update_interval"`
}

type ClusteringConfig struct {
	Enabled      bool   `yaml:"enabled"`
	RedisURL     string `yaml:"redis_url"`
	SyncInterval int    `yaml:"sync_interval"`
	NodeID       string `yaml:"node_id"`
}

type PerformanceConfig struct {
	MaxConcurrentBlocks int `yaml:"max_concurrent_blocks"`
	LogBufferSize       int `yaml:"log_buffer_size"`
	MemoryLimit         int `yaml:"memory_limit"`
	CPULimit            int `yaml:"cpu_limit"`
}

type HoneypotConfig struct {
	Enabled     bool  `yaml:"enabled"`
	Ports       []int `yaml:"ports"`
	LogAttempts bool  `yaml:"log_attempts"`
}

// Load loads configuration from the specified file
func Load(path string) (*Config, error) {
	// Set default values
	cfg := &Config{
		Server: ServerConfig{
			BindAddress: "0.0.0.0",
			Port:        8080,
		},
		Logs: LogsConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     30,
		},
		Detection: DetectionConfig{
			RateLimiting: RateLimitingConfig{
				Enabled:       true,
				Threshold:     100,
				WindowSeconds: 60,
				BlockDuration: 3600,
			},
		},
		Firewall: FirewallConfig{
			Backend:     "iptables",
			Chain:       "INPUT",
			JumpTarget:  "DROP",
			IPv6Support: true,
			Whitelist: []string{
				"127.0.0.1",
				"::1",
				"10.0.0.0/8",
				"172.16.0.0/12",
				"192.168.0.0/16",
			},
		},
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil // Return default config if file doesn't exist
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" || c.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS enabled but cert_file or key_file not specified")
		}
	}

	if c.Detection.RateLimiting.Enabled {
		if c.Detection.RateLimiting.Threshold <= 0 {
			return fmt.Errorf("rate limiting threshold must be positive")
		}
		if c.Detection.RateLimiting.WindowSeconds <= 0 {
			return fmt.Errorf("rate limiting window must be positive")
		}
	}

	return nil
}

// Save saves the configuration to the specified file
func (c *Config) Save(path string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
