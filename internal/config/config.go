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
	Server          ServerConfig        `yaml:"server"`
	Logs            LogsConfig          `yaml:"logs"`
	Monitoring      MonitoringConfig    `yaml:"monitoring"`
	Detection       DetectionConfig     `yaml:"detection"`
	Firewall        FirewallConfig      `yaml:"firewall"`
	Notifications   NotificationsConfig `yaml:"notifications"`
	Metrics         MetricsConfig       `yaml:"metrics"`
	MachineLearning MLConfig            `yaml:"machine_learning"`
	Clustering      ClusteringConfig    `yaml:"clustering"`
	Performance     PerformanceConfig   `yaml:"performance"`
	Honeypot        HoneypotConfig      `yaml:"honeypot"`
	WebInterface    WebInterfaceConfig  `yaml:"web_interface"`
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
	RateLimiting       RateLimitingConfig       `yaml:"rate_limiting"`
	BruteForce         BruteForceConfig         `yaml:"brute_force"`
	DDosProtection     DDosProtectionConfig     `yaml:"ddos_protection"`
	Geographic         GeographicConfig         `yaml:"geographic"`
	UserAgentBlocking  UserAgentBlockingConfig  `yaml:"user_agent_blocking"`
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
	Enabled          bool     `yaml:"enabled"`
	BlockedCountries []string `yaml:"blocked_countries"`
	AllowedCountries []string `yaml:"allowed_countries"`
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
	Backend     string            `yaml:"backend"`
	Chain       string            `yaml:"chain"`
	JumpTarget  string            `yaml:"jump_target"`
	IPv6Support bool              `yaml:"ipv6_support"`
	Whitelist   []string          `yaml:"whitelist"`
	Persistence PersistenceConfig `yaml:"persistence"`
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
	Enabled               bool    `yaml:"enabled"`
	ModelPath             string  `yaml:"model_path"`
	TrainingDataRetention int     `yaml:"training_data_retention"`
	AnomalyThreshold      float64 `yaml:"anomaly_threshold"`
	UpdateInterval        int     `yaml:"update_interval"`
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

// WebInterfaceConfig represents web interface configuration
type WebInterfaceConfig struct {
	Enabled   bool            `yaml:"enabled"`
	Auth      AuthConfig      `yaml:"auth"`
	Features  FeaturesConfig  `yaml:"features"`
	WebSocket WebSocketConfig `yaml:"websocket"`
	API       APIConfig       `yaml:"api"`
	Static    StaticConfig    `yaml:"static"`
}

type AuthConfig struct {
	Enabled          bool                `yaml:"enabled"`
	Method           string              `yaml:"method"`
	SessionTimeout   int                 `yaml:"session_timeout"`
	DefaultUsername  string              `yaml:"default_username"`
	DefaultPassword  string              `yaml:"default_password"`
	PasswordHashAlgo string              `yaml:"password_hash_algo"`
	Users            []User              `yaml:"users"`
	JWT              JWTConfig           `yaml:"jwt"`
	OAuth            OAuthConfig         `yaml:"oauth"`
	TwoFA            TwoFAConfig         `yaml:"two_fa"`
	PasswordReset    PasswordResetConfig `yaml:"password_reset"`
	APIKeys          APIKeyConfig        `yaml:"api_keys"`
	AuditLogging     AuditLoggingConfig  `yaml:"audit_logging"`
}

type User struct {
	Username     string     `yaml:"username"`
	Password     string     `yaml:"password"`
	Email        string     `yaml:"email"`
	Roles        []string   `yaml:"roles"`
	TwoFAEnabled bool       `yaml:"two_fa_enabled"`
	TwoFASecret  string     `yaml:"two_fa_secret"`
	APIKeys      []string   `yaml:"api_keys"`
	LastLogin    *time.Time `yaml:"last_login,omitempty"`
	CreatedAt    time.Time  `yaml:"created_at"`
	UpdatedAt    time.Time  `yaml:"updated_at"`
	Active       bool       `yaml:"active"`
}

type FeaturesConfig struct {
	RealTimeDashboard   bool `yaml:"real_time_dashboard"`
	LogViewer           bool `yaml:"log_viewer"`
	ConfigurationEditor bool `yaml:"configuration_editor"`
	FirewallManagement  bool `yaml:"firewall_management"`
	StatisticsCharts    bool `yaml:"statistics_charts"`
	ThreatAnalysis      bool `yaml:"threat_analysis"`
}

type WebSocketConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Path         string `yaml:"path"`
	PingInterval int    `yaml:"ping_interval"`
	PongTimeout  int    `yaml:"pong_timeout"`
}

type APIConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Version     string   `yaml:"version"`
	RateLimit   int      `yaml:"rate_limit"`
	CorsEnabled bool     `yaml:"cors_enabled"`
	CorsOrigins []string `yaml:"cors_origins"`
}

type StaticConfig struct {
	Path          string `yaml:"path"`
	CacheDuration int    `yaml:"cache_duration"`
	Compression   bool   `yaml:"compression"`
}

type JWTConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Secret        string        `yaml:"secret"`
	Expiration    time.Duration `yaml:"expiration"`
	RefreshExpiry time.Duration `yaml:"refresh_expiry"`
	Issuer        string        `yaml:"issuer"`
	Algorithm     string        `yaml:"algorithm"`
}

type OAuthConfig struct {
	Enabled     bool            `yaml:"enabled"`
	Providers   []OAuthProvider `yaml:"providers"`
	RedirectURL string          `yaml:"redirect_url"`
	SuccessURL  string          `yaml:"success_url"`
	ErrorURL    string          `yaml:"error_url"`
}

type OAuthProvider struct {
	Name         string   `yaml:"name"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	AuthURL      string   `yaml:"auth_url"`
	TokenURL     string   `yaml:"token_url"`
	UserInfoURL  string   `yaml:"user_info_url"`
	Scopes       []string `yaml:"scopes"`
	Enabled      bool     `yaml:"enabled"`
}

type TwoFAConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Issuer      string `yaml:"issuer"`
	QRCodeSize  int    `yaml:"qr_code_size"`
	BackupCodes int    `yaml:"backup_codes"`
}

type PasswordResetConfig struct {
	Enabled       bool          `yaml:"enabled"`
	TokenExpiry   time.Duration `yaml:"token_expiry"`
	EmailTemplate string        `yaml:"email_template"`
	FromEmail     string        `yaml:"from_email"`
	ResetURL      string        `yaml:"reset_url"`
}

type APIKeyConfig struct {
	Enabled       bool          `yaml:"enabled"`
	KeyLength     int           `yaml:"key_length"`
	DefaultExpiry time.Duration `yaml:"default_expiry"`
	MaxKeys       int           `yaml:"max_keys"`
	Prefix        string        `yaml:"prefix"`
}

type AuditLoggingConfig struct {
	Enabled    bool   `yaml:"enabled"`
	LogFile    string `yaml:"log_file"`
	MaxSize    int    `yaml:"max_size"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
	Compress   bool   `yaml:"compress"`
	IncludeIP  bool   `yaml:"include_ip"`
	IncludeUA  bool   `yaml:"include_user_agent"`
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

	// Validate JWT configuration when enabled
	if c.WebInterface.Auth.JWT.Enabled {
		if len(c.WebInterface.Auth.JWT.Secret) < 32 {
			return fmt.Errorf("JWT secret must be at least 32 bytes long, got %d bytes", len(c.WebInterface.Auth.JWT.Secret))
		}

		if c.WebInterface.Auth.JWT.Algorithm != "" {
			allowedAlgorithms := []string{"HS256", "HS384", "HS512"}
			algorithmValid := false
			for _, alg := range allowedAlgorithms {
				if c.WebInterface.Auth.JWT.Algorithm == alg {
					algorithmValid = true
					break
				}
			}
			if !algorithmValid {
				return fmt.Errorf("JWT algorithm must be one of %v, got %s", allowedAlgorithms, c.WebInterface.Auth.JWT.Algorithm)
			}
		}

		if c.WebInterface.Auth.JWT.Expiration <= 0 {
			return fmt.Errorf("JWT expiration must be positive, got %v", c.WebInterface.Auth.JWT.Expiration)
		}

		if c.WebInterface.Auth.JWT.RefreshExpiry <= 0 {
			return fmt.Errorf("JWT refresh expiry must be positive, got %v", c.WebInterface.Auth.JWT.RefreshExpiry)
		}

		// Reasonable bounds check: max 30 days for expiration, max 90 days for refresh
		maxExpiration := 30 * 24 * time.Hour
		maxRefreshExpiry := 90 * 24 * time.Hour

		if c.WebInterface.Auth.JWT.Expiration > maxExpiration {
			return fmt.Errorf("JWT expiration too long (max %v), got %v", maxExpiration, c.WebInterface.Auth.JWT.Expiration)
		}

		if c.WebInterface.Auth.JWT.RefreshExpiry > maxRefreshExpiry {
			return fmt.Errorf("JWT refresh expiry too long (max %v), got %v", maxRefreshExpiry, c.WebInterface.Auth.JWT.RefreshExpiry)
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
