package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"gopkg.in/yaml.v3"
	"golang.org/x/crypto/bcrypt"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiBlue   = "\033[34m"
)

type setupOptions struct {
	configPath    string
	force         bool
	nonInteractive bool
}

type setupConfig struct {
	Server       setupServerConfig       `yaml:"server"`
	Logs         setupLogsConfig         `yaml:"logs"`
	Monitoring   *setupMonitoringConfig  `yaml:"monitoring,omitempty"`
	Detection    *setupDetectionConfig   `yaml:"detection,omitempty"`
	Firewall     setupFirewallConfig     `yaml:"firewall"`
	WebInterface *setupWebInterfaceConfig `yaml:"web_interface,omitempty"`
}

type setupServerConfig struct {
	BindAddress string        `yaml:"bind_address"`
	Port        int           `yaml:"port"`
	TLS         setupTLSConfig `yaml:"tls"`
}

type setupTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
}

type setupLogsConfig struct {
	Level    string `yaml:"level"`
	Format   string `yaml:"format"`
	Output   string `yaml:"output"`
	FilePath string `yaml:"file_path,omitempty"`
}

type setupMonitoringConfig struct {
	NginxLogs  []setupLogConfig `yaml:"nginx_logs,omitempty"`
	ApacheLogs []setupLogConfig `yaml:"apache_logs,omitempty"`
}

type setupLogConfig struct {
	Path        string `yaml:"path"`
	Format      string `yaml:"format"`
	CustomRegex string `yaml:"custom_regex,omitempty"`
}

type setupDetectionConfig struct {
	Mode         string             `yaml:"mode"`
	RateLimiting setupRateLimitConfig `yaml:"rate_limiting"`
	Proxy        setupProxyConfig    `yaml:"proxy"`
}

type setupRateLimitConfig struct {
	Enabled       bool `yaml:"enabled"`
	Threshold     int  `yaml:"threshold"`
	WindowSeconds int  `yaml:"window_seconds"`
	BlockDuration int  `yaml:"block_duration"`
}

type setupProxyConfig struct {
	Enabled         bool     `yaml:"enabled"`
	TrustedProxies  []string `yaml:"trusted_proxies,omitempty"`
	ClientIPHeaders []string `yaml:"client_ip_headers,omitempty"`
}

type setupFirewallConfig struct {
	Backend     string                 `yaml:"backend"`
	Chain       string                 `yaml:"chain"`
	JumpTarget  string                 `yaml:"jump_target"`
	IPv6Support bool                   `yaml:"ipv6_support"`
	Whitelist   []string               `yaml:"whitelist,omitempty"`
	Persistence *setupPersistenceConfig `yaml:"persistence,omitempty"`
}

type setupPersistenceConfig struct {
	Enabled      bool   `yaml:"enabled"`
	SaveInterval int    `yaml:"save_interval"`
	RulesFile    string `yaml:"rules_file"`
}

type setupWebInterfaceConfig struct {
	Auth setupAuthConfig `yaml:"auth"`
}

type setupAuthConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Method          string `yaml:"method"`
	SessionTimeout  int    `yaml:"session_timeout"`
	DefaultUsername string `yaml:"default_username"`
	DefaultPassword string `yaml:"default_password"`
	PasswordHashAlgo string `yaml:"password_hash_algo"`
}

const setupBanner = `
 _   _           _           _         ____        __
| \ | | ___  ___| |_ ___  __| | ___   |  _ \ ___  / _|
|  \| |/ _ \ / __| __/ _ \ / _  |/ _ \  | |_) / _ \| |_
| |\  |  __/\__ \ ||  __/ (_| | (_) | |  _ < (_) |  _|
|_| \_|\___||___/\__\___|\__,_|\___/  |_| \_\___/|_|
`

func runSetup(args []string) int {
	if hasHelpFlag(args) {
		printSetupUsage(os.Stdout)
		return 0
	}

	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	configPath := fs.String("config", "config.yaml", "Path to write the config file")
	force := fs.Bool("force", false, "Overwrite config file if it exists")
	nonInteractive := fs.Bool("non-interactive", false, "Use defaults without prompting")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse setup options.")
		printSetupUsage(os.Stderr)
		return 2
	}

	opts := setupOptions{
		configPath:    strings.TrimSpace(*configPath),
		force:         *force,
		nonInteractive: *nonInteractive,
	}

	if opts.configPath == "" {
		opts.configPath = "config.yaml"
	}

	if err := runSetupWizard(opts); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}

	return 0
}

func runSetupWizard(opts setupOptions) error {
	printSetupBanner()
	if !opts.nonInteractive {
		printInfo("Press Enter to accept defaults.")
	}

	reader := bufio.NewReader(os.Stdin)

	configPath := opts.configPath
	if !opts.nonInteractive {
		value, err := promptString(reader, "Config file path", configPath)
		if err != nil {
			return err
		}
		configPath = value
	}
	configPath = expandPath(strings.TrimSpace(configPath))
	if configPath == "" {
		configPath = "config.yaml"
	}

	if exists(configPath) && !opts.force {
		if opts.nonInteractive {
			return fmt.Errorf("config file already exists: %s (use --force to overwrite)", configPath)
		}
		overwrite, err := promptYesNo(reader, fmt.Sprintf("Config file exists at %s. Overwrite", configPath), false)
		if err != nil {
			return err
		}
		if !overwrite {
			return errors.New("setup canceled")
		}
	}

	cfg := defaultSetupConfig()

	if err := applyInteractiveConfig(reader, cfg, opts.nonInteractive); err != nil {
		return err
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	setupCfg := buildSetupConfig(cfg)
	data, err := yaml.Marshal(&setupCfg)
	if err != nil {
		return fmt.Errorf("failed to render config: %w", err)
	}

	if err := writeConfigFile(configPath, data); err != nil {
		return err
	}

	printSuccess("Setup complete")
	printInfo(fmt.Sprintf("Config written to: %s", configPath))
	if cfg.WebInterface.Auth.Enabled {
		printInfo("Dashboard credentials saved as a bcrypt hash")
	}
	printSection("Next steps")
	fmt.Printf("  %s\n", colorize(ansiCyan, fmt.Sprintf("nginx-defender -config %s", configPath)))
	fmt.Printf("  %s\n", colorize(ansiCyan, "curl http://localhost:8080/health"))
	return nil
}

func applyInteractiveConfig(reader *bufio.Reader, cfg *config.Config, nonInteractive bool) error {
	bindAddress := cfg.Server.BindAddress
	if !nonInteractive {
		value, err := promptString(reader, "Bind address", bindAddress)
		if err != nil {
			return err
		}
		bindAddress = value
	}
	cfg.Server.BindAddress = strings.TrimSpace(bindAddress)

	port := cfg.Server.Port
	if !nonInteractive {
		value, err := promptInt(reader, "HTTP port", port, 1, 65535)
		if err != nil {
			return err
		}
		port = value
	}
	cfg.Server.Port = port

	tlsEnabled := cfg.Server.TLS.Enabled
	if !nonInteractive {
		value, err := promptYesNo(reader, "Enable TLS", tlsEnabled)
		if err != nil {
			return err
		}
		tlsEnabled = value
	}
	cfg.Server.TLS.Enabled = tlsEnabled
	if tlsEnabled {
		certDefault := "/etc/nginx-defender/ssl/cert.pem"
		keyDefault := "/etc/nginx-defender/ssl/key.pem"
		if !nonInteractive {
			cert, err := promptString(reader, "TLS cert file", certDefault)
			if err != nil {
				return err
			}
			key, err := promptString(reader, "TLS key file", keyDefault)
			if err != nil {
				return err
			}
			cfg.Server.TLS.CertFile = strings.TrimSpace(cert)
			cfg.Server.TLS.KeyFile = strings.TrimSpace(key)
		} else {
			cfg.Server.TLS.CertFile = certDefault
			cfg.Server.TLS.KeyFile = keyDefault
		}
	}

	logLevel := cfg.Logs.Level
	if !nonInteractive {
		value, err := promptChoice(reader, "Log level", []string{"debug", "info", "warn", "error"}, logLevel)
		if err != nil {
			return err
		}
		logLevel = value
	}
	cfg.Logs.Level = logLevel

	logFormat := cfg.Logs.Format
	if !nonInteractive {
		value, err := promptChoice(reader, "Log format", []string{"json", "text"}, logFormat)
		if err != nil {
			return err
		}
		logFormat = value
	}
	cfg.Logs.Format = logFormat

	logOutput := cfg.Logs.Output
	if logOutput == "" {
		logOutput = "stdout"
	}
	if !nonInteractive {
		value, err := promptChoice(reader, "Log output", []string{"stdout", "file"}, logOutput)
		if err != nil {
			return err
		}
		logOutput = value
	}
	cfg.Logs.Output = logOutput
	if logOutput == "file" {
		pathDefault := "./logs/nginx-defender.log"
		if !nonInteractive {
			value, err := promptString(reader, "Log file path", pathDefault)
			if err != nil {
				return err
			}
			pathDefault = value
		}
		cfg.Logs.FilePath = strings.TrimSpace(pathDefault)
	} else {
		cfg.Logs.FilePath = ""
	}

	monitoringEnabled := true
	if !nonInteractive {
		value, err := promptYesNo(reader, "Monitor an nginx access log", true)
		if err != nil {
			return err
		}
		monitoringEnabled = value
	}

	if monitoringEnabled {
		defaultPath := defaultNginxAccessLogPath()
		logPath := defaultPath
		if !nonInteractive {
			value, err := promptString(reader, "Nginx access log path", defaultPath)
			if err != nil {
				return err
			}
			logPath = value
		}
		logPath = strings.TrimSpace(logPath)
		if logPath == "" {
			return errors.New("nginx log path cannot be empty when monitoring is enabled")
		}

		format := "combined"
		if !nonInteractive {
			value, err := promptChoice(reader, "Nginx log format", []string{"combined", "common", "custom"}, format)
			if err != nil {
				return err
			}
			format = value
		}

		customRegex := ""
		if format == "custom" {
			if !nonInteractive {
				value, err := promptString(reader, "Custom log regex", "")
				if err != nil {
					return err
				}
				customRegex = value
			}
			customRegex = strings.TrimSpace(customRegex)
			if customRegex == "" {
				return errors.New("custom log regex is required when format is custom")
			}
		}

		cfg.Monitoring.NginxLogs = []config.LogConfig{{
			Path:        logPath,
			Format:      format,
			CustomRegex: strings.TrimSpace(customRegex),
		}}
	}

	backendDefault := cfg.Firewall.Backend
	if backendDefault == "" {
		backendDefault = defaultFirewallBackend()
	}
	if !nonInteractive {
		value, err := promptChoice(reader, "Firewall backend", []string{"nftables", "iptables", "pf", "mock"}, backendDefault)
		if err != nil {
			return err
		}
		backendDefault = value
	}
	cfg.Firewall.Backend = backendDefault

	ipv6 := cfg.Firewall.IPv6Support
	if !nonInteractive {
		value, err := promptYesNo(reader, "Enable IPv6 support", ipv6)
		if err != nil {
			return err
		}
		ipv6 = value
	}
	cfg.Firewall.IPv6Support = ipv6

	if !nonInteractive {
		extraWhitelist, err := promptString(reader, "Additional whitelist IPs/CIDRs (comma-separated)", "")
		if err != nil {
			return err
		}
		for _, entry := range splitCSV(extraWhitelist) {
			cfg.Firewall.Whitelist = append(cfg.Firewall.Whitelist, entry)
		}
	}

	mode := cfg.Detection.Mode
	if !nonInteractive {
		value, err := promptChoice(reader, "Detection mode", []string{"block", "monitor", "shadow", "ml", "hybrid"}, mode)
		if err != nil {
			return err
		}
		mode = value
	}
	cfg.Detection.Mode = mode

	rateLimitEnabled := cfg.Detection.RateLimiting.Enabled
	if !nonInteractive {
		value, err := promptYesNo(reader, "Enable rate limiting", rateLimitEnabled)
		if err != nil {
			return err
		}
		rateLimitEnabled = value
	}
	cfg.Detection.RateLimiting.Enabled = rateLimitEnabled
	if rateLimitEnabled {
		threshold := cfg.Detection.RateLimiting.Threshold
		windowSeconds := cfg.Detection.RateLimiting.WindowSeconds
		blockDuration := cfg.Detection.RateLimiting.BlockDuration

		if !nonInteractive {
			value, err := promptInt(reader, "Rate limit threshold (requests)", threshold, 1, 100000)
			if err != nil {
				return err
			}
			threshold = value

			value, err = promptInt(reader, "Rate limit window (seconds)", windowSeconds, 1, 3600)
			if err != nil {
				return err
			}
			windowSeconds = value

			value, err = promptInt(reader, "Block duration (seconds)", blockDuration, 1, 86400)
			if err != nil {
				return err
			}
			blockDuration = value
		}

		cfg.Detection.RateLimiting.Threshold = threshold
		cfg.Detection.RateLimiting.WindowSeconds = windowSeconds
		cfg.Detection.RateLimiting.BlockDuration = blockDuration
	}

	proxyEnabled := cfg.Detection.Proxy.Enabled
	if !nonInteractive {
		value, err := promptYesNo(reader, "Behind a proxy/load balancer", proxyEnabled)
		if err != nil {
			return err
		}
		proxyEnabled = value
	}
	cfg.Detection.Proxy.Enabled = proxyEnabled
	if proxyEnabled && !nonInteractive {
		trusted, err := promptString(reader, "Trusted proxy IPs/CIDRs (comma-separated)", "")
		if err != nil {
			return err
		}
		cfg.Detection.Proxy.TrustedProxies = splitCSV(trusted)
	}

	authEnabled := false
	if !nonInteractive {
		value, err := promptYesNo(reader, "Protect dashboard with login", true)
		if err != nil {
			return err
		}
		authEnabled = value
	}

	if authEnabled {
		cfg.WebInterface.Auth.Enabled = true
		cfg.WebInterface.Auth.Method = "session"
		cfg.WebInterface.Auth.SessionTimeout = 3600
		cfg.WebInterface.Auth.PasswordHashAlgo = "bcrypt"

		usernameDefault := "admin"
		if !nonInteractive {
			value, err := promptString(reader, "Admin username", usernameDefault)
			if err != nil {
				return err
			}
			usernameDefault = value
		}
		cfg.WebInterface.Auth.DefaultUsername = strings.TrimSpace(usernameDefault)

		password, err := promptPassword(reader, "Admin password (min 12 chars, upper/lower/digit/symbol)")
		if err != nil {
			return err
		}
		hashed, err := hashPassword(password)
		if err != nil {
			return err
		}
		cfg.WebInterface.Auth.DefaultPassword = hashed
	} else {
		cfg.WebInterface.Auth.Enabled = false
		cfg.WebInterface.Auth.DefaultUsername = ""
		cfg.WebInterface.Auth.DefaultPassword = ""
	}

	return nil
}

func buildSetupConfig(cfg *config.Config) setupConfig {
	setupCfg := setupConfig{
		Server: setupServerConfig{
			BindAddress: cfg.Server.BindAddress,
			Port:        cfg.Server.Port,
			TLS: setupTLSConfig{
				Enabled:  cfg.Server.TLS.Enabled,
				CertFile: cfg.Server.TLS.CertFile,
				KeyFile:  cfg.Server.TLS.KeyFile,
			},
		},
		Logs: setupLogsConfig{
			Level:    cfg.Logs.Level,
			Format:   cfg.Logs.Format,
			Output:   cfg.Logs.Output,
			FilePath: cfg.Logs.FilePath,
		},
		Detection: &setupDetectionConfig{
			Mode: cfg.Detection.Mode,
			RateLimiting: setupRateLimitConfig{
				Enabled:       cfg.Detection.RateLimiting.Enabled,
				Threshold:     cfg.Detection.RateLimiting.Threshold,
				WindowSeconds: cfg.Detection.RateLimiting.WindowSeconds,
				BlockDuration: cfg.Detection.RateLimiting.BlockDuration,
			},
			Proxy: setupProxyConfig{
				Enabled:         cfg.Detection.Proxy.Enabled,
				TrustedProxies:  cfg.Detection.Proxy.TrustedProxies,
				ClientIPHeaders: cfg.Detection.Proxy.ClientIPHeaders,
			},
		},
		Firewall: setupFirewallConfig{
			Backend:     cfg.Firewall.Backend,
			Chain:       cfg.Firewall.Chain,
			JumpTarget:  cfg.Firewall.JumpTarget,
			IPv6Support: cfg.Firewall.IPv6Support,
			Whitelist:   cfg.Firewall.Whitelist,
		},
	}

	if len(cfg.Monitoring.NginxLogs) > 0 || len(cfg.Monitoring.ApacheLogs) > 0 {
		monitoring := &setupMonitoringConfig{}
		for _, logCfg := range cfg.Monitoring.NginxLogs {
			monitoring.NginxLogs = append(monitoring.NginxLogs, setupLogConfig{
				Path:        logCfg.Path,
				Format:      logCfg.Format,
				CustomRegex: logCfg.CustomRegex,
			})
		}
		for _, logCfg := range cfg.Monitoring.ApacheLogs {
			monitoring.ApacheLogs = append(monitoring.ApacheLogs, setupLogConfig{
				Path:        logCfg.Path,
				Format:      logCfg.Format,
				CustomRegex: logCfg.CustomRegex,
			})
		}
		setupCfg.Monitoring = monitoring
	}

	if cfg.WebInterface.Auth.Enabled {
		setupCfg.WebInterface = &setupWebInterfaceConfig{
			Auth: setupAuthConfig{
				Enabled:         cfg.WebInterface.Auth.Enabled,
				Method:          cfg.WebInterface.Auth.Method,
				SessionTimeout:  cfg.WebInterface.Auth.SessionTimeout,
				DefaultUsername: cfg.WebInterface.Auth.DefaultUsername,
				DefaultPassword: cfg.WebInterface.Auth.DefaultPassword,
				PasswordHashAlgo: cfg.WebInterface.Auth.PasswordHashAlgo,
			},
		}
	}

	if cfg.Firewall.Persistence.Enabled {
		setupCfg.Firewall.Persistence = &setupPersistenceConfig{
			Enabled:      cfg.Firewall.Persistence.Enabled,
			SaveInterval: cfg.Firewall.Persistence.SaveInterval,
			RulesFile:    cfg.Firewall.Persistence.RulesFile,
		}
	}

	return setupCfg
}

func defaultSetupConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			BindAddress: "0.0.0.0",
			Port:        8080,
			TLS: config.TLSConfig{
				Enabled: false,
			},
		},
		Logs: config.LogsConfig{
			Level:      "info",
			Format:     "json",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     30,
		},
		Monitoring: config.MonitoringConfig{},
		Detection: config.DetectionConfig{
			Mode: "block",
			RateLimiting: config.RateLimitingConfig{
				Enabled:       true,
				Threshold:     100,
				WindowSeconds: 60,
				BlockDuration: 3600,
			},
			Proxy: config.ProxyConfig{
				Enabled:         false,
				TrustedProxies:  []string{},
				ClientIPHeaders: []string{"CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"},
			},
		},
		Firewall: config.FirewallConfig{
			Backend:     defaultFirewallBackend(),
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
		WebInterface: config.WebInterfaceConfig{
			Auth: config.AuthConfig{
				Enabled: false,
			},
		},
	}
}

func defaultFirewallBackend() string {
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd":
		return "pf"
	case "linux":
		return "nftables"
	default:
		return "mock"
	}
}

func defaultNginxAccessLogPath() string {
	switch runtime.GOOS {
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return "/opt/homebrew/var/log/nginx/access.log"
		}
		return "/usr/local/var/log/nginx/access.log"
	case "freebsd", "openbsd", "netbsd":
		return "/var/log/nginx/access.log"
	default:
		return "/var/log/nginx/access.log"
	}
}

func promptString(reader *bufio.Reader, label, defaultValue string) (string, error) {
	prompt := label + ": "
	if strings.TrimSpace(defaultValue) != "" {
		prompt = fmt.Sprintf("%s [%s]: ", label, defaultValue)
	}

	fmt.Print(prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue, nil
	}

	return input, nil
}

func promptYesNo(reader *bufio.Reader, label string, defaultYes bool) (bool, error) {
	option := "y/N"
	if defaultYes {
		option = "Y/n"
	}

	for {
		fmt.Printf("%s [%s]: ", label, option)
		input, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		input = strings.ToLower(strings.TrimSpace(input))
		if input == "" {
			return defaultYes, nil
		}
		if input == "y" || input == "yes" {
			return true, nil
		}
		if input == "n" || input == "no" {
			return false, nil
		}
		fmt.Println("Please enter y or n.")
	}
}

func promptChoice(reader *bufio.Reader, label string, choices []string, defaultValue string) (string, error) {
	options := strings.Join(choices, "/")
	for {
		fmt.Printf("%s [%s] (%s): ", label, defaultValue, options)
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		input = strings.ToLower(strings.TrimSpace(input))
		if input == "" {
			return defaultValue, nil
		}
		for _, choice := range choices {
			if input == strings.ToLower(choice) {
				return choice, nil
			}
		}
		fmt.Println("Invalid choice. Try again.")
	}
}

func promptInt(reader *bufio.Reader, label string, defaultValue int, minValue int, maxValue int) (int, error) {
	for {
		fmt.Printf("%s [%d]: ", label, defaultValue)
		input, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return defaultValue, nil
		}
		value, err := strconv.Atoi(input)
		if err != nil {
			fmt.Println("Please enter a number.")
			continue
		}
		if value < minValue || value > maxValue {
			printWarn(fmt.Sprintf("Value must be between %d and %d", minValue, maxValue))
			continue
		}
		return value, nil
	}
}

func promptPassword(reader *bufio.Reader, label string) (string, error) {
	for {
		fmt.Printf("%s: ", label)
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		input = strings.TrimSpace(input)
		if input == "" {
			fmt.Println("Password cannot be empty.")
			continue
		}
		if !isStrongPassword(input) {
			printWarn("Password must be at least 12 chars and include upper, lower, digit, and symbol")
			continue
		}
		return input, nil
	}
}

func isStrongPassword(password string) bool {
	if len(password) < 12 {
		return false
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

func writeConfigFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func printSetupUsage(out io.Writer) {
	fmt.Fprintln(out, "nginx-defender setup [options]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "  -config            Path to write the config file (default: config.yaml)")
	fmt.Fprintln(out, "  -force             Overwrite config file if it exists")
	fmt.Fprintln(out, "  -non-interactive   Use defaults without prompting")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Examples:")
	fmt.Fprintln(out, "  nginx-defender setup")
	fmt.Fprintln(out, "  nginx-defender setup -config /etc/nginx-defender/config.yaml -force")
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			return true
		}
	}
	return false
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	var entries []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	return entries
}

func expandPath(value string) string {
	if strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return value
		}
		return filepath.Join(home, strings.TrimPrefix(value, "~/"))
	}
	return value
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func printSetupBanner() {
	fmt.Print(colorize(ansiBlue, setupBanner))
	printBannerLine("NGINX DEFENDER SETUP WIZARD", ansiBold+ansiGreen)
	printBannerLine("High-speed onboarding for the WAF + threat engine", ansiCyan)
	printBannerLine("", "")
	printSection("Quick flow")
	fmt.Println("  1. Choose where the config should live")
	fmt.Println("  2. Pick your log source, firewall backend, and protection mode")
	fmt.Println("  3. Save a ready-to-run config and launch the service")
	fmt.Println()
}

func printBannerLine(text, color string) {
	fmt.Println(colorize(color, text))
}

func printSection(title string) {
	fmt.Printf("%s\n", colorize(ansiBold+ansiBlue, fmt.Sprintf("[%s]", title)))
}

func printInfo(message string) {
	fmt.Printf("%s %s\n", colorize(ansiCyan, "[i]"), message)
}

func printSuccess(message string) {
	fmt.Printf("%s %s\n", colorize(ansiGreen, "[ok]"), message)
}

func printWarn(message string) {
	fmt.Printf("%s %s\n", colorize(ansiYellow, "[!]"), message)
}

func colorize(color, text string) string {
	if color == "" {
		return text
	}
	return color + text + ansiReset
}
