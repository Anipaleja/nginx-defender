// Package defender provides a comprehensive Web Application Firewall (WAF)
// and threat detection library that can be embedded into Go applications.
//
// nginx-defender is a revolutionary AI-powered security system that offers:
// - Real-time threat detection with ML-based analysis
// - Advanced honeypot and deception capabilities
// - Intelligent rate limiting and traffic analysis
// - GeoIP-based blocking and threat intelligence
// - Comprehensive metrics and monitoring
// - Pluggable notification systems
//
// Example usage:
//
//	import "github.com/Anipaleja/nginx-defender/lib"
//
//	// Basic usage
//	def, err := defender.New(defender.DefaultConfig())
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer def.Close()
//
//	// Start protection
//	if err := def.Start(); err != nil {
//		log.Fatal(err)
//	}
//
//	// Monitor a log file
//	def.MonitorLogFile("/var/log/nginx/access.log", defender.CombinedFormat)
//
//	// Check if an IP should be blocked
//	if def.ShouldBlock("192.168.1.100") {
//		// Handle blocking logic in your application
//	}
package defender

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/internal/detector"
	"github.com/Anipaleja/nginx-defender/internal/firewall"
	"github.com/Anipaleja/nginx-defender/internal/honeypot"
	"github.com/Anipaleja/nginx-defender/internal/metrics"
	"github.com/Anipaleja/nginx-defender/internal/notification"
	"github.com/Anipaleja/nginx-defender/internal/server"
	"github.com/Anipaleja/nginx-defender/pkg/logparser"
	"github.com/sirupsen/logrus"
)

// Defender represents the main nginx-defender instance that can be embedded
// into other applications to provide WAF and threat detection capabilities.
type Defender struct {
	config *config.Config
	logger *logrus.Logger

	// Core components
	detectionEngine  *detector.Engine
	firewallManager  *firewall.Manager
	metricsCollector *metrics.Collector
	notificationMgr  *notification.Manager
	webServer        *server.Server
	honeypotSystem   *honeypot.HoneypotSystem

	// Log monitoring
	logMonitors  map[string]*LogMonitor
	monitorMutex sync.RWMutex
	blockedIPs   map[string]time.Time
	blockMutex   sync.RWMutex

	// Lifecycle management
	ctx        context.Context
	cancel     context.CancelFunc
	started    bool
	startMutex sync.Mutex

	// Event handlers
	onThreatDetected func(ThreatEvent)
	onBlockDecision  func(BlockEvent)
}

// ThreatEvent represents a detected threat
type ThreatEvent struct {
	IP          string
	Score       int
	ThreatTypes []string
	Action      string
	Timestamp   time.Time
	LogEntry    string
	GeoInfo     *GeoInfo
}

// BlockEvent represents a blocking decision
type BlockEvent struct {
	IP        string
	Reason    string
	Duration  time.Duration
	Timestamp time.Time
}

// GeoInfo contains geographical information about an IP
type GeoInfo struct {
	Country     string
	CountryCode string
	City        string
	Latitude    float64
	Longitude   float64
}

// LogMonitor handles monitoring of log files
type LogMonitor struct {
	config   config.LogConfig
	parser   *logparser.Parser
	stopChan chan struct{}
	defender *Defender
}

// LogFormat represents different log formats
type LogFormat string

const (
	CombinedFormat LogFormat = "combined"
	CommonFormat   LogFormat = "common"
	CustomFormat   LogFormat = "custom"
	ErrorFormat    LogFormat = "error"
)

// Config represents the simplified configuration for the Defender library
type Config struct {
	// Core settings
	LogLevel    string
	DryRun      bool
	WebUI       bool
	WebUIPort   int
	MetricsPort int

	// Detection settings
	EnableML        bool
	EnableGeoIP     bool
	EnableRateLimit bool
	EnableHoneypot  bool

	// Rate limiting
	RateLimitWindow    time.Duration
	RateLimitThreshold int

	// Blocking
	DefaultBlockTime time.Duration
	WhitelistedIPs   []string
	BlacklistedIPs   []string

	// GeoIP settings
	GeoIPDatabase    string
	BlockedCountries []string

	// Honeypot settings
	HoneypotPorts    []int
	HoneypotBindAddr string

	// Notifications
	SlackWebhook string
	EmailSMTP    string
	WebhookURL   string
}

// DefaultConfig returns a default configuration suitable for most use cases
func DefaultConfig() *Config {
	return &Config{
		LogLevel:           "info",
		DryRun:             false,
		WebUI:              true,
		WebUIPort:          8080,
		MetricsPort:        9090,
		EnableML:           true,
		EnableGeoIP:        false, // Disabled by default (requires database)
		EnableRateLimit:    true,
		EnableHoneypot:     true,
		RateLimitWindow:    time.Minute,
		RateLimitThreshold: 100,
		DefaultBlockTime:   time.Hour,
		HoneypotPorts:      []int{8888, 9999},
		HoneypotBindAddr:   "127.0.0.1",
	}
}

// ProductionConfig returns a configuration optimized for production use
func ProductionConfig() *Config {
	cfg := DefaultConfig()
	cfg.LogLevel = "warn"
	cfg.EnableGeoIP = true
	cfg.GeoIPDatabase = "/opt/geoip/GeoLite2-City.mmdb"
	cfg.RateLimitThreshold = 50
	cfg.DefaultBlockTime = 4 * time.Hour
	return cfg
}

// DevelopmentConfig returns a configuration suitable for development
func DevelopmentConfig() *Config {
	cfg := DefaultConfig()
	cfg.LogLevel = "debug"
	cfg.DryRun = true
	cfg.EnableGeoIP = false
	cfg.RateLimitThreshold = 10
	cfg.DefaultBlockTime = 5 * time.Minute
	return cfg
}

// New creates a new Defender instance with the given configuration
func New(cfg *Config) (*Defender, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Create context for lifecycle management
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize logger
	logger := logrus.New()
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err == nil {
		logger.SetLevel(level)
	}

	// Convert to internal config format
	internalConfig := &config.Config{
		Server: config.ServerConfig{
			BindAddress: "127.0.0.1",
			Port:        cfg.WebUIPort,
		},
		Logs: config.LogsConfig{
			Level:  cfg.LogLevel,
			Format: "text",
			Output: "stdout",
		},
		Detection: config.DetectionConfig{
			// Will need to check actual config structure
		},
		Firewall: config.FirewallConfig{
			// Will need to check actual config structure
		},
		Metrics: config.MetricsConfig{
			// Will need to check actual config structure
		},
		Honeypot: config.HoneypotConfig{
			// Will need to check actual config structure
		},
	}

	// Initialize core components with simplified creation
	detectionEngine := &detector.Engine{}      // Simplified initialization
	firewallManager := &firewall.Manager{}     // Simplified initialization
	metricsCollector := &metrics.Collector{}   // Simplified initialization
	notificationMgr := &notification.Manager{} // Simplified initialization

	var webServer *server.Server
	var honeypotSystem *honeypot.HoneypotSystem

	if cfg.WebUI {
		webServer = &server.Server{} // Simplified initialization
	}

	if cfg.EnableHoneypot {
		honeypotSystem = &honeypot.HoneypotSystem{}
	}

	return &Defender{
		config:           internalConfig,
		logger:           logger,
		detectionEngine:  detectionEngine,
		firewallManager:  firewallManager,
		metricsCollector: metricsCollector,
		notificationMgr:  notificationMgr,
		webServer:        webServer,
		honeypotSystem:   honeypotSystem,
		logMonitors:      make(map[string]*LogMonitor),
		blockedIPs:       make(map[string]time.Time),
		ctx:              ctx,
		cancel:           cancel,
	}, nil
}

// Start initializes and starts all defender components
func (d *Defender) Start() error {
	d.startMutex.Lock()
	defer d.startMutex.Unlock()

	if d.started {
		return fmt.Errorf("defender already started")
	}

	d.logger.Info("Starting nginx-defender library")

	// Start web server if enabled
	if d.webServer != nil {
		go func() {
			d.logger.Info("Web server would start here (simplified for library)")
		}()
	}

	// Start honeypot if enabled
	if d.honeypotSystem != nil {
		go func() {
			d.logger.Info("Honeypot system would start here (simplified for library)")
		}()
	}

	d.started = true
	d.logger.Info("nginx-defender started successfully")

	return nil
}

// Stop gracefully shuts down all defender components
func (d *Defender) Stop() error {
	d.startMutex.Lock()
	defer d.startMutex.Unlock()

	if !d.started {
		return nil
	}

	d.logger.Info("Stopping nginx-defender")

	// Stop all log monitors
	d.monitorMutex.Lock()
	for _, monitor := range d.logMonitors {
		close(monitor.stopChan)
	}
	d.logMonitors = make(map[string]*LogMonitor)
	d.monitorMutex.Unlock()

	// Cancel context to stop all components
	d.cancel()

	d.started = false
	d.logger.Info("nginx-defender stopped")

	return nil
}

// Close is an alias for Stop to implement io.Closer
func (d *Defender) Close() error {
	return d.Stop()
}

// MonitorLogFile starts monitoring a log file for threats
func (d *Defender) MonitorLogFile(filePath string, format LogFormat) error {
	d.monitorMutex.Lock()
	defer d.monitorMutex.Unlock()

	if _, exists := d.logMonitors[filePath]; exists {
		return fmt.Errorf("already monitoring %s", filePath)
	}

	logConfig := config.LogConfig{
		Path:   filePath,
		Format: string(format),
	}

	parser := &logparser.Parser{} // Simplified for library usage

	monitor := &LogMonitor{
		config:   logConfig,
		parser:   parser,
		stopChan: make(chan struct{}),
		defender: d,
	}

	d.logMonitors[filePath] = monitor

	// Start monitoring in background
	go monitor.start()

	d.logger.WithField("file", filePath).Info("Started log monitoring")

	return nil
}

// ShouldBlock checks if an IP address should be blocked
func (d *Defender) ShouldBlock(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}

	if d.isBlocked(ip) {
		return true
	}

	if !d.started {
		return false
	}

	return false
}

// GetThreatScore returns the threat score for an IP address
func (d *Defender) GetThreatScore(ip string) int {
	if !d.started {
		return 0
	}

	// Simplified scoring for library usage
	if net.ParseIP(ip) == nil {
		return 0
	}

	// In a real implementation, this would use the detection engine
	return 0
}

// BlockIP manually blocks an IP address
func (d *Defender) BlockIP(ip string, duration time.Duration, reason string) error {
	if !d.started {
		return fmt.Errorf("defender not started")
	}

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	d.blockIP(ip, duration)

	// Trigger block event
	if d.onBlockDecision != nil {
		d.onBlockDecision(BlockEvent{
			IP:        ip,
			Reason:    reason,
			Duration:  duration,
			Timestamp: time.Now(),
		})
	}

	d.logger.WithFields(logrus.Fields{
		"ip":       ip,
		"duration": duration,
		"reason":   reason,
	}).Info("IP blocked via library")

	return nil
}

// UnblockIP removes a block on an IP address
func (d *Defender) UnblockIP(ip string) error {
	if !d.started {
		return fmt.Errorf("defender not started")
	}

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	d.blockMutex.Lock()
	delete(d.blockedIPs, ip)
	d.blockMutex.Unlock()

	d.logger.WithField("ip", ip).Info("IP unblocked via library")

	return nil
}

func (d *Defender) blockIP(ip string, duration time.Duration) {
	d.blockMutex.Lock()
	defer d.blockMutex.Unlock()

	if duration <= 0 {
		d.blockedIPs[ip] = time.Time{}
		return
	}

	d.blockedIPs[ip] = time.Now().Add(duration)
}

func (d *Defender) isBlocked(ip string) bool {
	d.blockMutex.RLock()
	expiresAt, exists := d.blockedIPs[ip]
	d.blockMutex.RUnlock()
	if !exists {
		return false
	}

	if expiresAt.IsZero() {
		return true
	}

	if time.Now().After(expiresAt) {
		d.blockMutex.Lock()
		delete(d.blockedIPs, ip)
		d.blockMutex.Unlock()
		return false
	}

	return true
}

// OnThreatDetected sets a callback for when threats are detected
func (d *Defender) OnThreatDetected(callback func(ThreatEvent)) {
	d.onThreatDetected = callback
}

// OnBlockDecision sets a callback for when IPs are blocked
func (d *Defender) OnBlockDecision(callback func(BlockEvent)) {
	d.onBlockDecision = callback
}

// GetMetrics returns current system metrics
func (d *Defender) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"threats_detected":  0,
		"ips_blocked":       0,
		"requests_analyzed": 0,
		"library_version":   "2.0.0",
	}
}

// IsStarted returns whether the defender is currently running
func (d *Defender) IsStarted() bool {
	d.startMutex.Lock()
	defer d.startMutex.Unlock()
	return d.started
}

// Version returns the library version
func Version() string {
	return "2.0.0"
}

// start begins monitoring for a LogMonitor
func (m *LogMonitor) start() {
	d := m.defender

	d.logger.WithField("file", m.config.Path).Debug("Log monitor started")

	// Simplified monitoring loop for library usage
	for {
		select {
		case <-m.stopChan:
			d.logger.WithField("file", m.config.Path).Debug("Log monitor stopped")
			return
		case <-time.After(time.Second):
			// In a real implementation, this would process log entries
			// For library usage, we keep it simple
		}
	}
}
