package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/internal/detector"
	"github.com/Anipaleja/nginx-defender/internal/firewall"
	"github.com/Anipaleja/nginx-defender/internal/metrics"
	"github.com/Anipaleja/nginx-defender/internal/notification"
	"github.com/Anipaleja/nginx-defender/internal/server"
	"github.com/Anipaleja/nginx-defender/pkg/logparser"
	"github.com/sirupsen/logrus"
)

var (
	version   = "v2.0.0"
	buildTime = "unknown"
	gitHash   = "unknown"
)

// Application represents the main application
type Application struct {
	config          *config.Config
	logger          *logrus.Logger
	
	// Core components
	detectionEngine   *detector.Engine
	firewallManager   *firewall.Manager
	metricsCollector  *metrics.Collector
	notificationMgr   *notification.Manager
	webServer         *server.Server
	
	// Log monitoring
	logMonitors       []*LogMonitor
	
	// Context for graceful shutdown
	ctx               context.Context
	cancel            context.CancelFunc
}

// LogMonitor monitors a log file for threats
type LogMonitor struct {
	config   config.LogConfig
	parser   *logparser.Parser
	stopChan chan struct{}
}

func main() {
	var (
		configPath   = flag.String("config", "config.yaml", "Path to configuration file")
		versionFlag  = flag.Bool("version", false, "Show version information")
		validateFlag = flag.Bool("validate", false, "Validate configuration and exit")
		debugFlag    = flag.Bool("debug", false, "Enable debug logging")
		dryRun       = flag.Bool("dry-run", false, "Run in dry-run mode (no actual blocking)")
	)
	flag.Parse()

	if *versionFlag {
		fmt.Printf("nginx-defender %s\n", version)
		fmt.Printf("Build time: %s\n", buildTime)
		fmt.Printf("Git hash: %s\n", gitHash)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	if *validateFlag {
		fmt.Println("Configuration is valid")
		os.Exit(0)
	}

	// Initialize logger
	logger := logrus.New()
	if *debugFlag {
		logger.SetLevel(logrus.DebugLevel)
		cfg.Logs.Level = "debug"
	}
	
	// Set log level from config
	level, err := logrus.ParseLevel(cfg.Logs.Level)
	if err == nil {
		logger.SetLevel(level)
	}
	
	// Set log format
	if cfg.Logs.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	logger.Infof("Starting nginx-defender %s (build: %s, commit: %s)", version, buildTime, gitHash)

	// Create main application
	app, err := NewApplication(cfg, logger, *dryRun)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create application")
	}

	// Start the application
	if err := app.Start(); err != nil {
		logger.WithError(err).Fatal("Failed to start application")
	}

	// Wait for shutdown signal
	app.WaitForShutdown()

	// Graceful shutdown
	if err := app.Shutdown(); err != nil {
		logger.WithError(err).Error("Error during shutdown")
		os.Exit(1)
	}

	logger.Info("nginx-defender stopped")
}

// NewApplication creates a new application instance
func NewApplication(cfg *config.Config, logger *logrus.Logger, dryRun bool) (*Application, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	app := &Application{
		config: cfg,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize metrics collector
	metricsCollector := metrics.NewCollector(cfg.Metrics, logger)
	app.metricsCollector = metricsCollector

	// Initialize detection engine
	detectionEngine, err := detector.NewEngine(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create detection engine: %v", err)
	}
	app.detectionEngine = detectionEngine

	// Initialize firewall manager
	var firewallManager *firewall.Manager
	if !dryRun {
		firewallManager, err = firewall.NewManager(cfg.Firewall, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create firewall manager: %v", err)
		}
	} else {
		// Use mock backend for dry run
		mockConfig := cfg.Firewall
		mockConfig.Backend = "mock"
		firewallManager, err = firewall.NewManager(mockConfig, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create mock firewall manager: %v", err)
		}
		logger.Info("Running in dry-run mode - using mock firewall backend")
	}
	app.firewallManager = firewallManager

	// Initialize notification manager
	notificationMgr, err := notification.NewManager(cfg.Notifications, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create notification manager: %v", err)
	}
	app.notificationMgr = notificationMgr

	// Initialize web server
	webServer := server.NewServer(cfg.Server, logger)
	webServer.SetComponents(detectionEngine, firewallManager, metricsCollector)
	app.webServer = webServer

	// Initialize log monitors
	if err := app.initializeLogMonitors(); err != nil {
		return nil, fmt.Errorf("failed to initialize log monitors: %v", err)
	}

	return app, nil
}

// initializeLogMonitors initializes log file monitors
func (app *Application) initializeLogMonitors() error {
	// Monitor nginx logs
	for _, logConfig := range app.config.Monitoring.NginxLogs {
		monitor, err := app.createLogMonitor(logConfig, "nginx_combined")
		if err != nil {
			return fmt.Errorf("failed to create nginx log monitor: %v", err)
		}
		app.logMonitors = append(app.logMonitors, monitor)
	}

	// Monitor apache logs
	for _, logConfig := range app.config.Monitoring.ApacheLogs {
		monitor, err := app.createLogMonitor(logConfig, "apache_combined")
		if err != nil {
			return fmt.Errorf("failed to create apache log monitor: %v", err)
		}
		app.logMonitors = append(app.logMonitors, monitor)
	}

	return nil
}

// createLogMonitor creates a log monitor for a specific log file
func (app *Application) createLogMonitor(logConfig config.LogConfig, defaultFormat string) (*LogMonitor, error) {
	format := logConfig.Format
	if format == "" {
		format = defaultFormat
	}

	parser := logparser.NewParser(format)
	
	monitor := &LogMonitor{
		config:   logConfig,
		parser:   parser,
		stopChan: make(chan struct{}),
	}

	return monitor, nil
}

// Start starts all application components
func (app *Application) Start() error {
	app.logger.Info("Starting application components...")

	// Start log monitors
	for i, monitor := range app.logMonitors {
		go app.runLogMonitor(i, monitor)
		app.logger.Infof("Started log monitor for: %s", monitor.config.Path)
	}

	// Start web server
	go func() {
		if err := app.webServer.Start(); err != nil {
			app.logger.WithError(err).Error("Web server failed")
		}
	}()

	app.logger.Info("All components started successfully")
	return nil
}

// runLogMonitor runs a log monitor
func (app *Application) runLogMonitor(id int, monitor *LogMonitor) {
	app.logger.Infof("Starting log monitor %d for file: %s", id, monitor.config.Path)
	
	// This is a simplified implementation
	// In reality, you'd use file tailing libraries like fsnotify
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-monitor.stopChan:
			app.logger.Infof("Stopping log monitor %d", id)
			return
		case <-ticker.C:
			// Check for new log entries (simplified)
			// In reality, you'd tail the file and process new lines
			app.processLogFile(monitor)
		}
	}
}

// processLogFile processes a log file for threats
func (app *Application) processLogFile(monitor *LogMonitor) {
	// This is a placeholder implementation
	// In reality, you'd read new lines from the log file and process them
	
	// Example log entry processing
	sampleEntry := &logparser.LogEntry{
		IP:           "192.168.1.100",
		Timestamp:    time.Now(),
		Method:       "GET",
		Path:         "/admin/login",
		ResponseCode: 404,
		UserAgent:    "curl/7.68.0",
	}
	
	// Analyze the entry
	result := app.detectionEngine.AnalyzeLogEntry(sampleEntry)
	
	// Record metrics
	app.metricsCollector.RecordRequest(
		sampleEntry.Method,
		fmt.Sprintf("%d", sampleEntry.ResponseCode),
		"US", // Would be determined by GeoIP
		100*time.Millisecond,
	)
	
	// Handle threats
	if len(result.ThreatTypes) > 0 {
		app.handleThreatDetection(result)
	}
}

// handleThreatDetection handles a detected threat
func (app *Application) handleThreatDetection(result *detector.DetectionResult) {
	app.logger.WithFields(logrus.Fields{
		"ip":            result.IP,
		"threat_types":  result.ThreatTypes,
		"score":         result.Score,
		"action":        result.RecommendedAction,
	}).Warn("Threat detected")

	// Record threat metrics
	threatLevel := app.getThreatLevelString(result.ThreatLevel)
	for _, threatType := range result.ThreatTypes {
		app.metricsCollector.RecordThreat(
			threatType,
			threatLevel,
			result.RecommendedAction,
			result.Score,
			"", // Country would be determined
		)
	}

	// Take action based on recommendation
	switch result.RecommendedAction {
	case "BLOCK_IMMEDIATE", "BLOCK":
		duration := 1 * time.Hour
		if result.ThreatLevel == detector.ThreatLevelCritical {
			duration = 24 * time.Hour
		}
		
		err := app.firewallManager.BlockIP(
			result.IP,
			firewall.ActionBlock,
			duration,
			fmt.Sprintf("Threat detected: %v", result.ThreatTypes),
			map[string]string{
				"score":       fmt.Sprintf("%.2f", result.Score),
				"threat_types": fmt.Sprintf("%v", result.ThreatTypes),
			},
		)
		
		if err != nil {
			app.logger.WithError(err).Errorf("Failed to block IP %s", result.IP)
		} else {
			// Record blocked IP
			app.metricsCollector.RecordIPBlocked(
				fmt.Sprintf("threat:%v", result.ThreatTypes),
				"BLOCK",
				"", // Country
			)
			
			// Send notification
			app.notificationMgr.SendIPBlocked(
				result.IP,
				fmt.Sprintf("Threat detected: %v", result.ThreatTypes),
				"BLOCK",
				duration,
				nil, // Location info
			)
		}

	case "TARPIT":
		duration := 2 * time.Hour
		err := app.firewallManager.BlockIP(
			result.IP,
			firewall.ActionTarpit,
			duration,
			fmt.Sprintf("AI scraper detected: %v", result.ThreatTypes),
			nil,
		)
		
		if err != nil {
			app.logger.WithError(err).Errorf("Failed to tarpit IP %s", result.IP)
		}

	case "RATE_LIMIT":
		// Implement rate limiting logic
		app.logger.Infof("Rate limiting recommended for IP %s", result.IP)
	}

	// Broadcast update to web clients
	app.webServer.BroadcastUpdate("threat_detected", map[string]interface{}{
		"ip":            result.IP,
		"threat_types":  result.ThreatTypes,
		"score":         result.Score,
		"action":        result.RecommendedAction,
		"timestamp":     result.Timestamp,
	})
}

// getThreatLevelString converts threat level to string
func (app *Application) getThreatLevelString(level detector.ThreatLevel) string {
	switch level {
	case detector.ThreatLevelLow:
		return "low"
	case detector.ThreatLevelMedium:
		return "medium"
	case detector.ThreatLevelHigh:
		return "high"
	case detector.ThreatLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// WaitForShutdown waits for shutdown signals
func (app *Application) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	select {
	case sig := <-sigChan:
		app.logger.Infof("Received signal: %v", sig)
	case <-app.ctx.Done():
		app.logger.Info("Context cancelled")
	}
}

// Shutdown gracefully shuts down the application
func (app *Application) Shutdown() error {
	app.logger.Info("Starting graceful shutdown...")
	
	// Cancel context
	app.cancel()
	
	// Stop log monitors
	for _, monitor := range app.logMonitors {
		close(monitor.stopChan)
	}
	
	// Shutdown web server
	if err := app.webServer.Shutdown(); err != nil {
		app.logger.WithError(err).Error("Error shutting down web server")
	}
	
	// Shutdown firewall manager
	if err := app.firewallManager.Shutdown(); err != nil {
		app.logger.WithError(err).Error("Error shutting down firewall manager")
	}
	
	// Shutdown notification manager
	app.notificationMgr.Shutdown()
	
	app.logger.Info("Graceful shutdown completed")
	return nil
}
