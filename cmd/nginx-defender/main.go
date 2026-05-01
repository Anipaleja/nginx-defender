package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/internal/detector"
	"github.com/Anipaleja/nginx-defender/internal/firewall"
	"github.com/Anipaleja/nginx-defender/internal/metrics"
	"github.com/Anipaleja/nginx-defender/internal/notification"
	"github.com/Anipaleja/nginx-defender/internal/response"
	"github.com/Anipaleja/nginx-defender/internal/server"
	"github.com/Anipaleja/nginx-defender/pkg/logparser"
	"github.com/nxadm/tail"
	"github.com/sirupsen/logrus"
)

var (
	version   = "v2.0.0"
	buildTime = "unknown"
	gitHash   = "unknown"
)

// Application represents the main application
type Application struct {
	config *config.Config
	logger *logrus.Logger

	// Core components
	detectionEngine  *detector.Engine
	firewallManager  *firewall.Manager
	metricsCollector *metrics.Collector
	notificationMgr  *notification.Manager
	webServer        *server.Server

	// Log monitoring
	logMonitors  []*LogMonitor
	logEntryChan chan *logparser.LogEntry
	workerWG     sync.WaitGroup
	droppedLogs  uint64

	// Blocking escalation state
	offenderMutex sync.Mutex
	offenders     map[string]*offenderState

	// Context for graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// LogMonitor monitors a log file for threats
type LogMonitor struct {
	config   config.LogConfig
	parser   *logparser.Parser
	stopChan chan struct{}
}

type offenderState struct {
	Count     int
	LastBlock time.Time
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
	configureLocalPersistence(cfg, logger, dryRun)

	app := &Application{
		config:    cfg,
		logger:    logger,
		ctx:       ctx,
		cancel:    cancel,
		offenders: make(map[string]*offenderState),
	}

	bufferSize := cfg.Performance.LogBufferSize
	if bufferSize <= 0 {
		bufferSize = 10000
	}
	app.logEntryChan = make(chan *logparser.LogEntry, bufferSize)

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
	webServer := server.NewServer(cfg.Server, cfg.WebInterface, logger)
	webServer.SetComponents(detectionEngine, firewallManager, metricsCollector)
	app.webServer = webServer

	// Initialize log monitors
	if err := app.initializeLogMonitors(); err != nil {
		return nil, fmt.Errorf("failed to initialize log monitors: %v", err)
	}

	return app, nil
}

func configureLocalPersistence(cfg *config.Config, logger *logrus.Logger, dryRun bool) {
	if cfg == nil || !cfg.Firewall.Persistence.Enabled || cfg.Firewall.Persistence.RulesFile == "" {
		return
	}

	devMode := dryRun || isTrueEnv(os.Getenv("NGINX_DEFENDER_DEV_MODE"))
	if !devMode {
		return
	}

	original := cfg.Firewall.Persistence.RulesFile
	if ensureWritablePersistencePath(original) == nil {
		return
	}

	fallback := filepath.Join(os.TempDir(), "nginx-defender", "firewall_rules.json")
	if err := ensureWritablePersistencePath(fallback); err != nil {
		logger.WithError(err).Warn("Failed to prepare writable fallback persistence path in local/dev mode")
		return
	}

	cfg.Firewall.Persistence.RulesFile = fallback
	logger.WithFields(logrus.Fields{
		"original_rules_file": original,
		"fallback_rules_file": fallback,
		"dry_run":             dryRun,
	}).Info("Using writable local firewall persistence path")
}

func ensureWritablePersistencePath(rulesFile string) error {
	dir := filepath.Dir(rulesFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	probeFile := filepath.Join(dir, ".nginx-defender-write-test")
	file, err := os.OpenFile(probeFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if closeErr := file.Close(); closeErr != nil {
		return closeErr
	}

	_ = os.Remove(probeFile)
	return nil
}

func isTrueEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
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

	parser, err := logparser.NewParserWithRegex(format, logConfig.CustomRegex)
	if err != nil {
		return nil, fmt.Errorf("failed to create parser for %s: %w", logConfig.Path, err)
	}

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

	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}

	for i := 0; i < workerCount; i++ {
		app.workerWG.Add(1)
		go app.logWorker(i)
	}

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

	tailer, err := tail.TailFile(monitor.config.Path, tail.Config{
		ReOpen:    true,
		Follow:    true,
		MustExist: false,
		Poll:      true,
		Location: &tail.SeekInfo{
			Offset: 0,
			Whence: 2, // Start from EOF.
		},
	})
	if err != nil {
		app.logger.WithError(err).Errorf("Failed to start tailer for %s", monitor.config.Path)
		return
	}
	defer tailer.Cleanup()

	for {
		select {
		case <-monitor.stopChan:
			_ = tailer.Stop()
			app.logger.Infof("Stopping log monitor %d", id)
			return
		case <-app.ctx.Done():
			_ = tailer.Stop()
			app.logger.Infof("Stopping log monitor %d due to shutdown", id)
			return
		case line, ok := <-tailer.Lines:
			if !ok {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if line == nil {
				continue
			}
			if line.Err != nil {
				app.logger.WithError(line.Err).Warnf("Tailer error for %s", monitor.config.Path)
				continue
			}

			entry, parseErr := monitor.parser.ParseLine(line.Text)
			if parseErr != nil {
				app.logger.WithError(parseErr).Debugf("Failed to parse log line from %s", monitor.config.Path)
				continue
			}
			if entry == nil {
				continue
			}

			select {
			case app.logEntryChan <- entry:
			default:
				atomic.AddUint64(&app.droppedLogs, 1)
				app.logger.Warn("Log processing queue full, dropping log entry")
			}
		}
	}
}

func (app *Application) logWorker(id int) {
	defer app.workerWG.Done()

	for {
		select {
		case <-app.ctx.Done():
			return
		case entry, ok := <-app.logEntryChan:
			if !ok {
				return
			}
			app.processLogEntry(entry)
		}
	}
}

func (app *Application) processLogEntry(entry *logparser.LogEntry) {
	if entry == nil {
		return
	}

	start := time.Now()
	result := app.detectionEngine.AnalyzeLogEntry(entry)

	app.metricsCollector.RecordRequest(
		entry.Method,
		fmt.Sprintf("%d", entry.ResponseCode),
		result.Details["country"],
		time.Since(start),
	)

	if len(result.ThreatTypes) > 0 {
		app.handleThreatDetection(result)
		app.metricsCollector.RecordDecisionLatency(result.RecommendedAction, time.Since(start))
	}
}

// handleThreatDetection handles a detected threat
func (app *Application) handleThreatDetection(result *detector.DetectionResult) {
	mode := strings.ToLower(strings.TrimSpace(app.config.Detection.Mode))
	if mode == "" {
		mode = "block"
	}

	app.logger.WithFields(logrus.Fields{
		"ip":           result.IP,
		"threat_types": result.ThreatTypes,
		"score":        result.Score,
		"action":       result.RecommendedAction,
		"mode":         mode,
	}).Warn("Threat detected")

	// Record threat metrics
	threatLevel := app.getThreatLevelString(result.ThreatLevel)
	country := strings.TrimSpace(result.Details["country"])
	for _, threatType := range result.ThreatTypes {
		app.metricsCollector.RecordThreat(
			threatType,
			threatLevel,
			result.RecommendedAction,
			result.Score,
			country,
		)
	}

	primaryThreatType := "unknown"
	if len(result.ThreatTypes) > 0 {
		primaryThreatType = result.ThreatTypes[0]
	}

	decision := response.Plan(result)
	if decision.Action != "" {
		result.RecommendedAction = decision.Action
	}

	if mode == "shadow" || mode == "monitor" {
		app.logger.WithFields(logrus.Fields{
			"ip":           result.IP,
			"action":       result.RecommendedAction,
			"threat_types": result.ThreatTypes,
		}).Info("Shadow mode enabled; threat action simulated")

		app.webServer.BroadcastUpdate("threat_detected", map[string]interface{}{
			"ip":           result.IP,
			"threat_types": result.ThreatTypes,
			"score":        result.Score,
			"action":       result.RecommendedAction,
			"mode":         mode,
			"timestamp":    result.Timestamp,
			"enforced":     false,
		})
		return
	}

	// Take action based on recommendation
	switch result.RecommendedAction {
	case "BLOCK_IMMEDIATE", "BLOCK":
		duration := app.calculateBlockDuration(result.IP, result.ThreatLevel)

		err := app.firewallManager.BlockIP(
			result.IP,
			firewall.ActionBlock,
			duration,
			fmt.Sprintf("threat_type:%s", primaryThreatType),
			map[string]string{
				"score":        fmt.Sprintf("%.2f", result.Score),
				"threat_types": fmt.Sprintf("%v", result.ThreatTypes),
				"country":      country,
			},
		)

		if err != nil {
			app.logger.WithError(err).Errorf("Failed to block IP %s", result.IP)
		} else {
			// Record blocked IP
			app.metricsCollector.RecordIPBlocked(
				fmt.Sprintf("threat_type:%s", primaryThreatType),
				"BLOCK",
				country,
			)
			app.metricsCollector.UpdateFirewallRules(float64(len(app.firewallManager.GetRules())))

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
		duration := app.calculateBlockDuration(result.IP, detector.ThreatLevelHigh)
		err := app.firewallManager.BlockIP(
			result.IP,
			firewall.ActionTarpit,
			duration,
			fmt.Sprintf("threat_type:%s", primaryThreatType),
			nil,
		)

		if err != nil {
			app.logger.WithError(err).Errorf("Failed to tarpit IP %s", result.IP)
		} else {
			app.metricsCollector.RecordIPBlocked(
				fmt.Sprintf("threat_type:%s", primaryThreatType),
				"TARPIT",
				country,
			)
			app.metricsCollector.UpdateFirewallRules(float64(len(app.firewallManager.GetRules())))
		}

	case "RATE_LIMIT":
		duration := app.calculateBlockDuration(result.IP, detector.ThreatLevelMedium)
		err := app.firewallManager.BlockIP(
			result.IP,
			firewall.ActionRateLimit,
			duration,
			fmt.Sprintf("threat_type:%s", primaryThreatType),
			nil,
		)
		if err != nil {
			app.logger.WithError(err).Errorf("Failed to apply rate limit for IP %s", result.IP)
		} else {
			app.metricsCollector.RecordIPBlocked(
				fmt.Sprintf("threat_type:%s", primaryThreatType),
				"RATE_LIMIT",
				country,
			)
			app.metricsCollector.UpdateFirewallRules(float64(len(app.firewallManager.GetRules())))
		}
	}

	// Broadcast update to web clients
	app.webServer.BroadcastUpdate("threat_detected", map[string]interface{}{
		"ip":           result.IP,
		"threat_types": result.ThreatTypes,
		"score":        result.Score,
		"confidence":   result.Confidence,
		"action":       result.RecommendedAction,
		"mode":         mode,
		"enforced":     true,
		"escalated":    decision.Escalate,
		"timestamp":    result.Timestamp,
	})
}

func (app *Application) calculateBlockDuration(ip string, level detector.ThreatLevel) time.Duration {
	base := 1 * time.Hour
	if app.config.Detection.RateLimiting.BlockDuration > 0 {
		base = time.Duration(app.config.Detection.RateLimiting.BlockDuration) * time.Second
	}

	app.offenderMutex.Lock()
	defer app.offenderMutex.Unlock()

	now := time.Now()
	state, exists := app.offenders[ip]
	if !exists {
		state = &offenderState{}
		app.offenders[ip] = state
	}

	if !state.LastBlock.IsZero() && now.Sub(state.LastBlock) > 24*time.Hour {
		state.Count = 0
	}

	state.Count++
	state.LastBlock = now

	multiplier := 1 << (state.Count - 1)
	if multiplier > 16 {
		multiplier = 16
	}

	duration := base * time.Duration(multiplier)
	if level == detector.ThreatLevelCritical && duration < 24*time.Hour {
		duration = 24 * time.Hour
	}
	if duration > 7*24*time.Hour {
		duration = 7 * 24 * time.Hour
	}

	return duration
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

	app.workerWG.Wait()

	dropped := atomic.LoadUint64(&app.droppedLogs)
	if dropped > 0 {
		app.logger.WithField("dropped_logs", dropped).Warn("Dropped log entries during runtime")
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
