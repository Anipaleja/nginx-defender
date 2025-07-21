package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/internal/detector"
	"github.com/Anipaleja/nginx-defender/internal/firewall"
	"github.com/Anipaleja/nginx-defender/internal/metrics"
	"github.com/Anipaleja/nginx-defender/internal/notification"
	"github.com/Anipaleja/nginx-defender/internal/server"
	"github.com/sirupsen/logrus"
)

var (
	version   = "v2.0.0"
	buildTime = "unknown"
	gitHash   = "unknown"
)

func main() {
	var (
		configPath = flag.String("config", "config.yaml", "Path to configuration file")
		versionFlag = flag.Bool("version", false, "Show version information")
		validateFlag = flag.Bool("validate", false, "Validate configuration and exit")
		debugFlag = flag.Bool("debug", false, "Enable debug logging")
		dryRun = flag.Bool("dry-run", false, "Run in dry-run mode (no actual blocking)")
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

	// Setup logging
	setupLogging(cfg, *debugFlag)
	
	logrus.WithFields(logrus.Fields{
		"version": version,
		"config":  *configPath,
		"dry_run": *dryRun,
	}).Info("Starting nginx-defender")

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize components
	fw, err := firewall.New(cfg.Firewall, *dryRun)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize firewall")
	}

	notifier := notification.New(cfg.Notifications)
	metricsCollector := metrics.New(cfg.Metrics)
	
	det, err := detector.New(cfg.Detection, fw, notifier, metricsCollector)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to initialize detector")
	}

	// Start web server
	webServer := server.New(cfg.Server, det, fw, metricsCollector)
	go func() {
		if err := webServer.Start(ctx); err != nil {
			logrus.WithError(err).Error("Web server error")
		}
	}()

	// Start metrics server if enabled
	if cfg.Metrics.Prometheus.Enabled {
		go func() {
			if err := metricsCollector.StartPrometheusServer(ctx); err != nil {
				logrus.WithError(err).Error("Metrics server error")
			}
		}()
	}

	// Start log monitoring
	go func() {
		if err := det.Start(ctx); err != nil {
			logrus.WithError(err).Error("Detector error")
			cancel()
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		logrus.WithField("signal", sig).Info("Received shutdown signal")
	case <-ctx.Done():
		logrus.Info("Context cancelled")
	}

	// Graceful shutdown
	logrus.Info("Shutting down nginx-defender...")
	
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := webServer.Shutdown(shutdownCtx); err != nil {
		logrus.WithError(err).Error("Error shutting down web server")
	}

	if err := det.Stop(shutdownCtx); err != nil {
		logrus.WithError(err).Error("Error shutting down detector")
	}

	logrus.Info("nginx-defender stopped")
}

func setupLogging(cfg *config.Config, debug bool) {
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		switch cfg.Logs.Level {
		case "debug":
			logrus.SetLevel(logrus.DebugLevel)
		case "info":
			logrus.SetLevel(logrus.InfoLevel)
		case "warn":
			logrus.SetLevel(logrus.WarnLevel)
		case "error":
			logrus.SetLevel(logrus.ErrorLevel)
		default:
			logrus.SetLevel(logrus.InfoLevel)
		}
	}

	if cfg.Logs.Format == "json" {
		logrus.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	}

	if cfg.Logs.Output == "file" {
		// Ensure log directory exists
		if err := os.MkdirAll(filepath.Dir(cfg.Logs.FilePath), 0755); err != nil {
			logrus.WithError(err).Fatal("Failed to create log directory")
		}
		
		file, err := os.OpenFile(cfg.Logs.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logrus.WithError(err).Fatal("Failed to open log file")
		}
		logrus.SetOutput(file)
	}
}
