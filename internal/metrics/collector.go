package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Collector collects and exposes metrics
type Collector struct {
	config config.MetricsConfig
	logger *logrus.Logger
	
	// Prometheus metrics
	registry *prometheus.Registry
	
	// Request metrics
	totalRequests     *prometheus.CounterVec
	threatsDetected   *prometheus.CounterVec
	ipsBLocked        *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	
	// Threat metrics
	threatScore       *prometheus.HistogramVec
	threatsByType     *prometheus.CounterVec
	threatsByCountry  *prometheus.CounterVec
	
	// System metrics
	activeConnections prometheus.Gauge
	memoryUsage      prometheus.Gauge
	cpuUsage         prometheus.Gauge
	
	// Firewall metrics
	firewallRules    prometheus.Gauge
	blockedRequests  *prometheus.CounterVec
	
	// ML metrics
	mlPredictions    *prometheus.CounterVec
	mlModelAccuracy  prometheus.Gauge
	
	// Internal stats
	stats map[string]interface{}
	mutex sync.RWMutex
}

// NewCollector creates a new metrics collector
func NewCollector(cfg config.MetricsConfig, logger *logrus.Logger) *Collector {
	registry := prometheus.NewRegistry()
	
	collector := &Collector{
		config:   cfg,
		logger:   logger,
		registry: registry,
		stats:    make(map[string]interface{}),
	}
	
	collector.initializeMetrics()
	collector.registerMetrics()
	
	// Start background collection
	if cfg.ExportInterval > 0 {
		go collector.backgroundCollection()
	}
	
	return collector
}

// initializeMetrics initializes all Prometheus metrics
func (c *Collector) initializeMetrics() {
	// Request metrics
	c.totalRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nginx_defender_requests_total",
			Help: "Total number of requests processed",
		},
		[]string{"method", "status", "country"},
	)
	
	c.threatsDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nginx_defender_threats_detected_total",
			Help: "Total number of threats detected",
		},
		[]string{"threat_type", "threat_level", "action"},
	)
	
	c.ipsBLocked = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nginx_defender_ips_blocked_total",
			Help: "Total number of IPs blocked",
		},
		[]string{"reason", "action", "country"},
	)
	
	c.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "nginx_defender_request_duration_seconds",
			Help:    "Request processing duration in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"component"},
	)
	
	// Threat metrics
	c.threatScore = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "nginx_defender_threat_score",
			Help:    "Distribution of threat scores",
			Buckets: []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		},
		[]string{"threat_type"},
	)
	
	c.threatsByType = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nginx_defender_threats_by_type_total",
			Help: "Total threats detected by type",
		},
		[]string{"type"},
	)
	
	c.threatsByCountry = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nginx_defender_threats_by_country_total",
			Help: "Total threats detected by country",
		},
		[]string{"country"},
	)
	
	// System metrics
	c.activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "nginx_defender_active_connections",
			Help: "Number of active connections",
		},
	)
	
	c.memoryUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "nginx_defender_memory_usage_bytes",
			Help: "Memory usage in bytes",
		},
	)
	
	c.cpuUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "nginx_defender_cpu_usage_percent",
			Help: "CPU usage percentage",
		},
	)
	
	// Firewall metrics
	c.firewallRules = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "nginx_defender_firewall_rules",
			Help: "Number of active firewall rules",
		},
	)
	
	c.blockedRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nginx_defender_blocked_requests_total",
			Help: "Total number of blocked requests",
		},
		[]string{"action", "reason"},
	)
	
	// ML metrics
	c.mlPredictions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nginx_defender_ml_predictions_total",
			Help: "Total ML predictions made",
		},
		[]string{"prediction", "confidence_range"},
	)
	
	c.mlModelAccuracy = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "nginx_defender_ml_model_accuracy",
			Help: "Current ML model accuracy",
		},
	)
}

// registerMetrics registers all metrics with the registry
func (c *Collector) registerMetrics() {
	c.registry.MustRegister(c.totalRequests)
	c.registry.MustRegister(c.threatsDetected)
	c.registry.MustRegister(c.ipsBLocked)
	c.registry.MustRegister(c.requestDuration)
	c.registry.MustRegister(c.threatScore)
	c.registry.MustRegister(c.threatsByType)
	c.registry.MustRegister(c.threatsByCountry)
	c.registry.MustRegister(c.activeConnections)
	c.registry.MustRegister(c.memoryUsage)
	c.registry.MustRegister(c.cpuUsage)
	c.registry.MustRegister(c.firewallRules)
	c.registry.MustRegister(c.blockedRequests)
	c.registry.MustRegister(c.mlPredictions)
	c.registry.MustRegister(c.mlModelAccuracy)
}

// Record methods for different types of events
func (c *Collector) RecordRequest(method, status, country string, duration time.Duration) {
	c.totalRequests.WithLabelValues(method, status, country).Inc()
	c.requestDuration.WithLabelValues("request_processing").Observe(duration.Seconds())
}

func (c *Collector) RecordThreat(threatType, threatLevel, action string, score float64, country string) {
	c.threatsDetected.WithLabelValues(threatType, threatLevel, action).Inc()
	c.threatScore.WithLabelValues(threatType).Observe(score)
	c.threatsByType.WithLabelValues(threatType).Inc()
	if country != "" {
		c.threatsByCountry.WithLabelValues(country).Inc()
	}
}

func (c *Collector) RecordIPBlocked(reason, action, country string) {
	c.ipsBLocked.WithLabelValues(reason, action, country).Inc()
	c.blockedRequests.WithLabelValues(action, reason).Inc()
}

func (c *Collector) RecordMLPrediction(prediction string, confidence float64) {
	confidenceRange := c.getConfidenceRange(confidence)
	c.mlPredictions.WithLabelValues(prediction, confidenceRange).Inc()
}

func (c *Collector) UpdateFirewallRules(count float64) {
	c.firewallRules.Set(count)
}

func (c *Collector) UpdateSystemMetrics(activeConns, memoryUsage, cpuUsage float64) {
	c.activeConnections.Set(activeConns)
	c.memoryUsage.Set(memoryUsage)
	c.cpuUsage.Set(cpuUsage)
}

func (c *Collector) UpdateMLAccuracy(accuracy float64) {
	c.mlModelAccuracy.Set(accuracy)
}

// getConfidenceRange converts confidence score to range
func (c *Collector) getConfidenceRange(confidence float64) string {
	switch {
	case confidence >= 0.9:
		return "high"
	case confidence >= 0.7:
		return "medium"
	case confidence >= 0.5:
		return "low"
	default:
		return "very_low"
	}
}

// GetStats returns current statistics
func (c *Collector) GetStats() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	// Create a copy of stats
	stats := make(map[string]interface{})
	for k, v := range c.stats {
		stats[k] = v
	}
	
	return stats
}

// UpdateStats updates internal statistics
func (c *Collector) UpdateStats(key string, value interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.stats[key] = value
}

// Handler returns the Prometheus metrics handler
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// backgroundCollection runs background metric collection
func (c *Collector) backgroundCollection() {
	ticker := time.NewTicker(time.Duration(c.config.ExportInterval) * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		c.collectSystemMetrics()
	}
}

// collectSystemMetrics collects system-level metrics
func (c *Collector) collectSystemMetrics() {
	// This would collect actual system metrics
	// For now, simulate some basic metrics
	
	// Memory usage (would use actual system calls)
	memUsage := float64(100 * 1024 * 1024) // 100MB placeholder
	c.memoryUsage.Set(memUsage)
	
	// CPU usage (would use actual system calls)
	cpuUsage := 15.5 // 15.5% placeholder
	c.cpuUsage.Set(cpuUsage)
	
	// Update internal stats
	c.UpdateStats("memory_usage_mb", memUsage/1024/1024)
	c.UpdateStats("cpu_usage_percent", cpuUsage)
	c.UpdateStats("last_collection", time.Now().UTC())
}

// ExportMetrics exports metrics in various formats
func (c *Collector) ExportMetrics() (map[string]interface{}, error) {
	metrics := make(map[string]interface{})
	
	// Gather metrics from Prometheus registry
	metricFamilies, err := c.registry.Gather()
	if err != nil {
		return nil, fmt.Errorf("failed to gather metrics: %v", err)
	}
	
	// Convert to a more readable format
	for _, mf := range metricFamilies {
		name := mf.GetName()
		metrics[name] = map[string]interface{}{
			"help": mf.GetHelp(),
			"type": mf.GetType().String(),
		}
		
		// Add metric values
		metricValues := []map[string]interface{}{}
		for _, metric := range mf.GetMetric() {
			value := map[string]interface{}{}
			
			// Add labels
			if len(metric.GetLabel()) > 0 {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				value["labels"] = labels
			}
			
			// Add value based on metric type
			switch mf.GetType() {
			case 0: // COUNTER
				value["value"] = metric.GetCounter().GetValue()
			case 1: // GAUGE
				value["value"] = metric.GetGauge().GetValue()
			case 4: // HISTOGRAM
				hist := metric.GetHistogram()
				value["count"] = hist.GetSampleCount()
				value["sum"] = hist.GetSampleSum()
				buckets := make([]map[string]interface{}, 0)
				for _, bucket := range hist.GetBucket() {
					buckets = append(buckets, map[string]interface{}{
						"upper_bound": bucket.GetUpperBound(),
						"count":       bucket.GetCumulativeCount(),
					})
				}
				value["buckets"] = buckets
			}
			
			metricValues = append(metricValues, value)
		}
		
		metrics[name].(map[string]interface{})["values"] = metricValues
	}
	
	return metrics, nil
}

// Reset resets all metrics (useful for testing)
func (c *Collector) Reset() {
	// Create new registry and re-register metrics
	c.registry = prometheus.NewRegistry()
	c.initializeMetrics()
	c.registerMetrics()
	
	// Clear internal stats
	c.mutex.Lock()
	c.stats = make(map[string]interface{})
	c.mutex.Unlock()
	
	c.logger.Info("Metrics collector reset")
}
