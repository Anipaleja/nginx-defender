package detector

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/pkg/geoip"
	"github.com/Anipaleja/nginx-defender/pkg/logparser"
	"github.com/Anipaleja/nginx-defender/pkg/patterns"
	"github.com/Anipaleja/nginx-defender/pkg/ranges"
	"github.com/sirupsen/logrus"
)

// ThreatLevel represents the severity of a detected threat
type ThreatLevel int

const (
	ThreatLevelLow ThreatLevel = iota
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

// DetectionResult represents the result of threat detection
type DetectionResult struct {
	IP             string            `json:"ip"`
	ThreatLevel    ThreatLevel       `json:"threat_level"`
	ThreatTypes    []string          `json:"threat_types"`
	Score          float64           `json:"score"`
	Details        map[string]string `json:"details"`
	Timestamp      time.Time         `json:"timestamp"`
	RecommendedAction string         `json:"recommended_action"`
}

// Engine is the main threat detection engine
type Engine struct {
	config         *config.Config
	rangeManager   *ranges.RangeManager
	geoIP          *geoip.Service
	patternMatcher *patterns.Matcher
	
	// Detection state
	ipStats        map[string]*IPStatistics
	statsLock      sync.RWMutex
	
	// Machine learning
	mlModel        *MLModel
	
	// Behavioral analysis
	behaviorAnalyzer *BehaviorAnalyzer
	
	logger *logrus.Logger
}

// IPStatistics tracks statistics for an IP address
type IPStatistics struct {
	FirstSeen        time.Time
	LastSeen         time.Time
	RequestCount     int64
	FailedRequests   int64
	UniqueEndpoints  map[string]int
	UserAgents       map[string]int
	ResponseCodes    map[int]int
	RequestMethods   map[string]int
	BytesTransferred int64
	AvgResponseTime  float64
	
	// Behavioral metrics
	RequestPattern   []time.Time
	SuspiciousScore  float64
	ThreatCategories []string
	
	mutex sync.RWMutex
}

// NewEngine creates a new threat detection engine
func NewEngine(cfg *config.Config, logger *logrus.Logger) (*Engine, error) {
	engine := &Engine{
		config:  cfg,
		ipStats: make(map[string]*IPStatistics),
		logger:  logger,
	}
	
	// Initialize components
	engine.rangeManager = ranges.NewRangeManager()
	
	geoService, err := geoip.NewService(cfg.Detection.Geographic)
	if err != nil {
		return nil, err
	}
	engine.geoIP = geoService
	
	engine.patternMatcher = patterns.NewMatcher(cfg.Detection.SuspiciousPatterns.Patterns)
	
	// Initialize ML model if enabled
	if cfg.MachineLearning.Enabled {
		mlModel, err := NewMLModel(cfg.MachineLearning)
		if err != nil {
			logger.WithError(err).Warn("Failed to initialize ML model")
		} else {
			engine.mlModel = mlModel
		}
	}
	
	// Initialize behavior analyzer
	engine.behaviorAnalyzer = NewBehaviorAnalyzer(cfg)
	
	// Start cleanup routine
	go engine.cleanupRoutine()
	
	return engine, nil
}

// AnalyzeLogEntry analyzes a single log entry for threats
func (e *Engine) AnalyzeLogEntry(entry *logparser.LogEntry) *DetectionResult {
	result := &DetectionResult{
		IP:          entry.IP,
		ThreatTypes: []string{},
		Details:     make(map[string]string),
		Timestamp:   entry.Timestamp,
		Score:       0.0,
	}
	
	// Update IP statistics
	e.updateIPStats(entry)
	
	// Run all detection checks
	e.checkRateLimiting(entry, result)
	e.checkGeographic(entry, result)
	e.checkUserAgent(entry, result)
	e.checkSuspiciousPatterns(entry, result)
	e.checkThreatIntelligence(entry, result)
	e.checkBehavioralAnomalies(entry, result)
	
	// ML-based detection if available
	if e.mlModel != nil {
		e.runMLDetection(entry, result)
	}
	
	// Calculate final threat level and recommended action
	e.calculateThreatLevel(result)
	e.determineAction(result)
	
	return result
}

// checkRateLimiting checks for rate limiting violations
func (e *Engine) checkRateLimiting(entry *logparser.LogEntry, result *DetectionResult) {
	if !e.config.Detection.RateLimiting.Enabled {
		return
	}
	
	e.statsLock.RLock()
	stats, exists := e.ipStats[entry.IP]
	e.statsLock.RUnlock()
	
	if !exists {
		return
	}
	
	stats.mutex.RLock()
	defer stats.mutex.RUnlock()
	
	// Check request rate in the time window
	windowStart := time.Now().Add(-time.Duration(e.config.Detection.RateLimiting.WindowSeconds) * time.Second)
	recentRequests := 0
	
	for _, reqTime := range stats.RequestPattern {
		if reqTime.After(windowStart) {
			recentRequests++
		}
	}
	
	if recentRequests >= e.config.Detection.RateLimiting.Threshold {
		result.ThreatTypes = append(result.ThreatTypes, "rate_limiting")
		result.Score += 30.0
		result.Details["rate_limit_violations"] = fmt.Sprintf("%d requests in %d seconds", 
			recentRequests, e.config.Detection.RateLimiting.WindowSeconds)
	}
}

// checkGeographic checks geographic restrictions
func (e *Engine) checkGeographic(entry *logparser.LogEntry, result *DetectionResult) {
	if !e.config.Detection.Geographic.Enabled {
		return
	}
	
	country, err := e.geoIP.GetCountry(entry.IP)
	if err != nil {
		return
	}
	
	result.Details["country"] = country
	
	// Check blocked countries
	for _, blocked := range e.config.Detection.Geographic.BlockedCountries {
		if strings.EqualFold(country, blocked) {
			result.ThreatTypes = append(result.ThreatTypes, "geo_blocked")
			result.Score += 50.0
			result.Details["geo_violation"] = fmt.Sprintf("Request from blocked country: %s", country)
			return
		}
	}
	
	// Check allowed countries (if specified)
	if len(e.config.Detection.Geographic.AllowedCountries) > 0 {
		allowed := false
		for _, allowedCountry := range e.config.Detection.Geographic.AllowedCountries {
			if strings.EqualFold(country, allowedCountry) {
				allowed = true
				break
			}
		}
		if !allowed {
			result.ThreatTypes = append(result.ThreatTypes, "geo_not_allowed")
			result.Score += 40.0
			result.Details["geo_violation"] = fmt.Sprintf("Request from non-allowed country: %s", country)
		}
	}
}

// checkUserAgent checks user agent patterns
func (e *Engine) checkUserAgent(entry *logparser.LogEntry, result *DetectionResult) {
	if !e.config.Detection.UserAgentBlocking.Enabled {
		return
	}
	
	userAgent := entry.UserAgent
	
	// Check blocked patterns
	for _, pattern := range e.config.Detection.UserAgentBlocking.BlockedPatterns {
		if matched, _ := regexp.MatchString(pattern, userAgent); matched {
			result.ThreatTypes = append(result.ThreatTypes, "user_agent_blocked")
			result.Score += 25.0
			result.Details["user_agent_violation"] = fmt.Sprintf("Blocked pattern: %s", pattern)
			return
		}
	}
	
	// Check suspicious user agent characteristics
	if e.isSuspiciousUserAgent(userAgent) {
		result.ThreatTypes = append(result.ThreatTypes, "suspicious_user_agent")
		result.Score += 15.0
		result.Details["suspicious_ua"] = userAgent
	}
}

// checkSuspiciousPatterns checks for suspicious URL patterns
func (e *Engine) checkSuspiciousPatterns(entry *logparser.LogEntry, result *DetectionResult) {
	if !e.config.Detection.SuspiciousPatterns.Enabled {
		return
	}
	
	matches := e.patternMatcher.CheckPatterns(entry.Path, entry.QueryString, entry.UserAgent)
	if len(matches) > 0 {
		result.ThreatTypes = append(result.ThreatTypes, "suspicious_pattern")
		result.Score += float64(len(matches)) * 10.0
		result.Details["pattern_matches"] = strings.Join(matches, ", ")
	}
}

// checkThreatIntelligence checks against threat intelligence feeds
func (e *Engine) checkThreatIntelligence(entry *logparser.LogEntry, result *DetectionResult) {
	// Check against various threat categories
	categories := []string{"threat", "malware", "botnet", "tor", "vpn"}
	
	matched, matchedCategories := e.rangeManager.CheckIP(entry.IP, categories)
	if matched {
		result.ThreatTypes = append(result.ThreatTypes, "threat_intel")
		result.Score += 60.0
		result.Details["threat_categories"] = strings.Join(matchedCategories, ", ")
	}
	
	// Check against AI/scraper categories
	aiCategories := []string{"openai", "github", "deepseek", "anthropic"}
	aiMatched, aiMatchedCategories := e.rangeManager.CheckIP(entry.IP, aiCategories)
	if aiMatched {
		result.ThreatTypes = append(result.ThreatTypes, "ai_scraper")
		result.Score += 20.0
		result.Details["ai_categories"] = strings.Join(aiMatchedCategories, ", ")
	}
}

// checkBehavioralAnomalies uses behavioral analysis to detect anomalies
func (e *Engine) checkBehavioralAnomalies(entry *logparser.LogEntry, result *DetectionResult) {
	e.statsLock.RLock()
	stats, exists := e.ipStats[entry.IP]
	e.statsLock.RUnlock()
	
	if !exists {
		return
	}
	
	anomalyScore := e.behaviorAnalyzer.AnalyzeIP(stats, entry)
	if anomalyScore > 0.7 {
		result.ThreatTypes = append(result.ThreatTypes, "behavioral_anomaly")
		result.Score += anomalyScore * 40.0
		result.Details["anomaly_score"] = fmt.Sprintf("%.2f", anomalyScore)
	}
}

// runMLDetection runs machine learning based detection
func (e *Engine) runMLDetection(entry *logparser.LogEntry, result *DetectionResult) {
	features := e.extractFeatures(entry)
	prediction := e.mlModel.Predict(features)
	
	if prediction.IsThreat && prediction.Confidence > 0.8 {
		result.ThreatTypes = append(result.ThreatTypes, "ml_detection")
		result.Score += prediction.Confidence * 50.0
		result.Details["ml_confidence"] = fmt.Sprintf("%.2f", prediction.Confidence)
		result.Details["ml_threat_type"] = prediction.ThreatType
	}
}

// calculateThreatLevel determines the overall threat level
func (e *Engine) calculateThreatLevel(result *DetectionResult) {
	switch {
	case result.Score >= 80.0:
		result.ThreatLevel = ThreatLevelCritical
	case result.Score >= 60.0:
		result.ThreatLevel = ThreatLevelHigh
	case result.Score >= 30.0:
		result.ThreatLevel = ThreatLevelMedium
	default:
		result.ThreatLevel = ThreatLevelLow
	}
}

// determineAction determines the recommended action
func (e *Engine) determineAction(result *DetectionResult) {
	switch result.ThreatLevel {
	case ThreatLevelCritical:
		result.RecommendedAction = "BLOCK_IMMEDIATE"
	case ThreatLevelHigh:
		result.RecommendedAction = "BLOCK"
	case ThreatLevelMedium:
		result.RecommendedAction = "RATE_LIMIT"
	default:
		result.RecommendedAction = "MONITOR"
	}
	
	// Override based on specific threat types
	for _, threatType := range result.ThreatTypes {
		switch threatType {
		case "threat_intel", "malware":
			result.RecommendedAction = "BLOCK_IMMEDIATE"
		case "ai_scraper":
			result.RecommendedAction = "TARPIT"
		}
	}
}

// updateIPStats updates statistics for an IP address
func (e *Engine) updateIPStats(entry *logparser.LogEntry) {
	e.statsLock.Lock()
	defer e.statsLock.Unlock()
	
	stats, exists := e.ipStats[entry.IP]
	if !exists {
		stats = &IPStatistics{
			FirstSeen:       entry.Timestamp,
			UniqueEndpoints: make(map[string]int),
			UserAgents:      make(map[string]int),
			ResponseCodes:   make(map[int]int),
			RequestMethods:  make(map[string]int),
			RequestPattern:  []time.Time{},
		}
		e.ipStats[entry.IP] = stats
	}
	
	stats.mutex.Lock()
	defer stats.mutex.Unlock()
	
	// Update basic stats
	stats.LastSeen = entry.Timestamp
	stats.RequestCount++
	stats.UniqueEndpoints[entry.Path]++
	stats.UserAgents[entry.UserAgent]++
	stats.ResponseCodes[entry.ResponseCode]++
	stats.RequestMethods[entry.Method]++
	stats.BytesTransferred += int64(entry.ResponseSize)
	
	// Track failed requests
	if entry.ResponseCode >= 400 {
		stats.FailedRequests++
	}
	
	// Update request pattern (keep last 1000 requests)
	stats.RequestPattern = append(stats.RequestPattern, entry.Timestamp)
	if len(stats.RequestPattern) > 1000 {
		stats.RequestPattern = stats.RequestPattern[1:]
	}
}

// isSuspiciousUserAgent checks if a user agent is suspicious
func (e *Engine) isSuspiciousUserAgent(userAgent string) bool {
	suspicious := []string{
		"bot", "crawler", "spider", "scraper", "scan", "test", "benchmark",
		"wget", "curl", "python", "go-http", "java", "perl", "ruby",
	}
	
	lowerUA := strings.ToLower(userAgent)
	for _, pattern := range suspicious {
		if strings.Contains(lowerUA, pattern) {
			return true
		}
	}
	
	// Check for empty or very short user agents
	if len(userAgent) < 10 {
		return true
	}
	
	return false
}

// extractFeatures extracts features for ML prediction
func (e *Engine) extractFeatures(entry *logparser.LogEntry) []float64 {
	// This would extract various features for ML prediction
	// Features might include: request rate, path length, query complexity, etc.
	features := make([]float64, 20) // Example: 20 features
	
	// Feature 1: Path length
	features[0] = float64(len(entry.Path))
	
	// Feature 2: Query string length
	features[1] = float64(len(entry.QueryString))
	
	// Feature 3: User agent length
	features[2] = float64(len(entry.UserAgent))
	
	// Feature 4: Response code (normalized)
	features[3] = float64(entry.ResponseCode) / 500.0
	
	// Add more features as needed...
	
	return features
}

// cleanupRoutine periodically cleans up old statistics
func (e *Engine) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		e.cleanupOldStats()
	}
}

// cleanupOldStats removes old IP statistics
func (e *Engine) cleanupOldStats() {
	e.statsLock.Lock()
	defer e.statsLock.Unlock()
	
	cutoff := time.Now().Add(-24 * time.Hour)
	for ip, stats := range e.ipStats {
		stats.mutex.RLock()
		lastSeen := stats.LastSeen
		stats.mutex.RUnlock()
		
		if lastSeen.Before(cutoff) {
			delete(e.ipStats, ip)
		}
	}
}
