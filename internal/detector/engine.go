package detector

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/behavior"
	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/internal/deception"
	"github.com/Anipaleja/nginx-defender/internal/ml"
	"github.com/Anipaleja/nginx-defender/internal/plugins"
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
	ID                string            `json:"id"`
	IP                string            `json:"ip"`
	ThreatLevel       ThreatLevel       `json:"threat_level"`
	ThreatTypes       []string          `json:"threat_types"`
	Score             float64           `json:"score"`
	Confidence        float64           `json:"confidence"`
	Details           map[string]string `json:"details"`
	Timestamp         time.Time         `json:"timestamp"`
	RecommendedAction string            `json:"recommended_action"`
}

// Engine is the main threat detection engine
type Engine struct {
	config         *config.Config
	rangeManager   *ranges.RangeManager
	geoIP          *geoip.Service
	patternMatcher *patterns.Matcher
	builtInSignatures map[string]*regexp.Regexp

	// Detection state
	ipStats   map[string]*IPStatistics
	statsLock sync.RWMutex

	// Machine learning
	mlModel      *MLModel
	onlineModel  *ml.OnlineAnomalyModel
	mlEnabled    bool

	// Profiling and deception
	behaviorProfiler *behavior.Profiler
	deceptionEngine  *deception.Engine
	pluginManager    *plugins.Manager

	// Behavioral analysis
	behaviorAnalyzer *BehaviorAnalyzer

	// Replay and audit state
	history     []*DetectionResult
	historyByIP map[string][]*DetectionResult
	historyLock sync.RWMutex
	nextEventID uint64

	// Trusted proxy handling
	trustedProxyNetworks []*net.IPNet

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
		config:      cfg,
		ipStats:     make(map[string]*IPStatistics),
		history:     make([]*DetectionResult, 0, 2048),
		historyByIP: make(map[string][]*DetectionResult),
		builtInSignatures: make(map[string]*regexp.Regexp),
		logger:      logger,
	}

	// Initialize components
	engine.rangeManager = ranges.NewRangeManager()

	geoService, err := geoip.NewService(cfg.Detection.Geographic)
	if err != nil {
		return nil, err
	}
	engine.geoIP = geoService

	engine.patternMatcher = patterns.NewMatcher(cfg.Detection.SuspiciousPatterns.Patterns)
	engine.initializeBuiltInSignatures()
	engine.behaviorProfiler = behavior.NewProfiler(50000, 30*time.Minute)
	engine.deceptionEngine = deception.NewEngine()
	engine.pluginManager = plugins.NewManager()
	if paths := strings.TrimSpace(os.Getenv("NGINX_DEFENDER_PLUGINS")); paths != "" {
		for _, path := range strings.Split(paths, ",") {
			pluginPath := strings.TrimSpace(path)
			if pluginPath == "" {
				continue
			}
			if err := engine.pluginManager.LoadSharedObject(pluginPath); err != nil {
				logger.WithError(err).Warnf("Failed to load detection plugin %s", pluginPath)
			}
		}
	}

	// Initialize ML model if enabled
	if cfg.MachineLearning.Enabled {
		engine.mlEnabled = true
		engine.onlineModel = ml.NewOnlineAnomalyModel(cfg.MachineLearning.AnomalyThreshold)
		if cfg.MachineLearning.ModelPath != "" {
			if err := engine.onlineModel.Load(cfg.MachineLearning.ModelPath); err != nil {
				logger.WithError(err).Debug("Unable to load streaming ML model state, starting fresh")
			}
		}

		mlModel, err := NewMLModel(cfg.MachineLearning)
		if err != nil {
			logger.WithError(err).Warn("Failed to initialize ML model")
		} else {
			engine.mlModel = mlModel
		}
	}

	// Initialize behavior analyzer
	engine.behaviorAnalyzer = NewBehaviorAnalyzer(*cfg)

	if cfg.Detection.Proxy.Enabled {
		engine.trustedProxyNetworks = make([]*net.IPNet, 0, len(cfg.Detection.Proxy.TrustedProxies))
		for _, proxy := range cfg.Detection.Proxy.TrustedProxies {
			if strings.Contains(proxy, "/") {
				_, network, err := net.ParseCIDR(proxy)
				if err != nil {
					logger.WithError(err).Warnf("Invalid trusted proxy CIDR %s", proxy)
					continue
				}
				engine.trustedProxyNetworks = append(engine.trustedProxyNetworks, network)
				continue
			}

			parsed := net.ParseIP(proxy)
			if parsed == nil {
				logger.Warnf("Invalid trusted proxy IP %s", proxy)
				continue
			}

			bits := 128
			if parsed.To4() != nil {
				bits = 32
			}
			engine.trustedProxyNetworks = append(engine.trustedProxyNetworks, &net.IPNet{IP: parsed, Mask: net.CIDRMask(bits, bits)})
		}
	}

	// Start cleanup routine
	go engine.cleanupRoutine()

	return engine, nil
}

func (e *Engine) initializeBuiltInSignatures() {
	raw := map[string]string{
		"sql_injection":   `(?i)(union\s+select|select\s+.+\s+from|sleep\s*\(|benchmark\s*\(|information_schema|or\s+1=1|\bdrop\b\s+\btable\b|\bexec\b\s+\bxp_)`,
		"xss":             `(?i)(<script\b|javascript:|vbscript:|onerror\s*=|onload\s*=|<img[^>]+onerror=)`,
		"path_traversal":  `(?i)(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f|/etc/passwd|/proc/self/environ)`,
		"rce":             `(?i)(\b(wget|curl|chmod|nc|bash|sh)\b\s+|\$\(|` + "`" + `.+` + "`" + `|;\s*(cat|id|uname)\b)`,
		"cmd_injection":   `(?i)(\|\||&&|;\s*(rm|cat|bash|sh|python)\b)`,
		"sensitive_probe": `(?i)(/\.git/|/\.env|/wp-admin|/phpmyadmin|/actuator|/\.well-known/)`,
	}

	for kind, pattern := range raw {
		re, err := regexp.Compile(pattern)
		if err != nil {
			e.logger.WithError(err).Warnf("Failed to compile built-in signature for %s", kind)
			continue
		}
		e.builtInSignatures[kind] = re
	}
}

// AnalyzeLogEntry analyzes a single log entry for threats
func (e *Engine) AnalyzeLogEntry(entry *logparser.LogEntry) *DetectionResult {
	if entry == nil {
		return &DetectionResult{
			ThreatTypes: []string{},
			Details:     map[string]string{},
			Timestamp:   time.Now(),
		}
	}

	resolvedIP := e.resolveClientIP(entry)
	if resolvedIP != "" {
		entry.IP = resolvedIP
	}

	result := &DetectionResult{
		IP:          entry.IP,
		ThreatTypes: []string{},
		Details:     make(map[string]string),
		Timestamp:   entry.Timestamp,
		Score:       0.0,
		Confidence:  0.0,
	}

	// Update IP statistics
	e.updateIPStats(entry)

	// Run all detection checks
	e.checkRateLimiting(entry, result)
	e.checkGeographic(entry, result)
	e.checkUserAgent(entry, result)
	e.checkSuspiciousPatterns(entry, result)
	e.checkDeceptionSignals(entry, result)
	e.checkThreatIntelligence(entry, result)
	e.checkBehavioralAnomalies(entry, result)
	e.checkProfileSignals(entry, result)

	// ML-based detection if available
	if e.mlEnabled {
		e.runMLDetection(entry, result)
	}

	pluginCtx := &plugins.DetectionContext{
		ThreatTypes: append([]string{}, result.ThreatTypes...),
		Score:       result.Score,
		Details:     map[string]string{},
	}
	for k, v := range result.Details {
		pluginCtx.Details[k] = v
	}
	e.pluginManager.Run(entry, pluginCtx)
	result.ThreatTypes = pluginCtx.ThreatTypes
	result.Score = pluginCtx.Score
	result.Details = pluginCtx.Details

	// Calculate final threat level and recommended action
	e.calculateThreatLevel(result)
	e.determineAction(result)

	if result.Score > 0 {
		e.recordDetectionResult(result, entry)
	}

	return result
}

func (e *Engine) checkDeceptionSignals(entry *logparser.LogEntry, result *DetectionResult) {
	if e.deceptionEngine == nil || entry == nil {
		return
	}
	if matched, endpoint := e.deceptionEngine.Match(entry.Path); matched {
		result.ThreatTypes = append(result.ThreatTypes, "honeypot_interaction")
		result.Score += 70.0
		result.Details["deception_endpoint"] = endpoint
	}
}

func (e *Engine) checkProfileSignals(entry *logparser.LogEntry, result *DetectionResult) {
	if e.behaviorProfiler == nil || entry == nil {
		return
	}

	_, signals := e.behaviorProfiler.Observe(entry.IP, entry)
	result.Details["endpoint_entropy"] = fmt.Sprintf("%.3f", signals.EndpointEntropy)
	result.Details["burst_score"] = fmt.Sprintf("%.3f", signals.BurstScore)

	if signals.ScrapingScore > 0.7 {
		result.ThreatTypes = append(result.ThreatTypes, "scraping")
		result.Score += signals.ScrapingScore * 35.0
	}
	if signals.CredentialStuffing > 0.7 {
		result.ThreatTypes = append(result.ThreatTypes, "credential_stuffing")
		result.Score += signals.CredentialStuffing * 40.0
	}
	if signals.ProbingScore > 0.6 {
		result.ThreatTypes = append(result.ThreatTypes, "probing")
		result.Score += signals.ProbingScore * 35.0
	}
	if signals.HoneypotScore > 0 {
		result.Score += signals.HoneypotScore * 25.0
	}
}

// checkRateLimiting checks for rate limiting violations
func (e *Engine) checkRateLimiting(entry *logparser.LogEntry, result *DetectionResult) {
	if !e.config.Detection.RateLimiting.Enabled {
		return
	}

	threshold := e.config.Detection.RateLimiting.Threshold
	windowSeconds := e.config.Detection.RateLimiting.WindowSeconds
	for _, routeRule := range e.config.Detection.RateLimiting.Routes {
		if strings.HasPrefix(entry.Path, routeRule.PathPrefix) {
			threshold = routeRule.Threshold
			windowSeconds = routeRule.WindowSeconds
			break
		}
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
	windowStart := time.Now().Add(-time.Duration(windowSeconds) * time.Second)
	recentRequests := 0

	for _, reqTime := range stats.RequestPattern {
		if reqTime.After(windowStart) {
			recentRequests++
		}
	}

	if recentRequests >= threshold {
		result.ThreatTypes = append(result.ThreatTypes, "rate_limiting")
		result.Score += 30.0
		result.Details["rate_limit_violations"] = fmt.Sprintf("%d requests in %d seconds",
			recentRequests, windowSeconds)
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
	lowerUA := strings.ToLower(userAgent)

	// Check blocked patterns
	for _, pattern := range e.config.Detection.UserAgentBlocking.BlockedPatterns {
		if matched, _ := regexp.MatchString(pattern, userAgent); matched {
			result.ThreatTypes = append(result.ThreatTypes, "user_agent_blocked")
			result.Score += 25.0
			result.Details["user_agent_violation"] = fmt.Sprintf("Blocked pattern: %s", pattern)
			return
		}
	}

	if entry.IsBot {
		result.ThreatTypes = append(result.ThreatTypes, "bot_client")
		result.Score += 18.0
		result.Details["bot_client"] = "true"
	}

	if automationLabel := classifyAutomationClient(lowerUA); automationLabel != "" {
		result.ThreatTypes = append(result.ThreatTypes, automationLabel)
		result.Score += 40.0
		result.Details["automation_client"] = automationLabel
	}

	// Check suspicious user agent characteristics
	if e.isSuspiciousUserAgent(userAgent) {
		result.ThreatTypes = append(result.ThreatTypes, "suspicious_user_agent")
		result.Score += 12.0
		result.Details["suspicious_ua"] = userAgent

		if strings.Contains(lowerUA, "bot") || strings.Contains(lowerUA, "crawler") || strings.Contains(lowerUA, "spider") || strings.Contains(lowerUA, "scraper") {
			result.ThreatTypes = append(result.ThreatTypes, "bot_attack")
			result.Score += 18.0
		}

		if entry.Referer == "" && entry.Path != "/" {
			result.Score += 5.0
			result.Details["missing_referer"] = "true"
		}
	}
}

// checkSuspiciousPatterns checks for suspicious URL patterns
func (e *Engine) checkSuspiciousPatterns(entry *logparser.LogEntry, result *DetectionResult) {
	if !e.config.Detection.SuspiciousPatterns.Enabled {
		return
	}

	payload := strings.ToLower(entry.Path + " " + entry.QueryString + " " + entry.UserAgent)
	for threatType, re := range e.builtInSignatures {
		if re == nil || !re.MatchString(payload) {
			continue
		}

		result.ThreatTypes = append(result.ThreatTypes, threatType)
		switch threatType {
		case "sql_injection", "xss", "rce", "cmd_injection":
			result.Score += 55.0
		case "path_traversal", "sensitive_probe":
			result.Score += 45.0
		default:
			result.Score += 25.0
		}
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
	if !e.mlEnabled {
		return
	}

	if e.onlineModel != nil {
		onlineFeatures := ml.FeatureVector{
			RequestFrequency:   featureRequestFrequency(entry, result),
			EndpointEntropy:    parseFloatOrZero(result.Details["endpoint_entropy"]),
			UserAgentRisk:      userAgentRisk(entry.UserAgent),
			ErrorRate:          featureErrorRate(entry.ResponseCode),
			BurstScore:         parseFloatOrZero(result.Details["burst_score"]),
			CredentialStuffing: boolToFloat(containsThreat(result.ThreatTypes, "credential_stuffing")),
			ScanScore:          boolToFloat(containsThreat(result.ThreatTypes, "probing")),
			HoneypotScore:      boolToFloat(containsThreat(result.ThreatTypes, "honeypot_interaction")),
		}

		pred := e.onlineModel.PredictAndLearn(onlineFeatures)
		result.Details["ml_anomaly_score"] = fmt.Sprintf("%.3f", pred.AnomalyScore)
		result.Confidence = pred.Confidence
		if pred.IsAnomalous {
			result.ThreatTypes = append(result.ThreatTypes, "ml_streaming_anomaly")
			result.Score += pred.AnomalyScore * 50.0
		}
		if e.config.MachineLearning.ModelPath != "" {
			_ = e.onlineModel.Save(e.config.MachineLearning.ModelPath)
		}
	}

	if e.mlModel == nil {
		return
	}

	features := e.extractFeatures(entry)
	prediction := e.mlModel.Predict(features)

	if prediction.IsThreat && prediction.Confidence > 0.8 {
		result.ThreatTypes = append(result.ThreatTypes, "ml_detection")
		result.Score += prediction.Confidence * 50.0
		result.Details["ml_confidence"] = fmt.Sprintf("%.2f", prediction.Confidence)
		result.Details["ml_threat_type"] = prediction.ThreatType
		if prediction.Confidence > result.Confidence {
			result.Confidence = prediction.Confidence
		}
	}
}

func featureRequestFrequency(entry *logparser.LogEntry, result *DetectionResult) float64 {
	if entry == nil {
		return 0
	}
	if containsThreat(result.ThreatTypes, "rate_limiting") {
		return 1
	}
	return 0.4
}

func featureErrorRate(code int) float64 {
	if code >= 500 {
		return 1
	}
	if code >= 400 {
		return 0.6
	}
	return 0.1
}

func userAgentRisk(ua string) float64 {
	l := strings.ToLower(ua)
	if strings.Contains(l, "bot") || strings.Contains(l, "crawler") || strings.Contains(l, "scraper") {
		return 0.9
	}
	if len(strings.TrimSpace(ua)) < 10 {
		return 0.6
	}
	return 0.2
}

func containsThreat(types []string, target string) bool {
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}

func parseFloatOrZero(v string) float64 {
	var f float64
	_, _ = fmt.Sscanf(v, "%f", &f)
	return f
}

func boolToFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
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
		case "threat_intel", "malware", "sql_injection", "xss", "rce", "cmd_injection", "path_traversal", "sensitive_probe":
			result.RecommendedAction = "BLOCK_IMMEDIATE"
		case "ai_scraper", "bot_attack", "bot_client", "automation_client", "headless_browser", "playwright", "puppeteer", "selenium", "phantomjs":
			result.RecommendedAction = "BLOCK"
		case "suspicious_user_agent":
			if result.Score >= 45.0 {
				result.RecommendedAction = "BLOCK"
			} else if result.RecommendedAction == "MONITOR" {
				result.RecommendedAction = "TARPIT"
			}
		}
	}
}

func classifyAutomationClient(lowerUA string) string {
	switch {
	case lowerUA == "":
		return ""
	case strings.Contains(lowerUA, "playwright"):
		return "playwright"
	case strings.Contains(lowerUA, "puppeteer"):
		return "puppeteer"
	case strings.Contains(lowerUA, "selenium"):
		return "selenium"
	case strings.Contains(lowerUA, "phantomjs"):
		return "phantomjs"
	case strings.Contains(lowerUA, "headless"):
		return "headless_browser"
	case strings.Contains(lowerUA, "python-requests"), strings.Contains(lowerUA, "httpx"), strings.Contains(lowerUA, "aiohttp"), strings.Contains(lowerUA, "scrapy"):
		return "python_client"
	case strings.Contains(lowerUA, "go-http-client"), strings.Contains(lowerUA, "curl"), strings.Contains(lowerUA, "wget"), strings.Contains(lowerUA, "okhttp"), strings.Contains(lowerUA, "axios"), strings.Contains(lowerUA, "libwww-perl"), strings.Contains(lowerUA, "java/"):
		return "automation_client"
	default:
		return ""
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
	currentCount := stats.RequestCount
	stats.UniqueEndpoints[entry.Path]++
	stats.UserAgents[entry.UserAgent]++
	stats.ResponseCodes[entry.ResponseCode]++
	stats.RequestMethods[entry.Method]++
	stats.BytesTransferred += int64(entry.ResponseSize)

	if entry.RequestTime > 0 {
		if currentCount <= 1 {
			stats.AvgResponseTime = entry.RequestTime
		} else {
			stats.AvgResponseTime = ((stats.AvgResponseTime * float64(currentCount-1)) + entry.RequestTime) / float64(currentCount)
		}
	}

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

func (e *Engine) recordDetectionResult(result *DetectionResult, entry *logparser.LogEntry) {
	if result == nil || entry == nil {
		return
	}

	resultCopy := *result
	resultCopy.ID = fmt.Sprintf("threat-%d", atomic.AddUint64(&e.nextEventID, 1))

	detailsCopy := make(map[string]string, len(result.Details)+3)
	for key, value := range result.Details {
		detailsCopy[key] = value
	}
	detailsCopy["path"] = entry.Path
	detailsCopy["method"] = entry.Method
	if entry.XForwardedFor != "" {
		detailsCopy["x_forwarded_for"] = entry.XForwardedFor
	}
	resultCopy.Details = detailsCopy

	e.historyLock.Lock()
	defer e.historyLock.Unlock()

	e.history = append(e.history, &resultCopy)
	if len(e.history) > 10000 {
		e.history = e.history[len(e.history)-10000:]
	}

	e.historyByIP[resultCopy.IP] = append(e.historyByIP[resultCopy.IP], &resultCopy)
	if len(e.historyByIP[resultCopy.IP]) > 2000 {
		e.historyByIP[resultCopy.IP] = e.historyByIP[resultCopy.IP][len(e.historyByIP[resultCopy.IP])-2000:]
	}
}

func (e *Engine) GetRecentThreats(limit int) []DetectionResult {
	if limit <= 0 {
		limit = 100
	}

	e.historyLock.RLock()
	defer e.historyLock.RUnlock()

	if len(e.history) == 0 {
		return []DetectionResult{}
	}

	start := len(e.history) - limit
	if start < 0 {
		start = 0
	}

	results := make([]DetectionResult, 0, len(e.history)-start)
	for i := len(e.history) - 1; i >= start; i-- {
		results = append(results, *e.history[i])
	}

	return results
}

func (e *Engine) GetThreatByID(id string) (*DetectionResult, bool) {
	e.historyLock.RLock()
	defer e.historyLock.RUnlock()

	for _, result := range e.history {
		if result.ID == id {
			copyResult := *result
			return &copyResult, true
		}
	}

	return nil, false
}

func (e *Engine) GetIPThreatHistory(ip string, limit int) []DetectionResult {
	if limit <= 0 {
		limit = 100
	}

	e.historyLock.RLock()
	defer e.historyLock.RUnlock()

	entries, exists := e.historyByIP[ip]
	if !exists || len(entries) == 0 {
		return []DetectionResult{}
	}

	start := len(entries) - limit
	if start < 0 {
		start = 0
	}

	results := make([]DetectionResult, 0, len(entries)-start)
	for i := len(entries) - 1; i >= start; i-- {
		results = append(results, *entries[i])
	}

	return results
}

func (e *Engine) resolveClientIP(entry *logparser.LogEntry) string {
	if entry == nil {
		return ""
	}

	sourceIP := normalizeIP(entry.IP)
	if sourceIP == "" {
		return ""
	}

	if !e.config.Detection.Proxy.Enabled || len(e.trustedProxyNetworks) == 0 {
		return sourceIP
	}

	if !e.isTrustedProxy(sourceIP) {
		return sourceIP
	}

	headers := e.config.Detection.Proxy.ClientIPHeaders
	if len(headers) == 0 {
		headers = []string{"CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"}
	}

	for _, header := range headers {
		switch strings.ToLower(strings.TrimSpace(header)) {
		case "cf-connecting-ip":
			candidate := normalizeIP(getHeaderValue(entry.Headers, "CF-Connecting-IP"))
			if candidate != "" {
				return candidate
			}
		case "x-forwarded-for":
			xff := entry.XForwardedFor
			if xff == "" {
				xff = getHeaderValue(entry.Headers, "X-Forwarded-For")
			}
			// Iterate right-to-left: each proxy appends itself, so the rightmost
			// non-trusted IP is the actual client. Taking leftmost is spoofable
			// because an attacker can prepend arbitrary IPs to the XFF header.
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				parsed := normalizeIP(parts[i])
				if parsed == "" {
					continue
				}
				if !e.isTrustedProxy(parsed) {
					return parsed
				}
			}
		case "x-real-ip":
			candidate := normalizeIP(getHeaderValue(entry.Headers, "X-Real-IP"))
			if candidate != "" {
				return candidate
			}
		}
	}

	return sourceIP
}

func (e *Engine) isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	for _, network := range e.trustedProxyNetworks {
		if network.Contains(parsed) {
			return true
		}
	}

	return false
}

func getHeaderValue(headers map[string]string, key string) string {
	for headerKey, value := range headers {
		if strings.EqualFold(headerKey, key) {
			return strings.TrimSpace(value)
		}
	}

	return ""
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}

	return parsed.String()
}
