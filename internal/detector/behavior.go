package detector

import (
	"math"
	"sort"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/pkg/logparser"
)

// BehaviorAnalyzer analyzes behavioral patterns to detect anomalies
type BehaviorAnalyzer struct {
	config config.Config
}

// BehaviorMetrics represents behavioral metrics for an IP
type BehaviorMetrics struct {
	RequestFrequency    float64
	SessionDuration     float64
	EndpointDiversity   float64
	UserAgentConsistency float64
	ResponseTimePattern float64
	ErrorRatePattern    float64
	TimeOfDayPattern    float64
	RequestSizePattern  float64
}

// NewBehaviorAnalyzer creates a new behavior analyzer
func NewBehaviorAnalyzer(cfg config.Config) *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		config: cfg,
	}
}

// AnalyzeIP analyzes behavioral patterns for an IP address
func (ba *BehaviorAnalyzer) AnalyzeIP(stats *IPStatistics, currentEntry *logparser.LogEntry) float64 {
	stats.mutex.RLock()
	defer stats.mutex.RUnlock()
	
	metrics := ba.calculateMetrics(stats, currentEntry)
	return ba.calculateAnomalyScore(metrics)
}

// calculateMetrics calculates behavioral metrics
func (ba *BehaviorAnalyzer) calculateMetrics(stats *IPStatistics, currentEntry *logparser.LogEntry) BehaviorMetrics {
	metrics := BehaviorMetrics{}
	
	// Request frequency analysis
	metrics.RequestFrequency = ba.analyzeRequestFrequency(stats)
	
	// Session duration analysis
	metrics.SessionDuration = ba.analyzeSessionDuration(stats)
	
	// Endpoint diversity analysis
	metrics.EndpointDiversity = ba.analyzeEndpointDiversity(stats)
	
	// User agent consistency analysis
	metrics.UserAgentConsistency = ba.analyzeUserAgentConsistency(stats)
	
	// Response time pattern analysis
	metrics.ResponseTimePattern = ba.analyzeResponseTimePattern(stats)
	
	// Error rate pattern analysis
	metrics.ErrorRatePattern = ba.analyzeErrorRatePattern(stats)
	
	// Time of day pattern analysis
	metrics.TimeOfDayPattern = ba.analyzeTimeOfDayPattern(stats)
	
	// Request size pattern analysis
	metrics.RequestSizePattern = ba.analyzeRequestSizePattern(stats)
	
	return metrics
}

// analyzeRequestFrequency analyzes the request frequency pattern
func (ba *BehaviorAnalyzer) analyzeRequestFrequency(stats *IPStatistics) float64 {
	if len(stats.RequestPattern) < 2 {
		return 0.0
	}
	
	// Calculate intervals between requests
	intervals := make([]float64, 0, len(stats.RequestPattern)-1)
	for i := 1; i < len(stats.RequestPattern); i++ {
		interval := stats.RequestPattern[i].Sub(stats.RequestPattern[i-1]).Seconds()
		intervals = append(intervals, interval)
	}
	
	// Calculate variance in intervals (high variance = human-like, low variance = bot-like)
	if len(intervals) == 0 {
		return 0.0
	}
	
	mean := ba.calculateMean(intervals)
	variance := ba.calculateVariance(intervals, mean)
	
	// Normalize the score (lower variance = higher anomaly score)
	// Very regular patterns (low variance) are suspicious
	if variance < 1.0 { // Less than 1 second variance
		return 0.8
	} else if variance < 5.0 { // Less than 5 seconds variance
		return 0.5
	}
	
	return 0.0
}

// analyzeSessionDuration analyzes session duration patterns
func (ba *BehaviorAnalyzer) analyzeSessionDuration(stats *IPStatistics) float64 {
	sessionDuration := stats.LastSeen.Sub(stats.FirstSeen).Hours()
	
	// Very short sessions with many requests are suspicious
	if sessionDuration < 0.1 && stats.RequestCount > 50 { // Less than 6 minutes
		return 0.9
	}
	
	// Very long sessions might also be suspicious
	if sessionDuration > 24 && stats.RequestCount > 1000 { // More than 24 hours
		return 0.6
	}
	
	return 0.0
}

// analyzeEndpointDiversity analyzes the diversity of requested endpoints
func (ba *BehaviorAnalyzer) analyzeEndpointDiversity(stats *IPStatistics) float64 {
	if stats.RequestCount == 0 {
		return 0.0
	}
	
	uniqueEndpoints := float64(len(stats.UniqueEndpoints))
	totalRequests := float64(stats.RequestCount)
	
	// Calculate entropy of endpoint distribution
	entropy := 0.0
	for _, count := range stats.UniqueEndpoints {
		probability := float64(count) / totalRequests
		if probability > 0 {
			entropy -= probability * math.Log2(probability)
		}
	}
	
	// Normalize entropy
	maxEntropy := math.Log2(uniqueEndpoints)
	if maxEntropy == 0 {
		return 0.0
	}
	
	normalizedEntropy := entropy / maxEntropy
	
	// Low diversity (focused scanning) is suspicious
	if normalizedEntropy < 0.3 && uniqueEndpoints > 10 {
		return 0.7
	}
	
	// Very high diversity might also be suspicious (full site crawling)
	if normalizedEntropy > 0.9 && uniqueEndpoints > 100 {
		return 0.5
	}
	
	return 0.0
}

// analyzeUserAgentConsistency analyzes user agent consistency
func (ba *BehaviorAnalyzer) analyzeUserAgentConsistency(stats *IPStatistics) float64 {
	if len(stats.UserAgents) <= 1 {
		return 0.0
	}
	
	// Multiple user agents from same IP can be suspicious
	numUserAgents := float64(len(stats.UserAgents))
	totalRequests := float64(stats.RequestCount)
	
	// Calculate the ratio of user agents to requests
	ratio := numUserAgents / totalRequests
	
	// High number of different user agents is suspicious
	if numUserAgents > 5 && ratio > 0.1 {
		return 0.8
	}
	
	return 0.0
}

// analyzeResponseTimePattern analyzes response time patterns
func (ba *BehaviorAnalyzer) analyzeResponseTimePattern(stats *IPStatistics) float64 {
	// This would analyze response time patterns
	// For now, return a basic implementation
	
	avgResponseTime := stats.AvgResponseTime
	
	// Very fast responses might indicate cached/automated requests
	if avgResponseTime < 0.01 { // Less than 10ms average
		return 0.4
	}
	
	return 0.0
}

// analyzeErrorRatePattern analyzes error rate patterns
func (ba *BehaviorAnalyzer) analyzeErrorRatePattern(stats *IPStatistics) float64 {
	if stats.RequestCount == 0 {
		return 0.0
	}
	
	errorRate := float64(stats.FailedRequests) / float64(stats.RequestCount)
	
	// High error rates are suspicious (scanning, brute force)
	if errorRate > 0.8 {
		return 0.9
	} else if errorRate > 0.5 {
		return 0.6
	} else if errorRate > 0.3 {
		return 0.3
	}
	
	return 0.0
}

// analyzeTimeOfDayPattern analyzes time-of-day request patterns
func (ba *BehaviorAnalyzer) analyzeTimeOfDayPattern(stats *IPStatistics) float64 {
	if len(stats.RequestPattern) < 10 {
		return 0.0
	}
	
	// Count requests by hour of day
	hourCounts := make([]int, 24)
	for _, timestamp := range stats.RequestPattern {
		hour := timestamp.Hour()
		hourCounts[hour]++
	}
	
	// Calculate variance in hourly distribution
	totalRequests := len(stats.RequestPattern)
	expectedPerHour := float64(totalRequests) / 24.0
	
	variance := 0.0
	for _, count := range hourCounts {
		diff := float64(count) - expectedPerHour
		variance += diff * diff
	}
	variance /= 24.0
	
	// Very uniform distribution (bot-like) is suspicious
	standardDeviation := math.Sqrt(variance)
	if standardDeviation < expectedPerHour*0.2 { // Very uniform
		return 0.6
	}
	
	return 0.0
}

// analyzeRequestSizePattern analyzes request size patterns
func (ba *BehaviorAnalyzer) analyzeRequestSizePattern(stats *IPStatistics) float64 {
	if stats.RequestCount == 0 {
		return 0.0
	}
	
	avgBytes := float64(stats.BytesTransferred) / float64(stats.RequestCount)
	
	// Very small average request sizes might indicate scanning
	if avgBytes < 100 && stats.RequestCount > 50 {
		return 0.4
	}
	
	// Very large average request sizes might indicate data exfiltration
	if avgBytes > 1000000 { // 1MB average
		return 0.5
	}
	
	return 0.0
}

// calculateAnomalyScore calculates the overall anomaly score
func (ba *BehaviorAnalyzer) calculateAnomalyScore(metrics BehaviorMetrics) float64 {
	// Weighted combination of all metrics
	weights := map[string]float64{
		"request_frequency":      0.2,
		"session_duration":       0.1,
		"endpoint_diversity":     0.2,
		"user_agent_consistency": 0.15,
		"response_time_pattern":  0.1,
		"error_rate_pattern":     0.15,
		"time_of_day_pattern":    0.05,
		"request_size_pattern":   0.05,
	}
	
	score := 0.0
	score += metrics.RequestFrequency * weights["request_frequency"]
	score += metrics.SessionDuration * weights["session_duration"]
	score += metrics.EndpointDiversity * weights["endpoint_diversity"]
	score += metrics.UserAgentConsistency * weights["user_agent_consistency"]
	score += metrics.ResponseTimePattern * weights["response_time_pattern"]
	score += metrics.ErrorRatePattern * weights["error_rate_pattern"]
	score += metrics.TimeOfDayPattern * weights["time_of_day_pattern"]
	score += metrics.RequestSizePattern * weights["request_size_pattern"]
	
	// Ensure score is between 0 and 1
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

// Helper functions
func (ba *BehaviorAnalyzer) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}
	
	sum := 0.0
	for _, value := range values {
		sum += value
	}
	
	return sum / float64(len(values))
}

func (ba *BehaviorAnalyzer) calculateVariance(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0.0
	}
	
	sumSquares := 0.0
	for _, value := range values {
		diff := value - mean
		sumSquares += diff * diff
	}
	
	return sumSquares / float64(len(values))
}

func (ba *BehaviorAnalyzer) calculateMedian(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}
	
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)
	
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2.0
	}
	
	return sorted[mid]
}
