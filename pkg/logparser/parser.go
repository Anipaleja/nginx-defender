package logparser

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogEntry represents a parsed log entry
type LogEntry struct {
	IP           string    `json:"ip"`
	Timestamp    time.Time `json:"timestamp"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	QueryString  string    `json:"query_string"`
	Protocol     string    `json:"protocol"`
	ResponseCode int       `json:"response_code"`
	ResponseSize int       `json:"response_size"`
	Referer      string    `json:"referer"`
	UserAgent    string    `json:"user_agent"`
	RequestTime  float64   `json:"request_time"`
	
	// Additional fields for advanced analysis
	Host         string            `json:"host"`
	XForwardedFor string           `json:"x_forwarded_for"`
	Headers      map[string]string `json:"headers"`
	
	// Analysis results
	IsBot        bool     `json:"is_bot"`
	ThreatScore  float64  `json:"threat_score"`
	Tags         []string `json:"tags"`
}

// Parser handles parsing of different log formats
type Parser struct {
	format string
	regex  *regexp.Regexp
}

// Common log format patterns
var (
	// Nginx combined log format
	nginxCombinedPattern = `^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"(?: "([^"]*)")?`
	
	// Nginx extended format with request time
	nginxExtendedPattern = `^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)" (\S+)`
	
	// Apache combined log format
	apacheCombinedPattern = `^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"`
	
	// Custom JSON log format
	jsonPattern = `^\{.*\}$`
)

// NewParser creates a new log parser
func NewParser(format string) *Parser {
	var pattern string
	
	switch format {
	case "nginx_combined":
		pattern = nginxCombinedPattern
	case "nginx_extended":
		pattern = nginxExtendedPattern
	case "apache_combined":
		pattern = apacheCombinedPattern
	case "json":
		pattern = jsonPattern
	default:
		pattern = nginxCombinedPattern // default
	}
	
	return &Parser{
		format: format,
		regex:  regexp.MustCompile(pattern),
	}
}

// ParseLine parses a single log line
func (p *Parser) ParseLine(line string) (*LogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}
	
	switch p.format {
	case "json":
		return p.parseJSON(line)
	default:
		return p.parseRegex(line)
	}
}

// parseRegex parses using regex patterns
func (p *Parser) parseRegex(line string) (*LogEntry, error) {
	matches := p.regex.FindStringSubmatch(line)
	if len(matches) < 10 {
		return nil, fmt.Errorf("failed to parse log line: %s", line)
	}
	
	entry := &LogEntry{
		Headers: make(map[string]string),
		Tags:    []string{},
	}
	
	// Parse IP
	entry.IP = matches[1]
	
	// Parse timestamp
	timeStr := matches[2]
	timestamp, err := parseTimestamp(timeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %v", err)
	}
	entry.Timestamp = timestamp
	
	// Parse method and path
	entry.Method = matches[3]
	requestURI := matches[4]
	entry.Protocol = matches[5]
	
	// Parse request URI
	if requestURI != "" {
		if strings.Contains(requestURI, "?") {
			parts := strings.SplitN(requestURI, "?", 2)
			entry.Path = parts[0]
			entry.QueryString = parts[1]
		} else {
			entry.Path = requestURI
		}
	}
	
	// Parse response code and size
	if responseCode, err := strconv.Atoi(matches[6]); err == nil {
		entry.ResponseCode = responseCode
	}
	
	if responseSize, err := strconv.Atoi(matches[7]); err == nil {
		entry.ResponseSize = responseSize
	}
	
	// Parse referer and user agent
	entry.Referer = matches[8]
	entry.UserAgent = matches[9]
	
	// Parse request time if available
	if len(matches) > 10 && matches[10] != "" {
		if requestTime, err := strconv.ParseFloat(matches[10], 64); err == nil {
			entry.RequestTime = requestTime
		}
	}
	
	// Additional processing
	entry.IsBot = isBot(entry.UserAgent)
	entry.Host = extractHost(entry.Headers)
	
	return entry, nil
}

// parseJSON parses JSON formatted logs
func (p *Parser) parseJSON(line string) (*LogEntry, error) {
	// This would implement JSON parsing
	// For now, return a basic implementation
	return nil, fmt.Errorf("JSON parsing not implemented yet")
}

// parseTimestamp parses various timestamp formats
func parseTimestamp(timeStr string) (time.Time, error) {
	// Common nginx/apache timestamp format: 02/Jan/2006:15:04:05 -0700
	layouts := []string{
		"02/Jan/2006:15:04:05 -0700",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
		time.RFC3339,
	}
	
	for _, layout := range layouts {
		if t, err := time.Parse(layout, timeStr); err == nil {
			return t, nil
		}
	}
	
	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", timeStr)
}

// isBot determines if a user agent is likely a bot
func isBot(userAgent string) bool {
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper", "scan", "monitoring",
		"wget", "curl", "python", "go-http", "java/", "perl/",
	}
	
	lowerUA := strings.ToLower(userAgent)
	for _, pattern := range botPatterns {
		if strings.Contains(lowerUA, pattern) {
			return true
		}
	}
	
	return false
}

// extractHost extracts host from headers or other sources
func extractHost(headers map[string]string) string {
	if host, exists := headers["Host"]; exists {
		return host
	}
	return ""
}

// ParseFile parses an entire log file
func (p *Parser) ParseFile(scanner *bufio.Scanner, callback func(*LogEntry) error) error {
	for scanner.Scan() {
		line := scanner.Text()
		entry, err := p.ParseLine(line)
		if err != nil {
			continue // Skip invalid lines
		}
		if entry == nil {
			continue // Skip empty lines
		}
		
		if err := callback(entry); err != nil {
			return err
		}
	}
	
	return scanner.Err()
}
