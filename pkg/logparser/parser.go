package logparser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
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
	Host          string            `json:"host"`
	XForwardedFor string            `json:"x_forwarded_for"`
	Headers       map[string]string `json:"headers"`

	// Analysis results
	IsBot       bool     `json:"is_bot"`
	ThreatScore float64  `json:"threat_score"`
	Tags        []string `json:"tags"`
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
	parser, err := NewParserWithRegex(format, "")
	if err != nil {
		// Fall back to safe default parser on invalid configuration.
		return &Parser{
			format: "nginx_combined",
			regex:  regexp.MustCompile(nginxCombinedPattern),
		}
	}

	return parser
}

// NewParserWithRegex creates a new parser with an optional custom regex pattern.
func NewParserWithRegex(format, customRegex string) (*Parser, error) {
	var pattern string
	normalizedFormat := normalizeFormat(format)

	if customRegex != "" {
		compiled, err := regexp.Compile(customRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid custom regex: %w", err)
		}

		return &Parser{
			format: normalizedFormat,
			regex:  compiled,
		}, nil
	}

	switch normalizedFormat {
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
		normalizedFormat = "nginx_combined"
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile parser regex: %w", err)
	}

	return &Parser{
		format: normalizedFormat,
		regex:  compiled,
	}, nil
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
	payload := map[string]interface{}{}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		return nil, fmt.Errorf("failed to parse JSON log line: %w", err)
	}

	entry := &LogEntry{
		Headers: make(map[string]string),
		Tags:    []string{},
	}

	entry.IP = normalizeIP(getStringField(payload, "ip", "remote_addr", "client_ip", "source_ip"))
	if entry.IP == "" {
		return nil, fmt.Errorf("json log line missing client IP")
	}

	timeValue := getStringField(payload, "timestamp", "time", "time_local")
	if timeValue == "" {
		entry.Timestamp = time.Now()
	} else {
		timestamp, err := parseTimestamp(timeValue)
		if err != nil {
			return nil, fmt.Errorf("failed to parse json timestamp: %w", err)
		}
		entry.Timestamp = timestamp
	}

	requestLine := getStringField(payload, "request")
	entry.Method = getStringField(payload, "method", "request_method")
	entry.Path = getStringField(payload, "path", "request_uri", "uri")
	entry.QueryString = getStringField(payload, "query_string", "query")
	entry.Protocol = getStringField(payload, "protocol", "server_protocol")

	if requestLine != "" && (entry.Method == "" || entry.Path == "" || entry.Protocol == "") {
		parsedMethod, parsedPath, parsedProtocol := parseRequestLine(requestLine)
		if entry.Method == "" {
			entry.Method = parsedMethod
		}
		if entry.Path == "" {
			entry.Path = parsedPath
		}
		if entry.Protocol == "" {
			entry.Protocol = parsedProtocol
		}
	}

	if strings.Contains(entry.Path, "?") && entry.QueryString == "" {
		parts := strings.SplitN(entry.Path, "?", 2)
		entry.Path = parts[0]
		entry.QueryString = parts[1]
	}

	entry.ResponseCode = getIntField(payload, "status", "response_code")
	entry.ResponseSize = getIntField(payload, "body_bytes_sent", "response_size", "bytes_sent")
	entry.Referer = getStringField(payload, "referer", "http_referer")
	entry.UserAgent = getStringField(payload, "user_agent", "http_user_agent")
	entry.RequestTime = getFloatField(payload, "request_time")
	entry.Host = getStringField(payload, "host", "server_name")
	entry.XForwardedFor = getStringField(payload, "x_forwarded_for")

	if headersObj, ok := payload["headers"].(map[string]interface{}); ok {
		for key, val := range headersObj {
			entry.Headers[key] = fmt.Sprintf("%v", val)
		}
	}

	if entry.XForwardedFor == "" {
		entry.XForwardedFor = getStringFieldFromMap(entry.Headers, "X-Forwarded-For")
	}

	entry.IsBot = isBot(entry.UserAgent)

	return entry, nil
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

func normalizeFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "combined", "nginx", "nginx_combined":
		return "nginx_combined"
	case "extended", "nginx_extended":
		return "nginx_extended"
	case "apache", "apache_combined":
		return "apache_combined"
	case "json":
		return "json"
	default:
		return "nginx_combined"
	}
}

func getStringField(payload map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			switch v := value.(type) {
			case string:
				if strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			default:
				str := strings.TrimSpace(fmt.Sprintf("%v", v))
				if str != "" {
					return str
				}
			}
		}
	}

	return ""
}

func getStringFieldFromMap(values map[string]string, key string) string {
	for mapKey, value := range values {
		if strings.EqualFold(mapKey, key) {
			return strings.TrimSpace(value)
		}
	}

	return ""
}

func getIntField(payload map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			switch v := value.(type) {
			case int:
				return v
			case int32:
				return int(v)
			case int64:
				return int(v)
			case float64:
				return int(v)
			case string:
				parsed, err := strconv.Atoi(v)
				if err == nil {
					return parsed
				}
			}
		}
	}

	return 0
}

func getFloatField(payload map[string]interface{}, keys ...string) float64 {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			switch v := value.(type) {
			case float64:
				return v
			case float32:
				return float64(v)
			case int:
				return float64(v)
			case int64:
				return float64(v)
			case string:
				parsed, err := strconv.ParseFloat(v, 64)
				if err == nil {
					return parsed
				}
			}
		}
	}

	return 0.0
}

func parseRequestLine(requestLine string) (string, string, string) {
	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return "", "", ""
	}

	return parts[0], parts[1], parts[2]
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
