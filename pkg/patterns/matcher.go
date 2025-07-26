package patterns

import (
	"regexp"
	"strings"
)

// ThreatPattern represents a suspicious pattern
type ThreatPattern struct {
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	Regex       *regexp.Regexp
	Severity    int      `json:"severity"`
	Categories  []string `json:"categories"`
	Description string   `json:"description"`
}

// Matcher handles pattern matching for threat detection
type Matcher struct {
	patterns []ThreatPattern
}

// NewMatcher creates a new pattern matcher
func NewMatcher(customPatterns []string) *Matcher {
	matcher := &Matcher{}
	
	// Load default patterns
	matcher.loadDefaultPatterns()
	
	// Add custom patterns
	for _, pattern := range customPatterns {
		matcher.AddPattern(ThreatPattern{
			Name:     "custom",
			Pattern:  pattern,
			Regex:    regexp.MustCompile(pattern),
			Severity: 5,
		})
	}
	
	return matcher
}

// loadDefaultPatterns loads built-in threat patterns
func (m *Matcher) loadDefaultPatterns() {
	defaultPatterns := []ThreatPattern{
		// SQL Injection patterns
		{
			Name:        "sql_injection_union",
			Pattern:     `(?i)(union.*select|select.*union)`,
			Severity:    10,
			Categories:  []string{"sql_injection", "attack"},
			Description: "SQL injection using UNION SELECT",
		},
		{
			Name:        "sql_injection_basic",
			Pattern:     `(?i)('|(\\x27)|(\\x2D\\x2D)|(%27)|(%2D%2D))`,
			Severity:    8,
			Categories:  []string{"sql_injection", "attack"},
			Description: "Basic SQL injection attempt",
		},
		
		// XSS patterns
		{
			Name:        "xss_script",
			Pattern:     `(?i)<script[^>]*>.*?</script>`,
			Severity:    9,
			Categories:  []string{"xss", "attack"},
			Description: "Cross-site scripting attempt",
		},
		{
			Name:        "xss_javascript",
			Pattern:     `(?i)javascript:`,
			Severity:    7,
			Categories:  []string{"xss", "attack"},
			Description: "JavaScript injection attempt",
		},
		
		// Directory traversal
		{
			Name:        "dir_traversal",
			Pattern:     `(\.\./)|(\.\.\\)`,
			Severity:    8,
			Categories:  []string{"directory_traversal", "attack"},
			Description: "Directory traversal attempt",
		},
		{
			Name:        "dir_traversal_encoded",
			Pattern:     `(%2e%2e%2f)|(%2e%2e%5c)`,
			Severity:    8,
			Categories:  []string{"directory_traversal", "attack"},
			Description: "Encoded directory traversal attempt",
		},
		
		// Command injection
		{
			Name:        "cmd_injection",
			Pattern:     `(?i)(;|\||&amp;|&)(\\s)*(ls|pwd|id|whoami|cat|nc|curl|wget)`,
			Severity:    10,
			Categories:  []string{"command_injection", "attack"},
			Description: "Command injection attempt",
		},
		
		// File inclusion
		{
			Name:        "file_inclusion",
			Pattern:     `(?i)(include|require)(_once)?\\s*\\([^)]*\\.(php|asp|jsp)`,
			Severity:    9,
			Categories:  []string{"file_inclusion", "attack"},
			Description: "File inclusion attempt",
		},
		
		// Admin panel scanning
		{
			Name:        "admin_scan",
			Pattern:     `(?i)/(admin|administrator|wp-admin|phpmyadmin|cpanel)`,
			Severity:    5,
			Categories:  []string{"scanning", "reconnaissance"},
			Description: "Admin panel scanning",
		},
		
		// Web shell patterns
		{
			Name:        "web_shell",
			Pattern:     `(?i)\\.(php|asp|aspx|jsp)\\?.*=(system|exec|shell_exec|passthru)`,
			Severity:    10,
			Categories:  []string{"web_shell", "attack"},
			Description: "Web shell execution attempt",
		},
		
		// Sensitive file access
		{
			Name:        "sensitive_files",
			Pattern:     `(?i)/(etc/passwd|etc/shadow|web\\.config|\\.htaccess|wp-config\\.php)`,
			Severity:    8,
			Categories:  []string{"information_disclosure", "attack"},
			Description: "Sensitive file access attempt",
		},
		
		// WordPress specific attacks
		{
			Name:        "wp_attacks",
			Pattern:     `(?i)/wp-(admin|includes|content).*\\.(php|asp|jsp)`,
			Severity:    6,
			Categories:  []string{"wordpress", "attack"},
			Description: "WordPress attack attempt",
		},
		
		// Brute force indicators
		{
			Name:        "brute_force",
			Pattern:     `(?i)/(login|signin|auth|admin).*password`,
			Severity:    6,
			Categories:  []string{"brute_force", "attack"},
			Description: "Potential brute force attempt",
		},
		
		// Scanner user agents
		{
			Name:        "scanner_ua",
			Pattern:     `(?i)(nmap|nikto|sqlmap|dirbuster|gobuster|hydra|burp|nessus)`,
			Severity:    8,
			Categories:  []string{"scanning", "tool"},
			Description: "Security scanner user agent",
		},
		
		// Suspicious file extensions
		{
			Name:        "suspicious_extensions",
			Pattern:     `\\.(bak|old|tmp|log|config|conf|backup|swp|~)$`,
			Severity:    4,
			Categories:  []string{"information_disclosure"},
			Description: "Access to backup/temporary files",
		},
	}
	
	// Compile regex patterns
	for i := range defaultPatterns {
		defaultPatterns[i].Regex = regexp.MustCompile(defaultPatterns[i].Pattern)
	}
	
	m.patterns = defaultPatterns
}

// AddPattern adds a new pattern to the matcher
func (m *Matcher) AddPattern(pattern ThreatPattern) {
	if pattern.Regex == nil {
		pattern.Regex = regexp.MustCompile(pattern.Pattern)
	}
	m.patterns = append(m.patterns, pattern)
}

// CheckPatterns checks multiple inputs against all patterns
func (m *Matcher) CheckPatterns(path, queryString, userAgent string) []string {
	var matches []string
	
	inputs := []string{path, queryString, userAgent}
	
	for _, pattern := range m.patterns {
		for _, input := range inputs {
			if pattern.Regex.MatchString(input) {
				matches = append(matches, pattern.Name)
				break // Don't count the same pattern multiple times
			}
		}
	}
	
	return matches
}

// CheckSinglePattern checks a single input against all patterns
func (m *Matcher) CheckSinglePattern(input string) []ThreatPattern {
	var matches []ThreatPattern
	
	for _, pattern := range m.patterns {
		if pattern.Regex.MatchString(input) {
			matches = append(matches, pattern)
		}
	}
	
	return matches
}

// GetPatternByName retrieves a pattern by name
func (m *Matcher) GetPatternByName(name string) *ThreatPattern {
	for _, pattern := range m.patterns {
		if pattern.Name == name {
			return &pattern
		}
	}
	return nil
}

// GetPatternsByCategory retrieves patterns by category
func (m *Matcher) GetPatternsByCategory(category string) []ThreatPattern {
	var matches []ThreatPattern
	
	for _, pattern := range m.patterns {
		for _, cat := range pattern.Categories {
			if strings.EqualFold(cat, category) {
				matches = append(matches, pattern)
				break
			}
		}
	}
	
	return matches
}

// GetAllPatterns returns all loaded patterns
func (m *Matcher) GetAllPatterns() []ThreatPattern {
	return m.patterns
}
