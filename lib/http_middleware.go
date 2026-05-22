package defender

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	defaultHTTPBlockDuration = time.Hour
	defaultHTTPBlockScore    = 50
)

// AnalyzeHTTPRequest scores a single HTTP request for bot-like behavior.
func (d *Defender) AnalyzeHTTPRequest(r *http.Request) (int, []string) {
	if r == nil {
		return 0, nil
	}

	score := 0
	reasons := make([]string, 0, 4)

	userAgent := strings.TrimSpace(r.UserAgent())
	lowerUA := strings.ToLower(userAgent)

	if userAgent == "" {
		score += 20
		reasons = append(reasons, "missing_user_agent")
	}

	if automationLabel := classifyAutomationUserAgent(lowerUA); automationLabel != "" {
		score += 40
		reasons = append(reasons, automationLabel)
	}

	if isClearlyBotLike(lowerUA) {
		score += 20
		reasons = append(reasons, "bot_keyword")
	}

	if r.Header.Get("Accept-Language") == "" {
		score += 8
		reasons = append(reasons, "missing_accept_language")
	}

	if r.Header.Get("Accept") == "" {
		score += 5
		reasons = append(reasons, "missing_accept_header")
	}

	if r.Header.Get("Referer") == "" && r.URL != nil && r.URL.Path != "/" {
		score += 5
		reasons = append(reasons, "missing_referer")
	}

	if r.Header.Get("Sec-Ch-Ua") == "" && strings.Contains(lowerUA, "chrome") {
		score += 5
		reasons = append(reasons, "missing_client_hints")
	}

	if r.Method == http.MethodHead || r.Method == http.MethodOptions {
		score -= 5
	}

	if score < 0 {
		score = 0
	}

	return score, uniqueStrings(reasons)
}

// HTTPMiddleware returns a plug-and-play net/http middleware that blocks
// obvious bots and surfaces a per-request bot score via response headers.
func (d *Defender) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if next == nil {
				return
			}

			clientIP := extractClientIPFromRequest(r)
			if clientIP != "" && d.ShouldBlock(clientIP) {
				http.Error(w, "Access Denied - Blocked by nginx-defender", http.StatusForbidden)
				return
			}

			score, reasons := d.AnalyzeHTTPRequest(r)
			w.Header().Set("X-Protected-By", "nginx-defender")
			w.Header().Set("X-Bot-Score", fmt.Sprintf("%d", score))
			if len(reasons) > 0 {
				w.Header().Set("X-Bot-Reasons", strings.Join(reasons, ","))
			}

			if score >= defaultHTTPBlockScore {
				if clientIP != "" && net.ParseIP(clientIP) != nil {
					_ = d.BlockIP(clientIP, defaultHTTPBlockDuration, "HTTP middleware bot detection: "+strings.Join(reasons, ","))
				}
				http.Error(w, "Access Denied - Bot-like traffic blocked", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func extractClientIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return strings.TrimSpace(r.RemoteAddr)
}

func classifyAutomationUserAgent(lowerUA string) string {
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

func isClearlyBotLike(lowerUA string) bool {
	patterns := []string{"bot", "crawler", "spider", "scraper", "monitoring", "scan", "benchmark", "headless"}
	for _, pattern := range patterns {
		if strings.Contains(lowerUA, pattern) {
			return true
		}
	}

	return len(strings.TrimSpace(lowerUA)) > 0 && len(strings.TrimSpace(lowerUA)) < 12
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	return result
}