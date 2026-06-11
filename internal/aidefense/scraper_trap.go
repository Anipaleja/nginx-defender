// Package aidefense provides active defense against AI scrapers and
// automated crawlers through canary traps, robots.txt poisoning, and
// user-agent fingerprinting.
package aidefense

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// knownAIScrapers maps lower-cased user-agent substrings to human-readable
// names. Entries are checked in order; first match wins.
var knownAIScrapers = []struct {
	pattern string
	name    string
}{
	// OpenAI
	{"gptbot", "OpenAI GPTBot"},
	{"chatgpt-user", "OpenAI ChatGPT"},
	{"oai-searchbot", "OpenAI SearchBot"},
	// Anthropic
	{"claudebot", "Anthropic ClaudeBot"},
	{"claude-web", "Anthropic Claude-Web"},
	{"anthropic-ai", "Anthropic"},
	// Google AI
	{"google-extended", "Google Bard/Gemini"},
	// Meta
	{"meta-externalagent", "Meta AI"},
	{"facebookbot", "Meta FacebookBot"},
	// Perplexity
	{"perplexitybot", "Perplexity AI"},
	// Cohere
	{"cohere-ai", "Cohere AI"},
	// Apple
	{"applebot-extended", "Apple AI"},
	// ByteDance / TikTok
	{"bytespider", "ByteDance Bytespider"},
	// Common Crawl (used heavily to train LLMs)
	{"ccbot", "Common Crawl CCBot"},
	// You.com
	{"youbot", "You.com"},
	// Diffbot
	{"diffbot", "Diffbot"},
	// Imagesift
	{"imagesiftbot", "Imagesift"},
	// Omgili
	{"omgilibot", "Omgili"},
	{"omgili", "Omgili"},
	// PetalBot (Huawei)
	{"petalbot", "Huawei PetalBot"},
	// Scrapy / generic LLM training crawlers
	{"scrapy", "Scrapy"},
	{"ai2bot", "Allen Institute AI2Bot"},
	{"timpibot", "Timpi"},
	{"friendlycrawler", "FriendlyCrawler"},
	{"icc-crawler", "ICC Crawler"},
	{"dataprovider.com", "DataProvider"},
}

// canaryEntry records when an IP hit a canary path.
type canaryEntry struct {
	path      string
	hitAt     time.Time
	expiresAt time.Time
}

// ScraperTrap implements AI scraper detection via:
//  1. A curated user-agent blocklist for known AI crawlers.
//  2. Canary paths advertised in robots.txt as Disallow; any hit on these
//     paths is treated as proof that the client is ignoring robots.txt.
type ScraperTrap struct {
	canaryPaths   []string
	blockDuration time.Duration

	mu       sync.RWMutex
	hitsByIP map[string]*canaryEntry // IP → first canary hit
}

// Option configures a ScraperTrap.
type Option func(*ScraperTrap)

// WithCanaryPaths sets the honeypot paths listed in robots.txt as Disallow.
// Defaults are used if this option is not supplied.
func WithCanaryPaths(paths []string) Option {
	return func(st *ScraperTrap) {
		st.canaryPaths = paths
	}
}

// WithBlockDuration sets how long IPs remain blocked after a canary hit.
// Default: 24 hours.
func WithBlockDuration(d time.Duration) Option {
	return func(st *ScraperTrap) {
		st.blockDuration = d
	}
}

// NewScraperTrap creates a ready-to-use ScraperTrap.
func NewScraperTrap(opts ...Option) *ScraperTrap {
	st := &ScraperTrap{
		blockDuration: 24 * time.Hour,
		hitsByIP:      make(map[string]*canaryEntry),
		canaryPaths: []string{
			"/.well-known/ai-canary/",
			"/.well-known/llm-training/",
			"/api/v0/internal/",
			"/internal/training-data/",
			"/_scraper-trap/",
			"/data/corpus/",
		},
	}
	for _, opt := range opts {
		opt(st)
	}
	return st
}

// CheckUserAgent returns (true, name) when the user-agent belongs to a known
// AI scraper, or (false, "") otherwise. The check is case-insensitive.
func (st *ScraperTrap) CheckUserAgent(ua string) (bool, string) {
	lower := strings.ToLower(ua)
	for _, entry := range knownAIScrapers {
		if strings.Contains(lower, entry.pattern) {
			return true, entry.name
		}
	}
	return false, ""
}

// IsCanaryPath reports whether path matches one of the registered canary paths.
func (st *ScraperTrap) IsCanaryPath(path string) bool {
	lower := strings.ToLower(path)
	for _, cp := range st.canaryPaths {
		if strings.HasPrefix(lower, strings.ToLower(cp)) {
			return true
		}
	}
	return false
}

// RecordCanaryHit marks ip as having visited a canary path.
func (st *ScraperTrap) RecordCanaryHit(ip, path string) {
	now := time.Now()
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, exists := st.hitsByIP[ip]; !exists {
		st.hitsByIP[ip] = &canaryEntry{
			path:      path,
			hitAt:     now,
			expiresAt: now.Add(st.blockDuration),
		}
	}
}

// IsBlocked returns true if ip previously hit a canary path and the block
// has not yet expired.
func (st *ScraperTrap) IsBlocked(ip string) bool {
	st.mu.RLock()
	entry, exists := st.hitsByIP[ip]
	st.mu.RUnlock()
	if !exists {
		return false
	}
	if time.Now().After(entry.expiresAt) {
		st.mu.Lock()
		delete(st.hitsByIP, ip)
		st.mu.Unlock()
		return false
	}
	return true
}

// BlockedCount returns the number of IPs currently blocked due to canary hits.
func (st *ScraperTrap) BlockedCount() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	now := time.Now()
	count := 0
	for _, e := range st.hitsByIP {
		if now.Before(e.expiresAt) {
			count++
		}
	}
	return count
}

// RobotsTxtHandler returns an http.HandlerFunc that serves a robots.txt file
// which:
//   - Disallows all paths for known AI scrapers (by User-agent name).
//   - Disallows the canary paths for all bots.
//
// Deploy this at exactly GET /robots.txt in your application.
func (st *ScraperTrap) RobotsTxtHandler() http.HandlerFunc {
	body := st.buildRobotsTxt()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fmt.Fprint(w, body)
	}
}

func (st *ScraperTrap) buildRobotsTxt() string {
	var sb strings.Builder

	// Per-bot blocks for every known AI scraper
	seen := make(map[string]bool)
	for _, e := range knownAIScrapers {
		// Derive the User-agent name from the pattern (capitalise first char)
		agent := toUserAgentName(e.pattern)
		if seen[agent] {
			continue
		}
		seen[agent] = true
		fmt.Fprintf(&sb, "User-agent: %s\nDisallow: /\n\n", agent)
	}

	// General rules for all bots: disallow canary paths
	sb.WriteString("User-agent: *\n")
	for _, cp := range st.canaryPaths {
		fmt.Fprintf(&sb, "Disallow: %s\n", cp)
	}
	sb.WriteString("\n")

	return sb.String()
}

// toUserAgentName converts a lowercase pattern like "gptbot" to "GPTBot".
// For known patterns we use the canonical casing; otherwise we title-case.
var agentCanonical = map[string]string{
	"gptbot":             "GPTBot",
	"chatgpt-user":       "ChatGPT-User",
	"oai-searchbot":      "OAI-SearchBot",
	"claudebot":          "ClaudeBot",
	"claude-web":         "Claude-Web",
	"anthropic-ai":       "anthropic-ai",
	"google-extended":    "Google-Extended",
	"meta-externalagent": "Meta-ExternalAgent",
	"facebookbot":        "FacebookBot",
	"perplexitybot":      "PerplexityBot",
	"cohere-ai":          "cohere-ai",
	"applebot-extended":  "Applebot-Extended",
	"bytespider":         "Bytespider",
	"ccbot":              "CCBot",
	"youbot":             "YouBot",
	"diffbot":            "Diffbot",
	"imagesiftbot":       "ImagesiftBot",
	"omgilibot":          "omgilibot",
	"omgili":             "omgili",
	"petalbot":           "PetalBot",
	"scrapy":             "Scrapy",
	"ai2bot":             "AI2Bot",
	"timpibot":           "Timpibot",
	"friendlycrawler":    "FriendlyCrawler",
	"icc-crawler":        "ICC-Crawler",
	"dataprovider.com":   "DataProvider.com",
}

func toUserAgentName(pattern string) string {
	if canonical, ok := agentCanonical[pattern]; ok {
		return canonical
	}
	return strings.Title(pattern) //nolint:staticcheck
}

// Middleware returns HTTP middleware that:
//  1. Blocks IPs that previously hit a canary path.
//  2. Blocks requests to canary paths (recording the hit first).
//  3. Blocks requests whose User-Agent matches a known AI scraper.
//
// Use it as the outermost middleware layer so scrapers never reach your app.
func (st *ScraperTrap) Middleware(clientIP func(*http.Request) string) func(http.Handler) http.Handler {
	if clientIP == nil {
		clientIP = defaultClientIP
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)

			// 1. Previously-flagged canary hitter
			if ip != "" && st.IsBlocked(ip) {
				serveCanaryResponse(w, r)
				return
			}

			// 2. Current request targets a canary path
			if st.IsCanaryPath(r.URL.Path) {
				if ip != "" {
					st.RecordCanaryHit(ip, r.URL.Path)
				}
				serveCanaryResponse(w, r)
				return
			}

			// 3. Known AI scraper user-agent
			if matched, _ := st.CheckUserAgent(r.UserAgent()); matched {
				http.Error(w, "Access denied.", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// serveCanaryResponse returns fake-looking content to waste the scraper's
// time rather than a plain 403, making it harder to detect the trap.
func serveCanaryResponse(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok","data":[],"page":1,"total":0}`)
}

func defaultClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
