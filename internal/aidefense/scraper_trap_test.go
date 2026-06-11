package aidefense

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckUserAgentKnownScrapers(t *testing.T) {
	st := NewScraperTrap()

	cases := []struct {
		ua   string
		want bool
		name string
	}{
		{"Mozilla/5.0 GPTBot/1.0", true, "OpenAI GPTBot"},
		{"ClaudeBot/1.0", true, "Anthropic ClaudeBot"},
		{"PerplexityBot/1.0", true, "Perplexity AI"},
		{"CCBot/2.0 (https://commoncrawl.org/faq/)", true, "Common Crawl CCBot"},
		{"Bytespider", true, "ByteDance Bytespider"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", false, ""},
		{"curl/7.88.0", false, ""},
	}

	for _, tc := range cases {
		matched, name := st.CheckUserAgent(tc.ua)
		if matched != tc.want {
			t.Errorf("CheckUserAgent(%q) matched=%v want=%v", tc.ua, matched, tc.want)
		}
		if tc.want && name != tc.name {
			t.Errorf("CheckUserAgent(%q) name=%q want=%q", tc.ua, name, tc.name)
		}
	}
}

func TestCanaryPathDetection(t *testing.T) {
	st := NewScraperTrap()

	cases := []struct {
		path string
		want bool
	}{
		{"/.well-known/ai-canary/probe", true},
		{"/.well-known/llm-training/data.json", true},
		{"/api/v0/internal/stats", true},
		{"/", false},
		{"/about", false},
		{"/api/v1/products", false},
	}

	for _, tc := range cases {
		if got := st.IsCanaryPath(tc.path); got != tc.want {
			t.Errorf("IsCanaryPath(%q) = %v want %v", tc.path, got, tc.want)
		}
	}
}

func TestCanaryHitBlocking(t *testing.T) {
	st := NewScraperTrap()

	if st.IsBlocked("1.2.3.4") {
		t.Fatal("IP should not be blocked before any canary hit")
	}

	st.RecordCanaryHit("1.2.3.4", "/.well-known/ai-canary/")

	if !st.IsBlocked("1.2.3.4") {
		t.Fatal("IP should be blocked after canary hit")
	}
	if st.BlockedCount() != 1 {
		t.Fatalf("expected 1 blocked IP, got %d", st.BlockedCount())
	}
}

func TestRobotsTxtContent(t *testing.T) {
	st := NewScraperTrap()
	handler := st.RobotsTxtHandler()

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()

	// Must block known AI scrapers
	if !strings.Contains(body, "GPTBot") {
		t.Error("robots.txt must include GPTBot rule")
	}
	if !strings.Contains(body, "ClaudeBot") {
		t.Error("robots.txt must include ClaudeBot rule")
	}
	if !strings.Contains(body, "PerplexityBot") {
		t.Error("robots.txt must include PerplexityBot rule")
	}

	// Must disallow canary paths
	if !strings.Contains(body, "/.well-known/ai-canary/") {
		t.Error("robots.txt must disallow canary paths")
	}
}

func TestMiddlewareBlocksKnownScraper(t *testing.T) {
	st := NewScraperTrap()
	mw := st.Middleware(nil)

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/about", nil)
	req.Header.Set("User-Agent", "GPTBot/1.0")
	rec := httptest.NewRecorder()

	mw(inner).ServeHTTP(rec, req)

	if called {
		t.Error("inner handler should not be called for known AI scraper")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for AI scraper, got %d", rec.Code)
	}
}

func TestMiddlewareTrapsCanaryHit(t *testing.T) {
	st := NewScraperTrap()
	mw := st.Middleware(nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request: hits a canary path (should get fake 200 content)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/ai-canary/probe", nil)
	req.RemoteAddr = "10.0.0.1:55000"
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	// Canary response looks like a 200 (to fool the scraper) but with fake data
	if rec.Code != http.StatusOK {
		t.Errorf("expected canary 200, got %d", rec.Code)
	}

	// Second request from same IP on a normal path should also be blocked
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.1:55001"
	rec2 := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("blocked canary IP got %d want 200 (fake response)", rec2.Code)
	}
	if !st.IsBlocked("10.0.0.1") {
		t.Error("IP that hit canary should be flagged as blocked")
	}
}

func TestMiddlewarePassesThroughNormalRequests(t *testing.T) {
	st := NewScraperTrap()
	mw := st.Middleware(nil)

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/products", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.RemoteAddr = "8.8.8.8:12345"
	rec := httptest.NewRecorder()

	mw(inner).ServeHTTP(rec, req)

	if !called {
		t.Error("legitimate request should reach inner handler")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for normal request, got %d", rec.Code)
	}
}
