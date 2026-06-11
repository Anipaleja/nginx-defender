package defender

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnalyzeHTTPRequestFlagsAutomationClients(t *testing.T) {
	def, err := New(DevelopmentConfig())
	if err != nil {
		t.Fatalf("failed to create defender: %v", err)
	}
	defer def.Close()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/private", nil)
	req.Header.Set("User-Agent", "curl/8.1.0")

	score, reasons := def.AnalyzeHTTPRequest(req)
	if score < defaultHTTPBlockScore {
		t.Fatalf("expected automation request to score at least %d, got %d", defaultHTTPBlockScore, score)
	}

	if len(reasons) == 0 {
		t.Fatal("expected bot reasons to be reported")
	}

	foundAutomation := false
	for _, reason := range reasons {
		if reason == "automation_client" || reason == "bot_keyword" || reason == "curl" {
			foundAutomation = true
			break
		}
	}
	if !foundAutomation {
		t.Fatalf("expected automation-related reason, got %v", reasons)
	}
}

func TestHTTPMiddlewareBlocksBotRequests(t *testing.T) {
	// httptest.NewRequest sets RemoteAddr to "192.0.2.1:1234". Configure that
	// subnet as a trusted proxy so XFF is honoured and the real client IP
	// (203.0.113.1) is extracted and blocked.
	cfg := DevelopmentConfig()
	cfg.TrustedProxyCIDRs = []string{"192.0.2.0/24"}

	def, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create defender: %v", err)
	}
	defer def.Close()

	if err := def.Start(); err != nil {
		t.Fatalf("failed to start defender: %v", err)
	}

	handler := def.HTTPMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/private", nil)
	req.Header.Set("User-Agent", "HeadlessChrome/124.0.0.0")
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected middleware to block request with 403, got %d", rec.Code)
	}

	if got := rec.Header().Get("X-Bot-Score"); got == "" {
		t.Fatal("expected bot score header to be set")
	}

	if !def.ShouldBlock("203.0.113.1") {
		t.Fatal("expected blocked IP to remain blocked after middleware enforcement")
	}
}

func TestHTTPMiddlewareAllowsNormalRequests(t *testing.T) {
	def, err := New(DevelopmentConfig())
	if err != nil {
		t.Fatalf("failed to create defender: %v", err)
	}
	defer def.Close()

	if err := def.Start(); err != nil {
		t.Fatalf("failed to start defender: %v", err)
	}

	handler := def.HTTPMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected request to pass through, got status %d", rec.Code)
	}

	if body := strings.TrimSpace(rec.Body.String()); body != "ok" {
		t.Fatalf("expected handler body to be returned, got %q", body)
	}
}