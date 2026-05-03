package behavior

import (
	"testing"
	"time"

	"github.com/Anipaleja/nginx-defender/pkg/logparser"
)

func TestProfilerDetectsBurstAndStuffing(t *testing.T) {
	p := NewProfiler(100, 10*time.Minute)
	now := time.Now()
	var signals ProfileSignals
	for i := 0; i < 30; i++ {
		entry := &logparser.LogEntry{
			IP:           "1.2.3.4",
			Timestamp:    now.Add(time.Duration(i) * 100 * time.Millisecond),
			Path:         "/login",
			QueryString:  "u=a",
			ResponseCode: 401,
			UserAgent:    "bad-bot/1.0",
		}
		_, signals = p.Observe("1.2.3.4", entry)
	}

	if signals.BurstScore <= 0 {
		t.Fatalf("expected burst score > 0, got %.3f", signals.BurstScore)
	}
	if signals.CredentialStuffing <= 0 {
		t.Fatalf("expected credential stuffing score > 0, got %.3f", signals.CredentialStuffing)
	}
}
