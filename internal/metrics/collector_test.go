package metrics

import (
	"testing"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/sirupsen/logrus"
)

func TestCollectorSummariesIncludeBotBlocks(t *testing.T) {
	collector := NewCollector(config.MetricsConfig{}, logrus.New())

	collector.RecordThreat("bot_attack", "high", "TARPIT", 88.0, "US")
	collector.RecordIPBlocked("threat_type:bot_attack", "TARPIT", "US")

	stats := collector.GetStats()
	summary, ok := stats["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("summary missing from metrics stats")
	}

	if summary["total_bots_blocked"].(uint64) != 1 {
		t.Fatalf("expected 1 bot blocked, got %v", summary["total_bots_blocked"])
	}

	blockedByType, ok := stats["blocked_by_threat_type"].(map[string]uint64)
	if !ok {
		t.Fatalf("blocked_by_threat_type missing from stats")
	}

	if blockedByType["bot"] != 1 {
		t.Fatalf("expected blocked bot threat count of 1, got %d", blockedByType["bot"])
	}
}

func TestCollectorSummariesIncludeAttackTypes(t *testing.T) {
	collector := NewCollector(config.MetricsConfig{}, logrus.New())

	collector.RecordThreat("sql_injection", "critical", "BLOCK_IMMEDIATE", 95.0, "GB")
	collector.RecordIPBlocked("threat_type:sql_injection", "BLOCK", "GB")

	stats := collector.GetStats()
	blockedByType, ok := stats["blocked_by_threat_type"].(map[string]uint64)
	if !ok {
		t.Fatalf("blocked_by_threat_type missing from stats")
	}

	if blockedByType["sql_injection"] != 1 {
		t.Fatalf("expected sql_injection block count of 1, got %d", blockedByType["sql_injection"])
	}
}
