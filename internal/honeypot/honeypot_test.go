package honeypot

import (
	"context"
	"testing"

	"github.com/Anipaleja/nginx-defender/internal/types"
	"github.com/sirupsen/logrus"
)

func TestSecondHoneypotSystemDeployAndProcessInteraction(t *testing.T) {
	system, err := SecondHoneypotSystem(&HoneypotConfig{}, logrus.New())
	if err != nil {
		t.Fatalf("unexpected init error: %v", err)
	}

	honeypot, err := system.DeployHoneypotSys(context.Background(), &HoneypotRequests{Name: "ssh-trap", Type: "ssh"})
	if err != nil {
		t.Fatalf("unexpected deploy error: %v", err)
	}
	if honeypot.ID == "" {
		t.Fatal("expected a honeypot ID")
	}
	if honeypot.Status != "active" {
		t.Fatalf("expected active status, got %q", honeypot.Status)
	}

	response, err := system.ProcessInteractions(context.Background(), &types.HoneypotInteraction{ID: "interaction-1"})
	if err != nil {
		t.Fatalf("unexpected process error: %v", err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("unexpected status code: %d", response.StatusCode)
	}
	if response.ProcessingTime < 0 {
		t.Fatalf("expected non-negative processing time, got %s", response.ProcessingTime)
	}
	if system.stats.TotalInteractions != 1 {
		t.Fatalf("expected interaction count to increment, got %d", system.stats.TotalInteractions)
	}
}

func TestGenDeceptionContentUsesRequestData(t *testing.T) {
	system, err := SecondHoneypotSystem(&HoneypotConfig{Enabled: true}, logrus.New())
	if err != nil {
		t.Fatalf("unexpected init error: %v", err)
	}

	content, err := system.GenDeceptionContent(context.Background(), &DeceptionContentRequests{
		Target:   "ssh",
		Scenario: "brute-force",
		Protocol: "tcp",
		Seed:     "abc123",
	})
	if err != nil {
		t.Fatalf("unexpected content error: %v", err)
	}
	if content.Content == "" {
		t.Fatal("expected generated content")
	}
	if content.Content == "placeholder deception content" {
		t.Fatal("expected non-placeholder content")
	}
}
