package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/internal/detector"
	"github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/slack-go/slack"
	"github.com/sirupsen/logrus"
)

// Event represents a notification event
type Event struct {
	Type        string                 `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	IP          string                 `json:"ip"`
	Action      string                 `json:"action"`
	Reason      string                 `json:"reason"`
	ThreatLevel string                 `json:"threat_level"`
	Details     map[string]interface{} `json:"details"`
	Location    *LocationInfo          `json:"location,omitempty"`
}

// LocationInfo contains geographic information
type LocationInfo struct {
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
}

// Manager handles all notification channels
type Manager struct {
	config         config.NotificationsConfig
	logger         *logrus.Logger
	telegramBot    *tgbotapi.BotAPI
	slackClient    *slack.Client
	httpClient     *http.Client
	eventChan      chan Event
	stopChan       chan struct{}
}

// NewManager creates a new notification manager
func NewManager(cfg config.NotificationsConfig, logger *logrus.Logger) (*Manager, error) {
	manager := &Manager{
		config:     cfg,
		logger:     logger,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		eventChan:  make(chan Event, 1000),
		stopChan:   make(chan struct{}),
	}
	
	// Initialize Telegram bot
	if cfg.Telegram.Enabled && cfg.Telegram.BotToken != "" {
		bot, err := tgbotapi.NewBotAPI(cfg.Telegram.BotToken)
		if err != nil {
			logger.WithError(err).Warn("Failed to initialize Telegram bot")
		} else {
			manager.telegramBot = bot
			logger.Info("Telegram notifications enabled")
		}
	}
	
	// Initialize Slack client
	if cfg.Slack.Enabled && cfg.Slack.WebhookURL != "" {
		manager.slackClient = slack.New("")
		logger.Info("Slack notifications enabled")
	}
	
	// Start event processor
	go manager.processEvents()
	
	return manager, nil
}

// SendThreatDetected sends a threat detection notification
func (m *Manager) SendThreatDetected(result *detector.DetectionResult, location *LocationInfo) {
	event := Event{
		Type:        "threat_detected",
		Timestamp:   time.Now(),
		IP:          result.IP,
		Action:      result.RecommendedAction,
		Reason:      fmt.Sprintf("Threat types: %v", result.ThreatTypes),
		ThreatLevel: m.getThreatLevelString(result.ThreatLevel),
		Details: map[string]interface{}{
			"score":         result.Score,
			"threat_types":  result.ThreatTypes,
			"details":       result.Details,
		},
		Location: location,
	}
	
	select {
	case m.eventChan <- event:
	default:
		m.logger.Warn("Notification queue is full, dropping event")
	}
}

// SendIPBlocked sends an IP blocked notification
func (m *Manager) SendIPBlocked(ip, reason, action string, duration time.Duration, location *LocationInfo) {
	event := Event{
		Type:        "ip_blocked",
		Timestamp:   time.Now(),
		IP:          ip,
		Action:      action,
		Reason:      reason,
		ThreatLevel: "medium",
		Details: map[string]interface{}{
			"duration": duration.String(),
		},
		Location: location,
	}
	
	select {
	case m.eventChan <- event:
	default:
		m.logger.Warn("Notification queue is full, dropping event")
	}
}

// SendSystemAlert sends a system-level alert
func (m *Manager) SendSystemAlert(alertType, message string, details map[string]interface{}) {
	event := Event{
		Type:        alertType,
		Timestamp:   time.Now(),
		Reason:      message,
		ThreatLevel: "high",
		Details:     details,
	}
	
	select {
	case m.eventChan <- event:
	default:
		m.logger.Warn("Notification queue is full, dropping event")
	}
}

// processEvents processes notification events
func (m *Manager) processEvents() {
	for {
		select {
		case event := <-m.eventChan:
			m.processEvent(event)
		case <-m.stopChan:
			return
		}
	}
}

// processEvent processes a single notification event
func (m *Manager) processEvent(event Event) {
	// Send to all enabled channels
	if m.config.Telegram.Enabled {
		if err := m.sendTelegram(event); err != nil {
			m.logger.WithError(err).Error("Failed to send Telegram notification")
		}
	}
	
	if m.config.Slack.Enabled {
		if err := m.sendSlack(event); err != nil {
			m.logger.WithError(err).Error("Failed to send Slack notification")
		}
	}
	
	if m.config.Email.Enabled {
		if err := m.sendEmail(event); err != nil {
			m.logger.WithError(err).Error("Failed to send email notification")
		}
	}
	
	if m.config.Webhook.Enabled {
		if err := m.sendWebhook(event); err != nil {
			m.logger.WithError(err).Error("Failed to send webhook notification")
		}
	}
}

// sendTelegram sends a Telegram notification
func (m *Manager) sendTelegram(event Event) error {
	if m.telegramBot == nil {
		return fmt.Errorf("Telegram bot not initialized")
	}
	
	message := m.formatTelegramMessage(event)
	
	chatID, err := m.parseChatID(m.config.Telegram.ChatID)
	if err != nil {
		return fmt.Errorf("invalid chat ID: %v", err)
	}
	
	msg := tgbotapi.NewMessage(chatID, message)
	msg.ParseMode = "Markdown"
	
	_, err = m.telegramBot.Send(msg)
	return err
}

// sendSlack sends a Slack notification
func (m *Manager) sendSlack(event Event) error {
	webhook := slack.WebhookMessage{
		Channel:   m.config.Slack.Channel,
		Username:  "nginx-defender",
		IconEmoji: ":shield:",
		Text:      m.formatSlackMessage(event),
		Attachments: []slack.Attachment{
			{
				Color: m.getSlackColor(event.ThreatLevel),
				Fields: []slack.AttachmentField{
					{
						Title: "IP Address",
						Value: event.IP,
						Short: true,
					},
					{
						Title: "Action",
						Value: event.Action,
						Short: true,
					},
					{
						Title: "Threat Level",
						Value: event.ThreatLevel,
						Short: true,
					},
					{
						Title: "Timestamp",
						Value: event.Timestamp.Format(time.RFC3339),
						Short: true,
					},
				},
			},
		},
	}
	
	if event.Location != nil {
		webhook.Attachments[0].Fields = append(webhook.Attachments[0].Fields,
			slack.AttachmentField{
				Title: "Location",
				Value: fmt.Sprintf("%s, %s", event.Location.City, event.Location.Country),
				Short: true,
			},
		)
	}
	
	return slack.PostWebhook(m.config.Slack.WebhookURL, &webhook)
}

// sendEmail sends an email notification
func (m *Manager) sendEmail(event Event) error {
	// Email implementation would go here
	// For now, just log that we would send an email
	m.logger.Infof("Would send email notification for event: %s", event.Type)
	return nil
}

// sendWebhook sends a webhook notification
func (m *Manager) sendWebhook(event Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %v", err)
	}
	
	req, err := http.NewRequest("POST", m.config.Webhook.URL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "nginx-defender/2.0")
	
	if m.config.Webhook.Secret != "" {
		// Add HMAC signature header
		req.Header.Set("X-Nginx-Defender-Signature", m.calculateSignature(payload, m.config.Webhook.Secret))
	}
	
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status code: %d", resp.StatusCode)
	}
	
	return nil
}

// formatTelegramMessage formats a message for Telegram
func (m *Manager) formatTelegramMessage(event Event) string {
	var message string
	
	switch event.Type {
	case "threat_detected":
		message = fmt.Sprintf("🚨 *Threat Detected*\n\n")
		message += fmt.Sprintf("**IP:** `%s`\n", event.IP)
		message += fmt.Sprintf("**Action:** %s\n", event.Action)
		message += fmt.Sprintf("**Threat Level:** %s\n", event.ThreatLevel)
		message += fmt.Sprintf("**Reason:** %s\n", event.Reason)
		
		if event.Location != nil {
			message += fmt.Sprintf("**Location:** %s, %s\n", event.Location.City, event.Location.Country)
		}
		
		message += fmt.Sprintf("**Time:** %s", event.Timestamp.Format("2006-01-02 15:04:05 UTC"))
		
	case "ip_blocked":
		message = fmt.Sprintf("🔒 *IP Blocked*\n\n")
		message += fmt.Sprintf("**IP:** `%s`\n", event.IP)
		message += fmt.Sprintf("**Action:** %s\n", event.Action)
		message += fmt.Sprintf("**Reason:** %s\n", event.Reason)
		
		if duration, ok := event.Details["duration"].(string); ok {
			message += fmt.Sprintf("**Duration:** %s\n", duration)
		}
		
		if event.Location != nil {
			message += fmt.Sprintf("**Location:** %s, %s\n", event.Location.City, event.Location.Country)
		}
		
		message += fmt.Sprintf("**Time:** %s", event.Timestamp.Format("2006-01-02 15:04:05 UTC"))
		
	default:
		message = fmt.Sprintf("⚠️ *System Alert*\n\n")
		message += fmt.Sprintf("**Type:** %s\n", event.Type)
		message += fmt.Sprintf("**Message:** %s\n", event.Reason)
		message += fmt.Sprintf("**Time:** %s", event.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	}
	
	return message
}

// formatSlackMessage formats a message for Slack
func (m *Manager) formatSlackMessage(event Event) string {
	switch event.Type {
	case "threat_detected":
		return fmt.Sprintf("🚨 Threat detected from IP %s - Action: %s", event.IP, event.Action)
	case "ip_blocked":
		return fmt.Sprintf("🔒 IP %s has been blocked - Reason: %s", event.IP, event.Reason)
	default:
		return fmt.Sprintf("⚠️ System Alert: %s", event.Reason)
	}
}

// Helper functions
func (m *Manager) getThreatLevelString(level detector.ThreatLevel) string {
	switch level {
	case detector.ThreatLevelLow:
		return "low"
	case detector.ThreatLevelMedium:
		return "medium"
	case detector.ThreatLevelHigh:
		return "high"
	case detector.ThreatLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func (m *Manager) getSlackColor(threatLevel string) string {
	switch threatLevel {
	case "low":
		return "good"
	case "medium":
		return "warning"
	case "high", "critical":
		return "danger"
	default:
		return "#439FE0"
	}
}

func (m *Manager) parseChatID(chatID string) (int64, error) {
	// This would parse the chat ID string to int64
	// For now, return a placeholder
	return -1001234567890, nil // Placeholder
}

func (m *Manager) calculateSignature(payload []byte, secret string) string {
	// This would calculate HMAC-SHA256 signature
	// For now, return a placeholder
	return "placeholder_signature"
}

// Shutdown gracefully shuts down the notification manager
func (m *Manager) Shutdown() {
	close(m.stopChan)
	m.logger.Info("Notification manager shut down")
}
