package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/internal/detector"
	"github.com/Anipaleja/nginx-defender/internal/firewall"
	"github.com/Anipaleja/nginx-defender/internal/metrics"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

// Server provides the web interface and API
type Server struct {
	config          config.ServerConfig
	logger          *logrus.Logger
	router          *mux.Router
	httpServer      *http.Server
	
	// Components
	detectionEngine *detector.Engine
	firewallManager *firewall.Manager
	metricsCollector *metrics.Collector
	
	// WebSocket
	upgrader websocket.Upgrader
	clients  map[*websocket.Conn]bool
	
	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// NewServer creates a new web server
func NewServer(cfg config.ServerConfig, logger *logrus.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	
	server := &Server{
		config:  cfg,
		logger:  logger,
		router:  mux.NewRouter(),
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for now
			},
		},
		ctx:    ctx,
		cancel: cancel,
	}
	
	server.setupRoutes()
	
	server.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.Port),
		Handler:      server.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	return server
}

// SetComponents sets the required components
func (s *Server) SetComponents(engine *detector.Engine, firewall *firewall.Manager, metrics *metrics.Collector) {
	s.detectionEngine = engine
	s.firewallManager = firewall
	s.metricsCollector = metrics
}

// setupRoutes sets up all HTTP routes
func (s *Server) setupRoutes() {
	// Static files
	s.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./web/static/"))))
	
	// Web interface routes
	s.router.HandleFunc("/", s.dashboardHandler).Methods("GET")
	s.router.HandleFunc("/dashboard", s.dashboardHandler).Methods("GET")
	s.router.HandleFunc("/threats", s.threatsHandler).Methods("GET")
	s.router.HandleFunc("/firewall", s.firewallHandler).Methods("GET")
	s.router.HandleFunc("/settings", s.settingsHandler).Methods("GET")
	s.router.HandleFunc("/logs", s.logsHandler).Methods("GET")
	
	// API routes
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.jsonMiddleware)
	
	// Status and health
	api.HandleFunc("/health", s.healthHandler).Methods("GET")
	api.HandleFunc("/status", s.statusHandler).Methods("GET")
	api.HandleFunc("/stats", s.statsHandler).Methods("GET")
	
	// Threat detection
	api.HandleFunc("/threats", s.apiThreatsHandler).Methods("GET")
	api.HandleFunc("/threats/{id}", s.apiThreatHandler).Methods("GET")
	api.HandleFunc("/threats/search", s.apiThreatSearchHandler).Methods("POST")
	
	// Firewall management
	api.HandleFunc("/firewall/rules", s.apiFirewallRulesHandler).Methods("GET")
	api.HandleFunc("/firewall/rules", s.apiFirewallAddRuleHandler).Methods("POST")
	api.HandleFunc("/firewall/rules/{id}", s.apiFirewallDeleteRuleHandler).Methods("DELETE")
	api.HandleFunc("/firewall/block", s.apiFirewallBlockHandler).Methods("POST")
	api.HandleFunc("/firewall/unblock", s.apiFirewallUnblockHandler).Methods("POST")
	
	// IP analysis
	api.HandleFunc("/ip/{ip}/analyze", s.apiIPAnalyzeHandler).Methods("GET")
	api.HandleFunc("/ip/{ip}/history", s.apiIPHistoryHandler).Methods("GET")
	api.HandleFunc("/ip/{ip}/reputation", s.apiIPReputationHandler).Methods("GET")
	
	// Metrics and monitoring
	api.HandleFunc("/metrics", s.apiMetricsHandler).Methods("GET")
	api.HandleFunc("/metrics/export", s.apiMetricsExportHandler).Methods("GET")
	
	// Configuration
	api.HandleFunc("/config", s.apiConfigHandler).Methods("GET")
	api.HandleFunc("/config", s.apiConfigUpdateHandler).Methods("PUT")
	
	// Real-time updates via WebSocket
	s.router.HandleFunc("/ws", s.websocketHandler)
	
	// Prometheus metrics endpoint
	if s.metricsCollector != nil {
		s.router.Handle("/metrics", s.metricsCollector.Handler())
	}
}

// Middleware
func (s *Server) jsonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// Web interface handlers
func (s *Server) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, "dashboard.html", map[string]interface{}{
		"Title": "Dashboard",
	})
}

func (s *Server) threatsHandler(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, "threats.html", map[string]interface{}{
		"Title": "Threat Detection",
	})
}

func (s *Server) firewallHandler(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, "firewall.html", map[string]interface{}{
		"Title": "Firewall Rules",
	})
}

func (s *Server) settingsHandler(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, "settings.html", map[string]interface{}{
		"Title": "Settings",
	})
}

func (s *Server) logsHandler(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, "logs.html", map[string]interface{}{
		"Title": "Logs",
	})
}

// API handlers
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "2.0.0",
		"uptime":    time.Since(time.Now()).String(), // This would be actual uptime
	}
	
	json.NewEncoder(w).Encode(response)
}

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"detection_engine": s.detectionEngine != nil,
		"firewall":         s.firewallManager != nil,
		"metrics":          s.metricsCollector != nil,
		"websocket_clients": len(s.clients),
		"timestamp":        time.Now().UTC(),
	}
	
	if s.firewallManager != nil {
		status["firewall_stats"] = s.firewallManager.GetStats()
	}
	
	json.NewEncoder(w).Encode(status)
}

func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"timestamp": time.Now().UTC(),
	}
	
	if s.metricsCollector != nil {
		stats["metrics"] = s.metricsCollector.GetStats()
	}
	
	if s.firewallManager != nil {
		stats["firewall"] = s.firewallManager.GetStats()
	}
	
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) apiThreatsHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	limit := 100 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}
	
	// This would fetch recent threats from the detection engine
	threats := []map[string]interface{}{
		{
			"id":           "threat-1",
			"ip":           "192.168.1.100",
			"threat_level": "high",
			"score":        85.5,
			"timestamp":    time.Now().UTC(),
		},
		// More threats would be fetched from storage
	}
	
	response := map[string]interface{}{
		"threats": threats[:min(len(threats), limit)],
		"total":   len(threats),
		"limit":   limit,
	}
	
	json.NewEncoder(w).Encode(response)
}

func (s *Server) apiFirewallRulesHandler(w http.ResponseWriter, r *http.Request) {
	if s.firewallManager == nil {
		http.Error(w, "Firewall manager not available", http.StatusServiceUnavailable)
		return
	}
	
	rules := s.firewallManager.GetRules()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": rules,
		"total": len(rules),
	})
}

func (s *Server) apiFirewallBlockHandler(w http.ResponseWriter, r *http.Request) {
	if s.firewallManager == nil {
		http.Error(w, "Firewall manager not available", http.StatusServiceUnavailable)
		return
	}
	
	var request struct {
		IP       string `json:"ip"`
		Action   string `json:"action"`
		Duration string `json:"duration"`
		Reason   string `json:"reason"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	duration, err := time.ParseDuration(request.Duration)
	if err != nil {
		duration = 1 * time.Hour // default
	}
	
	action := firewall.ActionBlock
	switch request.Action {
	case "DROP":
		action = firewall.ActionDrop
	case "REJECT":
		action = firewall.ActionReject
	case "TARPIT":
		action = firewall.ActionTarpit
	}
	
	err = s.firewallManager.BlockIP(request.IP, action, duration, request.Reason, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "blocked",
		"ip":     request.IP,
	})
}

func (s *Server) apiIPAnalyzeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ip := vars["ip"]
	
	// This would perform real-time analysis of the IP
	analysis := map[string]interface{}{
		"ip":             ip,
		"reputation":     "unknown",
		"threat_score":   0.0,
		"country":        "Unknown",
		"asn":            "Unknown",
		"last_seen":      nil,
		"request_count":  0,
		"blocked":        false,
		"threat_categories": []string{},
	}
	
	// Check if IP is currently blocked
	if s.firewallManager != nil {
		blocked, rule := s.firewallManager.IsBlocked(ip)
		analysis["blocked"] = blocked
		if rule != nil {
			analysis["block_reason"] = rule.Reason
			analysis["block_expires"] = rule.ExpiresAt
		}
	}
	
	json.NewEncoder(w).Encode(analysis)
}

// WebSocket handler for real-time updates
func (s *Server) websocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.WithError(err).Error("Failed to upgrade WebSocket connection")
		return
	}
	defer conn.Close()
	
	s.clients[conn] = true
	s.logger.Infof("New WebSocket client connected. Total clients: %d", len(s.clients))
	
	// Send initial data
	initialData := map[string]interface{}{
		"type":      "connected",
		"timestamp": time.Now().UTC(),
		"message":   "Connected to nginx-defender real-time updates",
	}
	conn.WriteJSON(initialData)
	
	// Keep connection alive and handle client disconnect
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			delete(s.clients, conn)
			s.logger.Infof("WebSocket client disconnected. Total clients: %d", len(s.clients))
			break
		}
	}
}

// BroadcastUpdate broadcasts an update to all WebSocket clients
func (s *Server) BroadcastUpdate(updateType string, data interface{}) {
	message := map[string]interface{}{
		"type":      updateType,
		"data":      data,
		"timestamp": time.Now().UTC(),
	}
	
	for client := range s.clients {
		if err := client.WriteJSON(message); err != nil {
			client.Close()
			delete(s.clients, client)
		}
	}
}

// renderTemplate renders an HTML template
func (s *Server) renderTemplate(w http.ResponseWriter, template string, data map[string]interface{}) {
	// This would render actual HTML templates
	// For now, return a simple JSON response
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html>
	<head>
		<title>%s - nginx-defender</title>
		<link rel="stylesheet" href="/static/css/dashboard.css">
	</head>
	<body>
		<h1>%s</h1>
		<p>nginx-defender Web Interface</p>
		<script src="/static/js/dashboard.js"></script>
	</body>
	</html>
	`, data["Title"], data["Title"])
}

// Start starts the web server
func (s *Server) Start() error {
	s.logger.Infof("Starting web server on %s", s.httpServer.Addr)
	
	if s.config.TLS.Enabled {
		return s.httpServer.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile)
	}
	
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	s.logger.Info("Shutting down web server")
	
	// Close all WebSocket connections
	for client := range s.clients {
		client.Close()
	}
	
	// Cancel context
	s.cancel()
	
	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	return s.httpServer.Shutdown(ctx)
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Placeholder handlers for missing routes
func (s *Server) apiThreatHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiThreatSearchHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiFirewallAddRuleHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiFirewallDeleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiFirewallUnblockHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiIPHistoryHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiIPReputationHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiMetricsExportHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiConfigUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}
