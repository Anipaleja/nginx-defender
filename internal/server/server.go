package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Anipaleja/nginx-defender/internal/config"
	"github.com/Anipaleja/nginx-defender/internal/detector"
	"github.com/Anipaleja/nginx-defender/internal/firewall"
	"github.com/Anipaleja/nginx-defender/internal/metrics"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// Server provides the web interface and API
type Server struct {
	config     config.ServerConfig
	webConfig  config.WebInterfaceConfig
	logger     *logrus.Logger
	router     *mux.Router
	httpServer *http.Server
	startedAt  time.Time

	// Components
	detectionEngine  *detector.Engine
	firewallManager  *firewall.Manager
	metricsCollector *metrics.Collector

	// WebSocket
	upgrader     websocket.Upgrader
	clients      map[*websocket.Conn]bool
	clientsMutex sync.RWMutex

	// Authentication
	sessions     map[string]*Session
	sessionMutex sync.RWMutex

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// Session represents an authenticated session
type Session struct {
	ID        string
	Username  string
	Expires   time.Time
	CSRFToken string
}

// NewServer creates a new web server
func NewServer(cfg config.ServerConfig, webCfg config.WebInterfaceConfig, logger *logrus.Logger) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	server := &Server{
		config:    cfg,
		webConfig: webCfg,
		logger:    logger,
		router:    mux.NewRouter(),
		clients:   make(map[*websocket.Conn]bool),
		sessions:  make(map[string]*Session),
		upgrader:  websocket.Upgrader{},
		startedAt: time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}

	server.upgrader = websocket.Upgrader{
		CheckOrigin: server.isWebSocketOriginAllowed,
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
	s.router.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(http.Dir("./web/assets/"))))

	// Authentication routes (always available)
	s.router.HandleFunc("/login", s.loginPageHandler).Methods("GET")
	s.router.HandleFunc("/login", s.loginHandler).Methods("POST")
	s.router.HandleFunc("/logout", s.logoutHandler).Methods("POST")

	// Protected web interface routes
	protected := s.router.PathPrefix("/").Subrouter()
	if s.webConfig.Auth.Enabled {
		protected.Use(s.authMiddleware)
	}

	protected.HandleFunc("/", s.dashboardHandler).Methods("GET")
	protected.HandleFunc("/dashboard", s.dashboardHandler).Methods("GET")
	protected.HandleFunc("/threats", s.threatsHandler).Methods("GET")
	protected.HandleFunc("/firewall", s.firewallHandler).Methods("GET")
	protected.HandleFunc("/settings", s.settingsHandler).Methods("GET")
	protected.HandleFunc("/logs", s.logsHandler).Methods("GET")

	// API routes
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.jsonMiddleware)

	// Public health endpoint
	api.HandleFunc("/health", s.healthHandler).Methods("GET")

	protectedAPI := api.PathPrefix("/").Subrouter()
	if s.webConfig.Auth.Enabled {
		protectedAPI.Use(s.authMiddleware)
	}

	// Status and operational APIs
	protectedAPI.HandleFunc("/status", s.statusHandler).Methods("GET")
	protectedAPI.HandleFunc("/stats", s.statsHandler).Methods("GET")

	// Threat detector
	protectedAPI.HandleFunc("/threats", s.apiThreatsHandler).Methods("GET")
	protectedAPI.HandleFunc("/threats/{id}", s.apiThreatHandler).Methods("GET")
	protectedAPI.HandleFunc("/threats/{id}/false-positive", s.apiThreatFalsePositiveHandler).Methods("POST")
	protectedAPI.HandleFunc("/threats/search", s.apiThreatSearchHandler).Methods("POST")

	// Firewall management
	protectedAPI.HandleFunc("/firewall/rules", s.apiFirewallRulesHandler).Methods("GET")
	protectedAPI.HandleFunc("/firewall/rules", s.apiFirewallAddRuleHandler).Methods("POST")
	protectedAPI.HandleFunc("/firewall/rules/{id}", s.apiFirewallDeleteRuleHandler).Methods("DELETE")
	protectedAPI.HandleFunc("/firewall/block", s.apiFirewallBlockHandler).Methods("POST")
	protectedAPI.HandleFunc("/firewall/unblock", s.apiFirewallUnblockHandler).Methods("POST")

	// IP analysis
	protectedAPI.HandleFunc("/ip/{ip}/analyze", s.apiIPAnalyzeHandler).Methods("GET")
	protectedAPI.HandleFunc("/ip/{ip}/history", s.apiIPHistoryHandler).Methods("GET")
	protectedAPI.HandleFunc("/ip/{ip}/reputation", s.apiIPReputationHandler).Methods("GET")

	// Metrics and monitoring
	protectedAPI.HandleFunc("/metrics", s.apiMetricsHandler).Methods("GET")
	protectedAPI.HandleFunc("/metrics/export", s.apiMetricsExportHandler).Methods("GET")

	// Configuration
	protectedAPI.HandleFunc("/config", s.apiConfigHandler).Methods("GET")
	protectedAPI.HandleFunc("/config", s.apiConfigUpdateHandler).Methods("PUT")

	// Real-time updates via WebSocket
	if s.webConfig.Auth.Enabled {
		s.router.Handle("/ws", s.authMiddleware(http.HandlerFunc(s.websocketHandler))).Methods("GET")
	} else {
		s.router.HandleFunc("/ws", s.websocketHandler).Methods("GET")
	}

	// Prometheus metrics endpoint
	if s.metricsCollector != nil {
		s.router.Handle("/metrics", s.metricsCollector.Handler())
	}
}

// Middleware
func (s *Server) jsonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		origin := r.Header.Get("Origin")
		if origin != "" {
			if !s.webConfig.API.CorsEnabled || !s.isOriginAllowed(origin) {
				http.Error(w, "origin is not allowed", http.StatusForbidden)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
			if s.webConfig.Auth.Enabled {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}

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
		"uptime":    time.Since(s.startedAt).String(),
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	s.clientsMutex.RLock()
	clientCount := len(s.clients)
	s.clientsMutex.RUnlock()

	status := map[string]interface{}{
		"detection_engine":  s.detectionEngine != nil,
		"firewall":          s.firewallManager != nil,
		"metrics":           s.metricsCollector != nil,
		"websocket_clients": clientCount,
		"timestamp":         time.Now().UTC(),
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
	if s.detectionEngine == nil {
		http.Error(w, "Detection engine not available", http.StatusServiceUnavailable)
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	limit := 100 // default
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	threats := s.detectionEngine.GetRecentThreats(limit)

	response := map[string]interface{}{
		"threats": threats,
		"total":   len(threats),
		"limit":   limit,
	}

	json.NewEncoder(w).Encode(response)
}

func (s *Server) apiThreatFalsePositiveHandler(w http.ResponseWriter, r *http.Request) {
	if s.metricsCollector == nil {
		http.Error(w, "Metrics collector not available", http.StatusServiceUnavailable)
		return
	}

	id := mux.Vars(r)["id"]
	threatType := "unknown"
	if s.detectionEngine != nil {
		if threat, ok := s.detectionEngine.GetThreatByID(id); ok && len(threat.ThreatTypes) > 0 {
			threatType = threat.ThreatTypes[0]
		}
	}

	s.metricsCollector.RecordFalsePositive("api", threatType)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "recorded",
		"threat_id":   id,
		"threat_type": threatType,
	})
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

	history := []detector.DetectionResult{}
	if s.detectionEngine != nil {
		history = s.detectionEngine.GetIPThreatHistory(ip, 200)
	}

	threatScore := 0.0
	requestCount := len(history)
	lastSeen := interface{}(nil)
	threatTypes := make(map[string]struct{})
	for _, event := range history {
		if event.Score > threatScore {
			threatScore = event.Score
		}
		if event.Timestamp.After(time.Time{}) {
			lastSeen = event.Timestamp
		}
		for _, threatType := range event.ThreatTypes {
			threatTypes[threatType] = struct{}{}
		}
	}

	typeList := make([]string, 0, len(threatTypes))
	for threatType := range threatTypes {
		typeList = append(typeList, threatType)
	}

	analysis := map[string]interface{}{
		"ip":                ip,
		"reputation":        s.calculateReputation(requestCount, threatScore),
		"threat_score":      threatScore,
		"country":           "Unknown",
		"asn":               "Unknown",
		"last_seen":         lastSeen,
		"request_count":     requestCount,
		"blocked":           false,
		"threat_categories": typeList,
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

	s.clientsMutex.Lock()
	s.clients[conn] = true
	totalClients := len(s.clients)
	s.clientsMutex.Unlock()
	s.logger.Infof("New WebSocket client connected. Total clients: %d", totalClients)

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
			s.clientsMutex.Lock()
			delete(s.clients, conn)
			totalClients := len(s.clients)
			s.clientsMutex.Unlock()
			s.logger.Infof("WebSocket client disconnected. Total clients: %d", totalClients)
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

	s.clientsMutex.RLock()
	clients := make([]*websocket.Conn, 0, len(s.clients))
	for client := range s.clients {
		clients = append(clients, client)
	}
	s.clientsMutex.RUnlock()

	for _, client := range clients {
		if err := client.WriteJSON(message); err != nil {
			client.Close()
			s.clientsMutex.Lock()
			delete(s.clients, client)
			s.clientsMutex.Unlock()
		}
	}
}

// renderTemplate renders an HTML template
func (s *Server) renderTemplate(w http.ResponseWriter, templateName string, data map[string]interface{}) {
	templatePath := filepath.Join("web", "templates", templateName)

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		s.logger.Errorf("Failed to parse template %s: %v", templateName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	if err := tmpl.Execute(w, data); err != nil {
		s.logger.Errorf("Failed to execute template %s: %v", templateName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
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
	s.clientsMutex.Lock()
	for client := range s.clients {
		client.Close()
		delete(s.clients, client)
	}
	s.clientsMutex.Unlock()

	// Cancel context
	s.cancel()

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

func (s *Server) generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *Server) newSessionCookie(r *http.Request, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     "session",
		Value:    value,
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	}
}

func (s *Server) isSecureRequest(r *http.Request) bool {
	if s.config.TLS.Enabled {
		return true
	}
	xfp := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	return xfp == "https"
}

func (s *Server) isOriginAllowed(origin string) bool {
	if !s.webConfig.API.CorsEnabled {
		return false
	}

	for _, allowed := range s.webConfig.API.CorsOrigins {
		if strings.EqualFold(origin, allowed) {
			return true
		}
	}

	return false
}

func (s *Server) isWebSocketOriginAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}

	return s.isOriginAllowed(origin)
}

func (s *Server) handleAuthFailure(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authentication required"})
		return
	}

	s.redirectToLogin(w, r)
}

func isBcryptHash(value string) bool {
	if len(value) < 4 {
		return false
	}
	return value[0] == '$' && value[1] == '2' && (value[2] == 'a' || value[2] == 'b' || value[2] == 'y') && value[3] == '$'
}

func (s *Server) calculateReputation(eventCount int, maxScore float64) string {
	if eventCount == 0 {
		return "unknown"
	}

	switch {
	case maxScore >= 80:
		return "malicious"
	case maxScore >= 50:
		return "high-risk"
	case maxScore >= 20:
		return "suspicious"
	default:
		return "low-risk"
	}
}

// Placeholder handlers for missing routes
func (s *Server) apiThreatHandler(w http.ResponseWriter, r *http.Request) {
	if s.detectionEngine == nil {
		http.Error(w, "Detection engine not available", http.StatusServiceUnavailable)
		return
	}

	id := mux.Vars(r)["id"]
	threat, exists := s.detectionEngine.GetThreatByID(id)
	if !exists {
		http.Error(w, "Threat not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(threat)
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
	if s.firewallManager == nil {
		http.Error(w, "Firewall manager not available", http.StatusServiceUnavailable)
		return
	}

	var request struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.IP == "" {
		http.Error(w, "ip is required", http.StatusBadRequest)
		return
	}

	if err := s.firewallManager.UnblockIP(request.IP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status": "unblocked",
		"ip":     request.IP,
	})
}

func (s *Server) apiIPHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if s.detectionEngine == nil {
		http.Error(w, "Detection engine not available", http.StatusServiceUnavailable)
		return
	}

	ip := mux.Vars(r)["ip"]
	limit := 100
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil {
			limit = parsed
		}
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	history := s.detectionEngine.GetIPThreatHistory(ip, limit)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":      ip,
		"history": history,
		"total":   len(history),
	})
}

func (s *Server) apiIPReputationHandler(w http.ResponseWriter, r *http.Request) {
	ip := mux.Vars(r)["ip"]

	if s.detectionEngine == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":         ip,
			"reputation": "unknown",
		})
		return
	}

	history := s.detectionEngine.GetIPThreatHistory(ip, 200)
	maxScore := 0.0
	for _, event := range history {
		if event.Score > maxScore {
			maxScore = event.Score
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":          ip,
		"reputation":  s.calculateReputation(len(history), maxScore),
		"event_count": len(history),
		"max_score":   maxScore,
	})
}

func (s *Server) apiMetricsHandler(w http.ResponseWriter, r *http.Request) {
	if s.metricsCollector == nil {
		http.Error(w, "Metrics collector not available", http.StatusServiceUnavailable)
		return
	}

	json.NewEncoder(w).Encode(s.metricsCollector.GetStats())
}

func (s *Server) apiMetricsExportHandler(w http.ResponseWriter, r *http.Request) {
	if s.metricsCollector == nil {
		http.Error(w, "Metrics collector not available", http.StatusServiceUnavailable)
		return
	}

	metrics, err := s.metricsCollector.ExportMetrics()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(metrics)
}

// Authentication middleware
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			s.handleAuthFailure(w, r)
			return
		}

		s.sessionMutex.RLock()
		session, exists := s.sessions[cookie.Value]
		s.sessionMutex.RUnlock()

		if !exists || session.Expires.Before(time.Now()) {
			if exists {
				// Clean up expired session
				s.sessionMutex.Lock()
				delete(s.sessions, cookie.Value)
				s.sessionMutex.Unlock()
			}
			s.handleAuthFailure(w, r)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			csrfHeader := r.Header.Get("X-CSRF-Token")
			csrfForm := r.FormValue("csrf_token")
			provided := csrfHeader
			if provided == "" {
				provided = csrfForm
			}
			if subtle.ConstantTimeCompare([]byte(provided), []byte(session.CSRFToken)) != 1 {
				if strings.HasPrefix(r.URL.Path, "/api/") {
					http.Error(w, "invalid csrf token", http.StatusForbidden)
					return
				}
				http.Redirect(w, r, "/login?error=csrf", http.StatusFound)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// loginPageHandler handles GET requests to /login
func (s *Server) loginPageHandler(w http.ResponseWriter, r *http.Request) {
	errorMessage := s.getErrorMessage(r)
	csrfToken, err := s.generateToken(32)
	if err != nil {
		s.logger.WithError(err).Error("failed to generate login CSRF token")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "login_csrf",
		Value:    csrfToken,
		HttpOnly: true,
		Secure:   s.isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   300,
	})

	data := map[string]interface{}{
		"Error":     errorMessage,
		"CSRFToken": csrfToken,
	}

	s.renderTemplate(w, "login.html", data)
}

// loginHandler handles POST requests to /login
func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=invalid", http.StatusFound)
		return
	}

	loginCSRFCookie, err := r.Cookie("login_csrf")
	if err != nil {
		http.Redirect(w, r, "/login?error=csrf", http.StatusFound)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf_token")), []byte(loginCSRFCookie.Value)) != 1 {
		http.Redirect(w, r, "/login?error=csrf", http.StatusFound)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if s.validateCredentials(username, password) {
		// Create new session
		sessionID, err := s.generateToken(32)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		sessionCSRF, err := s.generateToken(32)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		session := &Session{
			ID:        sessionID,
			Username:  username,
			Expires:   time.Now().Add(time.Duration(s.webConfig.Auth.SessionTimeout) * time.Second),
			CSRFToken: sessionCSRF,
		}

		s.sessionMutex.Lock()
		s.sessions[sessionID] = session
		s.sessionMutex.Unlock()

		// Set session cookie
		http.SetCookie(w, s.newSessionCookie(r, sessionID, session.Expires))
		http.SetCookie(w, &http.Cookie{
			Name:     "login_csrf",
			Value:    "",
			HttpOnly: true,
			Secure:   s.isSecureRequest(r),
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
			MaxAge:   -1,
		})

		s.logger.Infof("User %s logged in successfully", username)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:     "login_csrf",
			Value:    "",
			HttpOnly: true,
			Secure:   s.isSecureRequest(r),
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
			MaxAge:   -1,
		})
		s.logger.Warnf("Failed login attempt for user %s", username)
		http.Redirect(w, r, "/login?error=invalid", http.StatusFound)
	}
}

// logoutHandler handles logout requests
func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil && r.Method == http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	cookie, err := r.Cookie("session")
	if err == nil {
		s.sessionMutex.RLock()
		session, exists := s.sessions[cookie.Value]
		s.sessionMutex.RUnlock()

		if exists && r.Method == http.MethodPost {
			csrf := r.Header.Get("X-CSRF-Token")
			if csrf == "" {
				csrf = r.FormValue("csrf_token")
			}
			if subtle.ConstantTimeCompare([]byte(csrf), []byte(session.CSRFToken)) != 1 {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}
		}

		// Remove session
		s.sessionMutex.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionMutex.Unlock()

		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour),
			HttpOnly: true,
			Secure:   s.isSecureRequest(r),
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
			MaxAge:   -1,
		})
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}

// validateCredentials validates user credentials
func (s *Server) validateCredentials(username, password string) bool {
	// Check users list from config
	for _, user := range s.webConfig.Auth.Users {
		if user.Username == username {
			return s.comparePassword(user.Password, password)
		}
	}

	// Fallback to default credentials
	if username == s.webConfig.Auth.DefaultUsername {
		return s.comparePassword(s.webConfig.Auth.DefaultPassword, password)
	}

	return false
}

func (s *Server) comparePassword(storedPassword, providedPassword string) bool {
	if s.webConfig.Auth.PasswordHashAlgo == "bcrypt" && isBcryptHash(storedPassword) {
		return bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(providedPassword)) == nil
	}

	if len(storedPassword) != len(providedPassword) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(storedPassword), []byte(providedPassword)) == 1
}

// redirectToLogin redirects to login page
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusFound)
}

// getErrorMessage returns error message for login page
func (s *Server) getErrorMessage(r *http.Request) string {
	errorParam := r.URL.Query().Get("error")
	if errorParam == "invalid" {
		return "Invalid username or password"
	}
	if errorParam == "csrf" {
		return "Security token validation failed. Please try again."
	}
	return ""
}

func (s *Server) apiConfigHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}

func (s *Server) apiConfigUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "not implemented"})
}
