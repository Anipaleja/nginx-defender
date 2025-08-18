// Example: Web framework middleware integration
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	defender "github.com/Anipaleja/nginx-defender/lib"
	"github.com/gorilla/mux"
)

// DefenderHTTPMiddleware creates middleware for standard HTTP applications
func DefenderHTTPMiddleware(def *defender.Defender) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)

			// Check if IP should be blocked
			if def.ShouldBlock(clientIP) {
				http.Error(w, "Access Denied - Blocked by nginx-defender", http.StatusForbidden)
				return
			}

			// Add security headers
			w.Header().Set("X-Protected-By", "nginx-defender")
			w.Header().Set("X-Threat-Score", fmt.Sprintf("%d", def.GetThreatScore(clientIP)))

			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	fmt.Println("🛡️  nginx-defender Middleware Examples")
	fmt.Println("======================================")

	// Initialize defender
	config := defender.DevelopmentConfig()
	config.WebUIPort = 8083

	def, err := defender.New(config)
	if err != nil {
		log.Fatal(err)
	}
	defer def.Close()

	// Set up event logging
	def.OnThreatDetected(func(event defender.ThreatEvent) {
		fmt.Printf("🚨 [MIDDLEWARE] Threat: %s (Score: %d)\n", event.IP, event.Score)
	})

	def.OnBlockDecision(func(event defender.BlockEvent) {
		fmt.Printf("🚫 [MIDDLEWARE] Blocked: %s (%s)\n", event.IP, event.Reason)
	})

	if err := def.Start(); err != nil {
		log.Fatal(err)
	}

	// Start example servers
	go runGorillaExample(def)
	go runStandardHTTPExample(def)

	fmt.Println("🌐 Started web servers:")
	fmt.Println("  - Gorilla Mux:   http://localhost:8084")
	fmt.Println("  - Standard HTTP: http://localhost:8085")
	fmt.Println("  - Defender UI:   http://localhost:8083")

	// Simulate some blocking for demonstration
	fmt.Println("\n🎭 Simulating blocked IPs for demo...")
	def.BlockIP("203.0.113.1", 0, "Demo blocked IP")
	def.BlockIP("198.51.100.1", 0, "Another demo blocked IP")

	fmt.Println("📋 Try these URLs to test protection:")
	fmt.Println("  - Normal access: curl http://localhost:8084/")
	fmt.Println("  - API endpoint: curl http://localhost:8085/api/health")
	fmt.Println("  - With blocked IP: curl -H 'X-Forwarded-For: 203.0.113.1' http://localhost:8084/")

	// Keep running
	select {}
}

func runGorillaExample(def *defender.Defender) {
	r := mux.NewRouter()

	// Apply middleware
	r.Use(DefenderHTTPMiddleware(def))

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Gorilla Mux + nginx-defender</title></head>
<body>
    <h1>🦍 Gorilla Mux + nginx-defender</h1>
    <p>Your IP: %s</p>
    <p>Threat Score: %s</p>
    <p>Protected by nginx-defender middleware</p>
    <p><a href="/api/status">Check API Status</a></p>
</body>
</html>`, getClientIP(r), w.Header().Get("X-Threat-Score"))
	})

	r.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"status":        "protected",
			"framework":     "gorilla/mux",
			"ip":            getClientIP(r),
			"threat_score":  w.Header().Get("X-Threat-Score"),
			"protected_by":  "nginx-defender",
			"timestamp":     time.Now().Format(time.RFC3339),
		}
		json.NewEncoder(w).Encode(response)
	})

	r.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		metrics := def.GetMetrics()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"framework": "gorilla/mux",
			"metrics":   metrics,
			"ip":        getClientIP(r),
		})
	})

	fmt.Println("🦍 Starting Gorilla Mux server on :8084")
	log.Fatal(http.ListenAndServe(":8084", r))
}

func runStandardHTTPExample(def *defender.Defender) {
	mux := http.NewServeMux()

	// Apply middleware manually for standard HTTP
	protectedHandler := DefenderHTTPMiddleware(def)

	mux.Handle("/", protectedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Standard HTTP + nginx-defender</title></head>
<body>
    <h1>🌐 Standard HTTP + nginx-defender</h1>
    <p>Your IP: %s</p>
    <p>Threat Score: %s</p>
    <p>Protected by nginx-defender middleware</p>
    <p><a href="/api/health">Check Health</a></p>
</body>
</html>`, getClientIP(r), w.Header().Get("X-Threat-Score"))
	})))

	mux.Handle("/api/health", protectedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"status":       "healthy",
			"defender":     def.IsStarted(),
			"version":      defender.Version(),
			"framework":    "standard-http",
			"ip":           getClientIP(r),
			"threat_score": w.Header().Get("X-Threat-Score"),
		}
		json.NewEncoder(w).Encode(response)
	})))

	mux.Handle("/api/check", protectedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request struct {
			IP string `json:"ip"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		shouldBlock := def.ShouldBlock(request.IP)
		score := def.GetThreatScore(request.IP)

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"ip":           request.IP,
			"should_block": shouldBlock,
			"threat_score": score,
			"checked_by":   "nginx-defender",
		}
		json.NewEncoder(w).Encode(response)
	})))

	fmt.Println("🌐 Starting Standard HTTP server on :8085")
	log.Fatal(http.ListenAndServe(":8085", mux))
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	return ip
}
