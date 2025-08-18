// Example: Advanced usage with custom configuration
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	defender "github.com/Anipaleja/nginx-defender/lib"
)

func main() {
	fmt.Println("nginx-defender Advanced Library Example")
	fmt.Println("=============================================")

	// Create custom configuration for production-like usage
	config := defender.ProductionConfig()
	config.EnableGeoIP = false // Disable for this example
	config.RateLimitThreshold = 20
	config.DefaultBlockTime = 10 * time.Minute
	config.WebUIPort = 8081

	// Create defender with custom config
	def, err := defender.New(config)
	if err != nil {
		log.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	// Set up detailed event handlers
	def.OnThreatDetected(func(event defender.ThreatEvent) {
		fmt.Printf("[%s] THREAT: %s (Score: %d)\n",
			event.Timestamp.Format("15:04:05"), event.IP, event.Score)

		if event.GeoInfo != nil {
			fmt.Printf("    Location: %s, %s\n", event.GeoInfo.City, event.GeoInfo.Country)
		}

		fmt.Printf("    Types: %v\n", event.ThreatTypes)
		fmt.Printf("    Action: %s\n", event.Action)
	})

	def.OnBlockDecision(func(event defender.BlockEvent) {
		fmt.Printf("[%s] BLOCKED: %s\n",
			event.Timestamp.Format("15:04:05"), event.IP)
		fmt.Printf("    Duration: %v\n", event.Duration)
		fmt.Printf("    Reason: %s\n", event.Reason)
	})

	// Start the defender
	if err := def.Start(); err != nil {
		log.Fatalf("Failed to start defender: %v", err)
	}

	fmt.Println("Advanced defender started")
	fmt.Printf("Management UI: http://localhost:%d\n", config.WebUIPort)

	// Monitor multiple log files
	logFiles := []struct {
		path   string
		format defender.LogFormat
	}{
		{"/var/log/nginx/access.log", defender.CombinedFormat},
		{"/var/log/nginx/error.log", defender.ErrorFormat},
		{"/tmp/app.log", defender.CustomFormat},
	}

	for _, logFile := range logFiles {
		if err := def.MonitorLogFile(logFile.path, logFile.format); err != nil {
			fmt.Printf("Warning: Cannot monitor %s: %v\n", logFile.path, err)
		} else {
			fmt.Printf("Monitoring: %s (%s format)\n", logFile.path, logFile.format)
		}
	}

	// Set up a simple HTTP server to demonstrate integration
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr

		// Check if the IP should be blocked
		if def.ShouldBlock(clientIP) {
			http.Error(w, "Access Denied - Blocked by nginx-defender", http.StatusForbidden)
			return
		}

		// Get threat score for logging
		score := def.GetThreatScore(clientIP)

		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>nginx-defender Protected Site</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .safe { color: green; }
        .warning { color: orange; }
        .danger { color: red; }
    </style>
</head>
<body>
    <h1>Welcome to nginx-defender Protected Site</h1>
    <p>Your IP: <strong>%s</strong></p>
    <p>Threat Score: <span class="%s">%d</span></p>
    <p>Status: <span class="safe">Access Granted</span></p>
    
    <h2>Protection Features Active:</h2>
    <ul>
        <li>Real-time threat detection</li>
        <li>Rate limiting</li>
        <li>ML-powered analysis</li>
        <li>Honeypot system</li>
        <li>Advanced logging</li>
    </ul>
    
    <p><em>Powered by nginx-defender v%s</em></p>
</body>
</html>`, clientIP, getThreatClass(score), score, defender.Version())
	})

	// Start HTTP server
	go func() {
		fmt.Println("Starting demo web server on :8082")
		if err := http.ListenAndServe(":8082", nil); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Simulate some activities
	fmt.Println("\n🎭 Simulating security events...")

	// Test different scenarios
	scenarios := []struct {
		ip     string
		reason string
		action string
	}{
		{"192.168.1.100", "Suspicious scanning activity", "monitor"},
		{"10.0.0.50", "Rate limit exceeded", "block"},
		{"203.0.113.10", "Known malicious IP", "block"},
	}

	for i, scenario := range scenarios {
		fmt.Printf("\nScenario %d: %s\n", i+1, scenario.reason)

		if scenario.action == "block" {
			if err := def.BlockIP(scenario.ip, 2*time.Minute, scenario.reason); err != nil {
				log.Printf("Failed to block IP: %v", err)
			}
		}

		// Check status
		blocked := def.ShouldBlock(scenario.ip)
		score := def.GetThreatScore(scenario.ip)

		fmt.Printf("  IP: %s, Blocked: %v, Score: %d\n", scenario.ip, blocked, score)

		time.Sleep(2 * time.Second)
	}

	// Show final metrics
	fmt.Println("\nFinal metrics:")
	metrics := def.GetMetrics()
	for key, value := range metrics {
		fmt.Printf("  %s: %v\n", key, value)
	}

	fmt.Println("\nDemo server running at: http://localhost:8082")
	fmt.Println("Keeping services running for 2 minutes...")
	fmt.Println("   Try accessing the demo server to see protection in action!")

	time.Sleep(2 * time.Minute)

	fmt.Println("Advanced example completed!")
}

func getThreatClass(score int) string {
	if score >= 70 {
		return "danger"
	} else if score >= 30 {
		return "warning"
	}
	return "safe"
}
