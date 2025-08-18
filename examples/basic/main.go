// Example: Basic usage of nginx-defender as a library
package main

import (
	"fmt"
	"log"
	"time"

	defender "github.com/Anipaleja/nginx-defender/lib"
)

func main() {
	fmt.Println("🛡️  nginx-defender Library Example")
	fmt.Println("====================================")

	// Create a new defender instance with default configuration
	def, err := defender.New(defender.DefaultConfig())
	if err != nil {
		log.Fatalf("Failed to create defender: %v", err)
	}
	defer def.Close()

	// Set up event handlers
	def.OnThreatDetected(func(event defender.ThreatEvent) {
		fmt.Printf("THREAT DETECTED: IP %s (Score: %d, Types: %v)\n",
			event.IP, event.Score, event.ThreatTypes)
	})

	def.OnBlockDecision(func(event defender.BlockEvent) {
		fmt.Printf("IP BLOCKED: %s for %v (Reason: %s)\n",
			event.IP, event.Duration, event.Reason)
	})

	// Start the defender
	if err := def.Start(); err != nil {
		log.Fatalf("Failed to start defender: %v", err)
	}

	fmt.Println("Defender started successfully")
	fmt.Printf("Web UI: http://localhost:8080\n")
	fmt.Printf("Metrics: http://localhost:9090\n")

	// Monitor a log file
	if err := def.MonitorLogFile("/tmp/nginx-logs/access.log", defender.CombinedFormat); err != nil {
		log.Printf("Warning: Failed to monitor log file: %v", err)
	} else {
		fmt.Println("Started monitoring /tmp/nginx-logs/access.log")
	}

	// Simulate checking some IPs
	testIPs := []string{
		"192.168.1.100",
		"10.0.0.1",
		"203.0.113.1",
		"invalid-ip",
	}

	fmt.Println("\nTesting IP threat analysis:")
	for _, ip := range testIPs {
		if def.ShouldBlock(ip) {
			fmt.Printf("%s - SHOULD BLOCK\n", ip)
		} else {
			score := def.GetThreatScore(ip)
			fmt.Printf("%s - Safe (Score: %d)\n", ip, score)
		}
	}

	// Manually block an IP
	fmt.Println("\nManually blocking suspicious IP...")
	if err := def.BlockIP("203.0.113.1", 5*time.Minute, "Manual block for testing"); err != nil {
		log.Printf("Failed to block IP: %v", err)
	}

	// Show metrics
	fmt.Println("\nCurrent metrics:")
	metrics := def.GetMetrics()
	for key, value := range metrics {
		fmt.Printf("  %s: %v\n", key, value)
	}

	// Keep running for a bit to see it in action
	fmt.Println("\nRunning for 30 seconds...")
	time.Sleep(30 * time.Second)

	// Unblock the IP
	fmt.Println("Unblocking IP...")
	if err := def.UnblockIP("203.0.113.1"); err != nil {
		log.Printf("Failed to unblock IP: %v", err)
	}

	fmt.Println("Example completed successfully!")
}
