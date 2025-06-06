// logguard.go
//
// Auto-Rate Limiter & Threat Blocker for Nginx logs
//
// Watches the Nginx access log file in real time,
// detects abusive IPs (e.g., >100 requests in 60s),
// blocks them via iptables,
// and logs actions.
//
// Requires Linux, iptables installed, and permissions to run iptables commands.
//
// Usage:
//   go run logguard.go -log /var/log/nginx/access.log -threshold 100 -window 60 -blocktime 3600
//
// Flags:
//   -log       Path to access log file
//   -threshold Number of requests to trigger block (default 100)
//   -window    Time window in seconds (default 60)
//   -blocktime Block duration in seconds (default 3600 = 1 hour)

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

var (
	logFilePath string
	threshold   int
	windowSec   int
	blockTime   int
)

type ipRecord struct {
	timestamps []time.Time
	blockedAt  time.Time
}

var (
	ipMap   = make(map[string]*ipRecord)
	mapLock sync.Mutex
)

var ipRegex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}`) // extract IP at start of line

func main() {
	flag.StringVar(&logFilePath, "log", "/var/log/nginx/access.log", "Path to nginx access log")
	flag.IntVar(&threshold, "threshold", 100, "Request threshold to block IP")
	flag.IntVar(&windowSec, "window", 60, "Time window in seconds")
	flag.IntVar(&blockTime, "blocktime", 3600, "Block duration in seconds")
	flag.Parse()

	fmt.Printf("Starting LogGuard\nMonitoring: %s\nThreshold: %d reqs per %d seconds\nBlock duration: %d seconds\n",
		logFilePath, threshold, windowSec, blockTime)

	file, err := os.Open(logFilePath)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	// Seek to end of file to only read new lines
	file.Seek(0, os.SEEK_END)

	reader := bufio.NewReader(file)

	// Start cleanup goroutine to unblock IPs after blockTime
	go unblockRoutine()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			// No new line yet, sleep briefly
			time.Sleep(200 * time.Millisecond)
			continue
		}
		processLine(line)
	}
}

func processLine(line string) {
	ip := extractIP(line)
	if ip == "" {
		return
	}
	now := time.Now()

	mapLock.Lock()
	defer mapLock.Unlock()

	record, exists := ipMap[ip]
	if !exists {
		record = &ipRecord{timestamps: []time.Time{}}
		ipMap[ip] = record
	}

	// If blocked, ignore requests from this IP (optional: could track still)
	if !record.blockedAt.IsZero() {
		return
	}

	// Append new timestamp
	record.timestamps = append(record.timestamps, now)

	// Remove timestamps older than windowSec
	cutoff := now.Add(-time.Duration(windowSec) * time.Second)
	var filtered []time.Time
	for _, t := range record.timestamps {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	record.timestamps = filtered

	// Check threshold
	if len(record.timestamps) >= threshold {
		blockIP(ip)
		record.blockedAt = now
		log.Printf("Blocked IP %s for %d seconds after %d requests in %d seconds", ip, blockTime, len(record.timestamps), windowSec)
	}
}

func extractIP(line string) string {
	ip := ipRegex.FindString(line)
	return ip
}

func blockIP(ip string) {
	cmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		log.Printf("Failed to block IP %s: %v", ip, err)
	} else {
		log.Printf("IP %s blocked via iptables", ip)
	}
}

func unblockRoutine() {
	for {
		time.Sleep(60 * time.Second)
		now := time.Now()

		mapLock.Lock()
		for ip, record := range ipMap {
			if record.blockedAt.IsZero() {
				continue
			}
			if now.Sub(record.blockedAt).Seconds() > float64(blockTime) {
				unblockIP(ip)
				record.blockedAt = time.Time{}
				record.timestamps = []time.Time{}
				log.Printf("Unblocked IP %s after block period", ip)
			}
		}
		mapLock.Unlock()
	}
}

func unblockIP(ip string) {
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		log.Printf("Failed to unblock IP %s: %v", ip, err)
	} else {
		log.Printf("IP %s unblocked via iptables", ip)
	}
}
