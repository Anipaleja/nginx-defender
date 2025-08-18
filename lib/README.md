# nginx-defender Library

A comprehensive, embeddable Web Application Firewall (WAF) and threat detection library for Go applications.

## Features

- 🚀 **Real-time threat detection** with ML-powered analysis
- 🍯 **Advanced honeypot system** for deception and early warning
- 🌍 **GeoIP-based blocking** with country-level restrictions
- ⚡ **Intelligent rate limiting** with adaptive thresholds
- 📊 **Comprehensive metrics** and monitoring
- 🔔 **Multi-channel notifications** (Slack, email, webhooks)
- 🎯 **Pattern-based detection** for known attack signatures
- 🧠 **Machine learning classification** for behavioral analysis
- 🔧 **Highly configurable** with production-ready defaults

## Installation

```bash
go get github.com/Anipaleja/nginx-defender/lib
```

## Quick Start

```go
package main

import (
    "log"
    
    "github.com/Anipaleja/nginx-defender/lib"
)

func main() {
    // Create defender with default configuration
    def, err := defender.New(defender.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }
    defer def.Close()
    
    // Start protection
    if err := def.Start(); err != nil {
        log.Fatal(err)
    }
    
    // Monitor log files
    def.MonitorLogFile("/var/log/nginx/access.log", defender.CombinedFormat)
    
    // Check if IP should be blocked
    if def.ShouldBlock("192.168.1.100") {
        // Handle blocking in your application
    }
}
```

## Configuration Options

### Default Configuration
```go
config := defender.DefaultConfig()
// Suitable for most applications with balanced security/performance
```

### Production Configuration
```go
config := defender.ProductionConfig()
// Optimized for production environments with enhanced security
```

### Development Configuration
```go
config := defender.DevelopmentConfig()
// Safe for development with debug logging and dry-run mode
```

### Custom Configuration
```go
config := &defender.Config{
    LogLevel:           "info",
    DryRun:             false,
    WebUI:              true,
    WebUIPort:          8080,
    EnableML:           true,
    EnableGeoIP:        true,
    EnableRateLimit:    true,
    RateLimitThreshold: 100,
    DefaultBlockTime:   time.Hour,
    GeoIPDatabase:      "/path/to/GeoLite2-City.mmdb",
    BlockedCountries:   []string{"CN", "RU"},
}
```

## Core Features

### Threat Detection
```go
// Set up threat detection callback
def.OnThreatDetected(func(event defender.ThreatEvent) {
    fmt.Printf("Threat detected: %s (Score: %d)\n", event.IP, event.Score)
    
    // Access additional threat information
    fmt.Printf("Types: %v\n", event.ThreatTypes)
    fmt.Printf("Action: %s\n", event.Action)
    
    if event.GeoInfo != nil {
        fmt.Printf("Location: %s, %s\n", event.GeoInfo.City, event.GeoInfo.Country)
    }
})
```

### Manual IP Management
```go
// Block an IP manually
err := def.BlockIP("203.0.113.1", 30*time.Minute, "Manual security review")

// Unblock an IP
err := def.UnblockIP("203.0.113.1")

// Check if IP should be blocked
shouldBlock := def.ShouldBlock("192.168.1.100")

// Get threat score
score := def.GetThreatScore("192.168.1.100")
```

### Log Monitoring
```go
// Monitor different log formats
def.MonitorLogFile("/var/log/nginx/access.log", defender.CombinedFormat)
def.MonitorLogFile("/var/log/nginx/error.log", defender.ErrorFormat)
def.MonitorLogFile("/var/log/app/custom.log", defender.CustomFormat)
```

### Event Handling
```go
// Set up block decision callback
def.OnBlockDecision(func(event defender.BlockEvent) {
    fmt.Printf("IP %s blocked for %v\n", event.IP, event.Duration)
    fmt.Printf("Reason: %s\n", event.Reason)
    
    // Integrate with your logging/alerting system
    alertSecurityTeam(event)
})
```

### Metrics and Monitoring
```go
// Get current metrics
metrics := def.GetMetrics()
fmt.Printf("Threats detected: %v\n", metrics["threats_detected"])
fmt.Printf("IPs blocked: %v\n", metrics["ips_blocked"])
fmt.Printf("Requests analyzed: %v\n", metrics["requests_analyzed"])
```

## Integration Examples

### HTTP Middleware
```go
func defenderMiddleware(def *defender.Defender) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            clientIP := getClientIP(r)
            
            if def.ShouldBlock(clientIP) {
                http.Error(w, "Access Denied", http.StatusForbidden)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
```

### Gin Framework
```go
func DefenderMiddleware(def *defender.Defender) gin.HandlerFunc {
    return func(c *gin.Context) {
        clientIP := c.ClientIP()
        
        if def.ShouldBlock(clientIP) {
            c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

### Echo Framework
```go
func DefenderMiddleware(def *defender.Defender) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            clientIP := c.RealIP()
            
            if def.ShouldBlock(clientIP) {
                return echo.NewHTTPError(http.StatusForbidden, "Access denied")
            }
            
            return next(c)
        }
    }
}
```

## Log Formats Supported

- **Combined Format**: Standard nginx/apache combined log format
- **Common Format**: Standard common log format  
- **Error Format**: Nginx/apache error log format
- **Custom Format**: User-defined regex patterns

## Advanced Features

### GeoIP Blocking
```go
config := defender.DefaultConfig()
config.EnableGeoIP = true
config.GeoIPDatabase = "/path/to/GeoLite2-City.mmdb"
config.BlockedCountries = []string{"CN", "RU", "KP"}
```

### Rate Limiting
```go
config := defender.DefaultConfig()
config.EnableRateLimit = true
config.RateLimitWindow = time.Minute
config.RateLimitThreshold = 50 // requests per window
```

### Machine Learning Detection
```go
config := defender.DefaultConfig()
config.EnableML = true
// ML models automatically classify request patterns
```

### Honeypot System
```go
config := defender.DefaultConfig()
config.EnableHoneypot = true
config.HoneypotPorts = []int{22, 23, 80, 443} // ports to monitor
config.HoneypotBindAddr = "0.0.0.0"
```

## Production Deployment

### Docker Integration
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o app .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/app .
COPY --from=builder /app/GeoLite2-City.mmdb /opt/geoip/
CMD ["./app"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-with-defender
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: app
        image: myapp:latest
        ports:
        - containerPort: 8080
        env:
        - name: DEFENDER_LOG_LEVEL
          value: "info"
        - name: DEFENDER_GEOIP_DB
          value: "/data/GeoLite2-City.mmdb"
        volumeMounts:
        - name: geoip-data
          mountPath: /data
      volumes:
      - name: geoip-data
        configMap:
          name: geoip-database
```

## Performance Considerations

- **Memory Usage**: ~50-100MB base usage, scales with active IP tracking
- **CPU Impact**: <5% overhead for typical web applications
- **Log Processing**: Can handle 10,000+ requests/second log processing
- **Storage**: Metrics and IP data stored in memory, configurable retention

## Security Features

- **Zero-day Protection**: ML-based detection of unknown attack patterns
- **Low False Positives**: Intelligent whitelisting and learning algorithms
- **Adaptive Thresholds**: Dynamic rate limiting based on traffic patterns
- **Threat Intelligence**: Integration with known malicious IP databases
- **Encrypted Communication**: TLS support for all external communications

## Monitoring and Alerting

### Prometheus Metrics
```go
// Metrics automatically exposed on configured port
// Access at http://localhost:9090/metrics
```

### Health Checks
```go
// Check defender status
if !def.IsStarted() {
    // Handle defender not running
}
```

### Custom Alerting
```go
def.OnThreatDetected(func(event defender.ThreatEvent) {
    if event.Score > 80 {
        // Send high-priority alert
        sendSlackAlert(fmt.Sprintf("High threat detected: %s", event.IP))
    }
})
```

## Examples

See the `/examples` directory for complete working examples:

- [`examples/basic/`](examples/basic/) - Basic library usage
- [`examples/advanced/`](examples/advanced/) - Advanced features and integration
- [`examples/middleware/`](examples/middleware/) - Web framework integration
- [`examples/production/`](examples/production/) - Production deployment example

## API Reference

### Types

#### `Defender`
Main library instance providing WAF and threat detection capabilities.

#### `Config`
Configuration structure for customizing defender behavior.

#### `ThreatEvent`
Event triggered when a threat is detected.

#### `BlockEvent`
Event triggered when an IP is blocked.

#### `LogFormat`
Enumeration of supported log formats.

### Methods

#### `New(config *Config) (*Defender, error)`
Creates a new defender instance.

#### `Start() error`
Starts all defender components.

#### `Stop() error`
Gracefully stops all components.

#### `MonitorLogFile(path string, format LogFormat) error`
Begins monitoring a log file for threats.

#### `ShouldBlock(ip string) bool`
Checks if an IP should be blocked.

#### `BlockIP(ip string, duration time.Duration, reason string) error`
Manually blocks an IP address.

#### `UnblockIP(ip string) error`
Removes a block on an IP address.

## License

MIT License - see [LICENSE](../LICENSE) file for details.

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## Support

- 📖 Documentation: [docs/](../docs/)
- 🐛 Issues: [GitHub Issues](https://github.com/Anipaleja/nginx-defender/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/Anipaleja/nginx-defender/discussions)
