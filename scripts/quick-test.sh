#!/bin/bash

echo "🧪 Quick nginx-defender Functionality Test"
echo "=========================================="

# Build the application
go build -o nginx-defender-quick-test ./cmd/nginx-defender

# Test 1: Configuration validation
echo "1. Testing configuration validation..."
if ./nginx-defender-quick-test -config config.yaml -validate > /dev/null 2>&1; then
    echo "✅ Configuration validation: PASSED"
else
    echo "❌ Configuration validation: FAILED"
fi

# Test 2: Unit tests
echo "2. Running unit tests..."
if go test ./internal/firewall > /dev/null 2>&1; then
    echo "✅ Unit tests: PASSED"
else
    echo "❌ Unit tests: FAILED"
fi

# Test 3: Build test
echo "3. Testing build..."
if go build ./... > /dev/null 2>&1; then
    echo "✅ Build test: PASSED"
else
    echo "❌ Build test: FAILED"
fi

# Test 4: Regex patterns test
echo "4. Testing regex patterns..."
go run -c '
package main
import (
    "fmt"
    "regexp"
)
func main() {
    pattern := `(?i)(include|require)(_once)?\\s*\\([^)]*\\.(php|asp|jsp)\\)`
    _, err := regexp.Compile(pattern)
    if err != nil {
        fmt.Printf("Pattern error: %v\n", err)
        return
    }
    fmt.Println("Pattern compilation successful")
}'

if [ $? -eq 0 ]; then
    echo "✅ Regex patterns: PASSED"
else
    echo "❌ Regex patterns: FAILED"
fi

# Test 5: Mock firewall test
echo "5. Testing mock firewall backend..."
cat > quick_test.go << 'EOF'
package main

import (
    "time"
    "github.com/Anipaleja/nginx-defender/internal/config"
    "github.com/Anipaleja/nginx-defender/internal/firewall"
    "github.com/sirupsen/logrus"
)

func main() {
    cfg := config.FirewallConfig{
        Backend: "mock",
        Whitelist: []string{"127.0.0.1"},
    }
    
    logger := logrus.New()
    logger.SetLevel(logrus.ErrorLevel)
    
    manager, err := firewall.NewManager(cfg, logger)
    if err != nil {
        panic(err)
    }
    defer manager.Shutdown()
    
    // Test blocking
    err = manager.BlockIP("192.168.1.100", firewall.ActionBlock, 5*time.Minute, "test", nil)
    if err != nil {
        panic(err)
    }
    
    time.Sleep(100 * time.Millisecond)
    
    blocked, _ := manager.IsBlocked("192.168.1.100")
    if !blocked {
        panic("IP should be blocked")
    }
    
    println("Mock firewall test successful")
}
EOF

if go run quick_test.go > /dev/null 2>&1; then
    echo "✅ Mock firewall: PASSED"
else
    echo -n "❌ Mock firewall: FAILED - "
    go run quick_test.go 2>&1 | head -1
fi

# Clean up
rm -f nginx-defender-quick-test quick_test.go

echo ""
echo "🎯 Quick test complete!"
echo ""
echo "📝 Manual Testing Instructions:"
echo "1. Run: go build -o nginx-defender ./cmd/nginx-defender"
echo "2. Test dry-run: ./nginx-defender -config config.yaml -dry-run"
echo "3. Test web interface: ./nginx-defender -config config.yaml"
echo "4. Visit: http://localhost:8080 for web dashboard"
echo "5. Visit: http://localhost:9090/metrics for Prometheus metrics"
echo ""
echo "🔧 Debugging:"
echo "- Use -debug flag for verbose logging"
echo "- Use -dry-run flag to test without actual firewall changes"
echo "- Check logs for detailed error information"
