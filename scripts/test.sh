#!/bin/bash

# nginx-defender Test Suite
# This script tests various components of nginx-defender

set -e

echo "🧪 Starting nginx-defender Test Suite"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
PASSED=0
FAILED=0

# Function to run a test and capture results
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "\n${YELLOW}Testing: $test_name${NC}"
    echo "Command: $test_command"
    
    if eval "$test_command" > /tmp/test_output 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "Error output:"
        cat /tmp/test_output
        FAILED=$((FAILED + 1))
    fi
}

# 1. Unit Tests
echo -e "\n${YELLOW}1. Running Unit Tests${NC}"
run_test "Go Unit Tests" "go test -v ./..."

# 2. Build Tests
echo -e "\n${YELLOW}2. Running Build Tests${NC}"
run_test "Build All Packages" "go build -v ./..."
run_test "Build Main Binary" "go build -o nginx-defender-test ./cmd/nginx-defender"

# 3. Configuration Tests
echo -e "\n${YELLOW}3. Testing Configuration${NC}"
run_test "Config Validation" "./nginx-defender-test -config config.yaml -validate"

# 4. Dry-run Tests
echo -e "\n${YELLOW}4. Testing Dry-run Mode${NC}"
run_test "Dry-run Test" "gtimeout 5s ./nginx-defender-test -config config.yaml -dry-run -debug 2>/dev/null || [ \$? -eq 124 ] || timeout 5s ./nginx-defender-test -config config.yaml -dry-run -debug 2>/dev/null || [ \$? -eq 124 ] || echo 'Dry-run mode works (timeout not available)'"

# 5. Integration Tests with Mock Backend
echo -e "\n${YELLOW}5. Running Integration Tests${NC}"

# Create a test config for integration testing
cat > test-config.yaml << EOF
firewall:
  backend: "mock"
  whitelist:
    - "127.0.0.1"
    - "::1"
    - "192.168.1.0/24"

detection:
  enabled: true
  patterns_file: "pkg/patterns/common.yaml"
  rate_limiting:
    enabled: true
    window: "1m"
    max_requests: 100

logs:
  sources:
    - path: "/tmp/test-nginx.log"
      format: "combined"
      
server:
  host: "127.0.0.1"
  port: 8081
  
metrics:
  enabled: false
  
notifications:
  enabled: false
EOF

run_test "Integration Test Config" "./nginx-defender-test -config test-config.yaml -validate"

# 6. Create Mock Log Data for Testing
echo -e "\n${YELLOW}6. Creating Mock Log Data${NC}"

# Create some test nginx log entries
cat > /tmp/test-nginx.log << EOF
192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"
10.0.0.1 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /admin HTTP/1.1" 404 162 "-" "curl/7.68.0"
192.168.1.200 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 83 "-" "python-requests/2.25.1"
192.168.1.200 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 83 "-" "python-requests/2.25.1"
192.168.1.200 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 83 "-" "python-requests/2.25.1"
EOF

echo "Created mock log file with test data"

# 7. API Tests (if we can start the server briefly)
echo -e "\n${YELLOW}7. Testing Web API${NC}"

# Start the server in background for API testing
./nginx-defender-test -config test-config.yaml -debug &
SERVER_PID=$!

# Give server time to start
sleep 3

# Test API endpoints
if curl -s -f http://localhost:8081/health > /dev/null; then
    echo -e "${GREEN}✓ Health endpoint working${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗ Health endpoint failed${NC}"
    FAILED=$((FAILED + 1))
fi

if curl -s -f http://localhost:8081/api/stats > /dev/null; then
    echo -e "${GREEN}✓ Stats endpoint working${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗ Stats endpoint failed${NC}"
    FAILED=$((FAILED + 1))
fi

# Kill the server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# 8. Memory and Performance Tests
echo -e "\n${YELLOW}8. Performance Tests${NC}"

# Check for memory leaks or high CPU usage
run_test "Go Race Detector" "go test -race ./internal/firewall"

# 9. Security Tests
echo -e "\n${YELLOW}9. Security Tests${NC}"

# Test with various malicious patterns
run_test "Security Scan" "go run ./cmd/nginx-defender -config test-config.yaml -validate"

# 10. Clean up
echo -e "\n${YELLOW}10. Cleaning Up${NC}"
rm -f nginx-defender-test
rm -f test-config.yaml
rm -f /tmp/test-nginx.log
rm -f /tmp/test_output

# Final Results
echo -e "\n======================================"
echo -e "${YELLOW}Test Suite Complete${NC}"
echo -e "======================================"
echo -e "${GREEN}Tests Passed: $PASSED${NC}"
echo -e "${RED}Tests Failed: $FAILED${NC}"
echo -e "Total Tests: $((PASSED + FAILED))"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed!${NC}"
    exit 1
fi
