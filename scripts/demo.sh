#!/bin/bash

# nginx-defender Manual Testing Script
# This script demonstrates nginx-defender capabilities

set -e

echo "🛡️  nginx-defender Manual Testing Demo"
echo "======================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Build the application
echo -e "${BLUE}Building nginx-defender...${NC}"
go build -o nginx-defender-demo ./cmd/nginx-defender

# Create test configuration
echo -e "${BLUE}Creating test configuration...${NC}"
cat > demo-config.yaml << EOF
firewall:
  backend: "mock"  # Use mock backend for safe testing
  whitelist:
    - "127.0.0.1"
    - "::1"
    - "192.168.1.0/24"

detection:
  enabled: true
  ml_model: ""  # Disable ML for demo
  patterns_file: "pkg/patterns/common.yaml"
  rate_limiting:
    enabled: true
    window: "1m"
    max_requests: 10
  geo_blocking:
    enabled: false

logs:
  level: "info"
  format: "text"
  output: "stdout"
  sources:
    - path: "/tmp/demo-nginx.log"
      format: "combined"
      follow: true

server:
  host: "127.0.0.1"
  port: 8080
  tls:
    enabled: false

metrics:
  enabled: true
  prometheus:
    enabled: true
    host: "127.0.0.1"
    port: 9090

notifications:
  enabled: true
  channels:
    console:
      enabled: true
    email:
      enabled: false
    telegram:
      enabled: false
    slack:
      enabled: false
EOF

# Create demo nginx log file with various attack patterns
echo -e "${BLUE}Creating demo log file with attack patterns...${NC}"
cat > /tmp/demo-nginx.log << EOF
# Normal traffic
192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
192.168.1.101 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /about HTTP/1.1" 200 1234 "http://example.com/" "Mozilla/5.0"

# SQL Injection attempts
10.0.0.1 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /search?q='; DROP TABLE users; -- HTTP/1.1" 403 0 "-" "curl/7.68.0"
10.0.0.1 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 400 0 "-" "sqlmap/1.4.7" "username=admin' OR '1'='1"

# XSS attempts
10.0.0.2 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /comment?text=<script>alert('xss')</script> HTTP/1.1" 403 0 "-" "Mozilla/5.0"

# Directory traversal
10.0.0.3 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /../../../etc/passwd HTTP/1.1" 404 162 "-" "curl/7.68.0"
10.0.0.3 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /..\\..\\..\\windows\\system32\\config\\sam HTTP/1.1" 404 162 "-" "wget/1.20.3"

# Brute force login attempts
10.0.0.4 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 83 "-" "python-requests/2.25.1"
10.0.0.4 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 83 "-" "python-requests/2.25.1"
10.0.0.4 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 83 "-" "python-requests/2.25.1"
10.0.0.4 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 83 "-" "python-requests/2.25.1"
10.0.0.4 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /login HTTP/1.1" 401 83 "-" "python-requests/2.25.1"

# Scanner/bot traffic
10.0.0.5 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /admin HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
10.0.0.5 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /wp-admin HTTP/1.1" 404 162 "-" "Nikto/2.1.6"
10.0.0.5 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "Nikto/2.1.6"

# Rate limiting test - many requests from same IP
EOF

# Add rapid requests for rate limiting test
for i in {1..15}; do
    echo "10.0.0.6 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /api/data HTTP/1.1\" 200 100 \"-\" \"curl/7.68.0\"" >> /tmp/demo-nginx.log
done

echo -e "${GREEN}Demo environment prepared!${NC}"
echo ""

# Function to show menu
show_menu() {
    echo -e "${YELLOW}Select a test to run:${NC}"
    echo "1. Validate Configuration"
    echo "2. Start nginx-defender (dry-run mode)"
    echo "3. Test Web Dashboard (manual)"
    echo "4. Add New Attack Patterns to Log"
    echo "5. View Current Firewall Rules"
    echo "6. Test API Endpoints"
    echo "7. Run All Tests"
    echo "8. Clean Up and Exit"
    echo ""
    echo -n "Enter your choice (1-8): "
}

# Function to validate config
test_config() {
    echo -e "${BLUE}Testing configuration validation...${NC}"
    ./nginx-defender-demo -config demo-config.yaml -validate
    echo -e "${GREEN}✓ Configuration is valid${NC}"
}

# Function to start in dry-run mode
start_dry_run() {
    echo -e "${BLUE}Starting nginx-defender in dry-run mode...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    ./nginx-defender-demo -config demo-config.yaml -dry-run -debug
}

# Function to show web dashboard info
show_web_info() {
    echo -e "${BLUE}Web Dashboard Information:${NC}"
    echo "Once nginx-defender is running, you can access:"
    echo "• Web Dashboard: http://localhost:8080"
    echo "• API Endpoints: http://localhost:8080/api/*"
    echo "• Metrics: http://localhost:9090/metrics"
    echo ""
    echo -e "${YELLOW}Start nginx-defender and then open these URLs in your browser${NC}"
}

# Function to add new attack patterns
add_attack_patterns() {
    echo -e "${BLUE}Adding new attack patterns to log...${NC}"
    
    # Add some more attack patterns
    cat >> /tmp/demo-nginx.log << EOF

# New attack patterns added at $(date)
# Command injection attempts
10.0.0.10 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /cgi-bin/test.cgi?cmd=cat%20/etc/passwd HTTP/1.1" 403 0 "-" "curl/7.68.0"
10.0.0.11 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /upload HTTP/1.1" 400 0 "-" "curl/7.68.0" "file=test.php; system('whoami');"

# Large request (potential DoS)
10.0.0.12 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /submit HTTP/1.1" 413 0 "-" "python-requests/2.25.1" "$(printf 'A%.0s' {1..1000})"

# Suspicious user agents
10.0.0.13 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET / HTTP/1.1" 200 612 "-" "ZmEu"
10.0.0.14 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET / HTTP/1.1" 200 612 "-" "masscan"
EOF

    echo -e "${GREEN}✓ New attack patterns added to log${NC}"
    echo "Log file updated: /tmp/demo-nginx.log"
}

# Function to show current rules (mock)
show_rules() {
    echo -e "${BLUE}Current Firewall Rules (simulated):${NC}"
    echo "Since we're using mock backend, here are example rules that would be created:"
    echo ""
    echo -e "${RED}BLOCKED IPs:${NC}"
    echo "• 10.0.0.1 - SQL Injection attempts (expires in 1h)"
    echo "• 10.0.0.2 - XSS attempts (expires in 30m)"
    echo "• 10.0.0.4 - Brute force login (expires in 2h)"
    echo "• 10.0.0.5 - Scanner/bot activity (expires in 1h)"
    echo "• 10.0.0.6 - Rate limit exceeded (expires in 15m)"
    echo ""
    echo -e "${GREEN}WHITELISTED IPs:${NC}"
    echo "• 127.0.0.1 - Localhost"
    echo "• 192.168.1.0/24 - Local network"
}

# Function to test API endpoints
test_api() {
    echo -e "${BLUE}Testing API endpoints...${NC}"
    echo "This requires nginx-defender to be running."
    echo "Start it in another terminal with: ./nginx-defender-demo -config demo-config.yaml"
    echo ""
    echo "Testing endpoints:"
    
    # Test health endpoint
    echo -n "• Health endpoint: "
    if curl -s -f http://localhost:8080/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Working${NC}"
    else
        echo -e "${RED}✗ Not available (is nginx-defender running?)${NC}"
    fi
    
    # Test stats endpoint
    echo -n "• Stats endpoint: "
    if curl -s -f http://localhost:8080/api/stats > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Working${NC}"
        echo "  Sample response:"
        curl -s http://localhost:8080/api/stats | head -10
    else
        echo -e "${RED}✗ Not available${NC}"
    fi
    
    # Test rules endpoint
    echo -n "• Rules endpoint: "
    if curl -s -f http://localhost:8080/api/rules > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Working${NC}"
    else
        echo -e "${RED}✗ Not available${NC}"
    fi
}

# Function to run all tests
run_all_tests() {
    echo -e "${BLUE}Running all available tests...${NC}"
    
    test_config
    echo ""
    
    show_rules
    echo ""
    
    add_attack_patterns
    echo ""
    
    echo -e "${YELLOW}For complete testing, start nginx-defender in another terminal and test the web interface${NC}"
}

# Function to clean up
cleanup() {
    echo -e "${BLUE}Cleaning up demo files...${NC}"
    rm -f nginx-defender-demo
    rm -f demo-config.yaml
    rm -f /tmp/demo-nginx.log
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Main loop
while true; do
    echo ""
    show_menu
    read -r choice
    
    case $choice in
        1)
            test_config
            ;;
        2)
            start_dry_run
            ;;
        3)
            show_web_info
            ;;
        4)
            add_attack_patterns
            ;;
        5)
            show_rules
            ;;
        6)
            test_api
            ;;
        7)
            run_all_tests
            ;;
        8)
            cleanup
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please select 1-8.${NC}"
            ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
done
