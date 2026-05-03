#!/bin/bash

set -uo pipefail

echo "Testing nginx-defender authentication..."

# Build latest binary to test current source code behavior.
go build -o ./nginx-defender-test ./cmd/nginx-defender

# Start nginx-defender in background
./nginx-defender-test -config config.yaml -dry-run &
PID=$!

# Wait for server to start
sleep 5

echo "Testing login page..."
curl -s http://localhost:8080/login | grep -q "nginx-defender Login"
if [ $? -eq 0 ]; then
    echo "Login page is accessible"
else
    echo "Login page not accessible"
fi

echo "Testing authentication..."
# Fetch login page and extract CSRF token
CSRF_TOKEN=$(curl -s -c /tmp/nginx_defender_login.cookies http://localhost:8080/login | \
    sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')

if [ -z "$CSRF_TOKEN" ]; then
    echo "Failed to retrieve login CSRF token"
    rm -f /tmp/nginx_defender_login.cookies
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
    exit 1
fi

# Test login with correct credentials
LOGIN_STATUS=$(curl -s -o /tmp/nginx_defender_login_response.body -D /tmp/nginx_defender_login_response.headers \
    -c /tmp/nginx_defender_session.cookies -b /tmp/nginx_defender_login.cookies -X POST http://localhost:8080/login \
    -d "username=admin&password=ReplaceMe_Str0ng!2026&csrf_token=${CSRF_TOKEN}" \
    -w "%{http_code}")

LOGIN_LOCATION=$(awk 'tolower($1) == "location:" {print $2}' /tmp/nginx_defender_login_response.headers | tr -d '\r')

if [ "$LOGIN_STATUS" = "302" ] && [ "$LOGIN_LOCATION" = "/dashboard" ]; then
    echo "Authentication successful (redirect received)"
else
    echo "Authentication failed (status=${LOGIN_STATUS}, location=${LOGIN_LOCATION})"
fi

echo "Testing dashboard access..."
DASHBOARD_STATUS=$(curl -s -o /tmp/nginx_defender_dashboard.html -b /tmp/nginx_defender_session.cookies -w "%{http_code}" http://localhost:8080/dashboard)

if [ "$DASHBOARD_STATUS" = "200" ] && grep -qi "dashboard" /tmp/nginx_defender_dashboard.html; then
    echo "Dashboard is accessible"
else
    echo "Dashboard not accessible (status=${DASHBOARD_STATUS})"
fi

# Clean up
rm -f /tmp/nginx_defender_login.cookies /tmp/nginx_defender_session.cookies \
    /tmp/nginx_defender_login_response.headers /tmp/nginx_defender_login_response.body \
    /tmp/nginx_defender_dashboard.html
kill $PID 2>/dev/null
wait $PID 2>/dev/null

echo "Authentication test complete!"
