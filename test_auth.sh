#!/bin/bash

echo "Testing nginx-defender authentication..."

# Start nginx-defender in background
./nginx-defender-test -config config.yaml -dry-run &
PID=$!

# Wait for server to start
sleep 5

echo "Testing login page..."
curl -s http://localhost:8080/login | grep -q "nginx-defender Login"
if [ $? -eq 0 ]; then
    echo "✅ Login page is accessible"
else
    echo "❌ Login page not accessible"
fi

echo "Testing authentication..."
# Test login with correct credentials
COOKIE=$(curl -s -c - -b - -X POST http://localhost:8080/login \
    -d "username=admin&password=change_me_please" \
    -w "%{http_code}" \
    | tail -1)

if [ "$COOKIE" = "302" ]; then
    echo "✅ Authentication successful (redirect received)"
else
    echo "❌ Authentication failed"
fi

echo "Testing dashboard access..."
curl -s http://localhost:8080/dashboard | grep -q "Dashboard"
if [ $? -eq 0 ]; then
    echo "✅ Dashboard is accessible"
else
    echo "❌ Dashboard not accessible"
fi

# Clean up
kill $PID 2>/dev/null
wait $PID 2>/dev/null

echo "Authentication test complete!"
