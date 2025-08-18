# nginx-defender nginx Integration

Direct integration with nginx for real-time protection.

## Installation Options

### 1. Go Library (Current)
```bash
go get github.com/Anipaleja/nginx-defender/lib
```

### 2. Python Package (Coming Soon)
```bash
pip install nginx-defender
```

### 3. Node.js Package (Coming Soon)
```bash
npm install nginx-defender
```

### 4. Direct nginx Module (Planned)
```bash
# Would be compiled as nginx module
./configure --add-module=../nginx-defender-module
make && make install
```

## Current nginx Integration

### Method 1: Log Monitoring + API Calls

1. **nginx configuration:**
```nginx
# /etc/nginx/nginx.conf
http {
    # Enhanced logging for nginx-defender
    log_format defender_format '$remote_addr - $remote_user [$time_local] '
                              '"$request" $status $body_bytes_sent '
                              '"$http_referer" "$http_user_agent" '
                              '$request_time $upstream_response_time '
                              '"$http_x_forwarded_for"';
    
    # Log to file for monitoring
    access_log /var/log/nginx/defender.log defender_format;
    
    # Include defender rules
    include /etc/nginx/conf.d/defender-*.conf;
    
    server {
        listen 80;
        server_name example.com;
        
        # nginx-defender protection endpoint
        location = /defender-check {
            internal;
            proxy_pass http://127.0.0.1:8080/api/check;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Real-IP $remote_addr;
        }
        
        # Protected locations
        location / {
            # Check with defender before processing
            auth_request /defender-check;
            
            # Add security headers
            auth_request_set $defender_score $upstream_http_x_threat_score;
            add_header X-Threat-Score $defender_score;
            add_header X-Protected-By "nginx-defender";
            
            # Your application
            proxy_pass http://backend;
        }
        
        # Handle blocked requests
        error_page 403 /blocked.html;
        location = /blocked.html {
            root /usr/share/nginx/html;
            internal;
        }
    }
}
```

2. **Start nginx-defender service:**
```bash
# Start nginx-defender with API mode
./nginx-defender-test-v2 --config config.yaml &

# Monitor nginx logs
tail -f /var/log/nginx/defender.log | ./nginx-defender-test-v2 --stdin-mode
```

### Method 2: Lua Script Integration

```nginx
# /etc/nginx/nginx.conf
http {
    lua_package_path "/etc/nginx/lua/?.lua;;";
    
    # Initialize defender connection
    init_by_lua_block {
        defender = require "nginx_defender"
        defender.init("http://127.0.0.1:8080")
    }
    
    server {
        listen 80;
        
        location / {
            # Check with defender
            access_by_lua_block {
                local ip = ngx.var.remote_addr
                
                if defender.should_block(ip) then
                    ngx.status = 403
                    ngx.say("Access denied by nginx-defender")
                    ngx.exit(403)
                end
                
                local score = defender.get_threat_score(ip)
                ngx.header["X-Threat-Score"] = score
            }
            
            proxy_pass http://backend;
        }
    }
}
```

### Method 3: External Auth Module

```nginx
# Using nginx auth_request module
server {
    location = /auth {
        internal;
        proxy_pass http://nginx-defender-auth/validate;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    location / {
        auth_request /auth;
        
        # Set headers from auth response
        auth_request_set $user $upstream_http_x_user;
        auth_request_set $threat_score $upstream_http_x_threat_score;
        
        proxy_set_header X-User $user;
        proxy_set_header X-Threat-Score $threat_score;
        
        proxy_pass http://backend;
    }
}
```

## Framework-Specific Usage

### Django + nginx
```python
# Django settings
MIDDLEWARE = [
    'nginx_defender.DjangoDefenderMiddleware',
    # ... other middleware
]

# nginx.conf
upstream django {
    server unix:///path/to/your/mysite/mysite.sock;
}

server {
    location / {
        auth_request /defender-check;
        uwsgi_pass django;
        include /path/to/your/mysite/uwsgi_params;
    }
}
```

### Express + nginx
```javascript
const express = require('express');
const { expressMiddleware, NginxDefender } = require('nginx-defender');

const app = express();
const defender = new NginxDefender();

app.use(expressMiddleware(defender));

// nginx.conf proxies to this Express app
```

### Laravel + nginx
```php
// Laravel middleware
class NginxDefenderMiddleware {
    public function handle($request, Closure $next) {
        $ip = $request->ip();
        
        // Call nginx-defender API
        $response = Http::post('http://127.0.0.1:8080/api/check', ['ip' => $ip]);
        
        if ($response->json('should_block')) {
            abort(403, 'Access denied by security system');
        }
        
        return $next($request);
    }
}
```

## Real-time Integration Examples

### 1. Fail2Ban Style Integration
```bash
#!/bin/bash
# /etc/nginx-defender/ban-ip.sh

IP=$1
DURATION=${2:-3600}  # Default 1 hour
REASON=${3:-"nginx-defender auto-block"}

# Block via nginx-defender API
curl -X POST http://127.0.0.1:8080/api/block \
     -H "Content-Type: application/json" \
     -d "{\"ip\":\"$IP\",\"duration\":\"${DURATION}s\",\"reason\":\"$REASON\"}"

# Also block via iptables as backup
iptables -A INPUT -s $IP -j DROP

# Log the action
echo "$(date): Blocked $IP for ${DURATION}s - $REASON" >> /var/log/nginx-defender/blocks.log
```

### 2. Log Processing Script
```bash
#!/bin/bash
# Real-time log processing

tail -F /var/log/nginx/access.log | while read line; do
    # Extract IP from log line
    IP=$(echo "$line" | awk '{print $1}')
    
    # Send to nginx-defender for analysis
    curl -X POST http://127.0.0.1:8080/api/analyze \
         -H "Content-Type: application/json" \
         -d "{\"log_entry\":\"$line\",\"ip\":\"$IP\"}"
done
```

### 3. Dynamic nginx Configuration
```bash
#!/bin/bash
# Generate nginx config based on defender state

# Get blocked IPs from defender
BLOCKED_IPS=$(curl -s http://127.0.0.1:8080/api/blocked-ips)

# Generate nginx deny rules
echo "# Auto-generated by nginx-defender" > /etc/nginx/conf.d/defender-blocks.conf
echo "$BLOCKED_IPS" | jq -r '.[]' | while read ip; do
    echo "deny $ip;" >> /etc/nginx/conf.d/defender-blocks.conf
done

# Reload nginx
nginx -s reload
```

## Production Deployment

### Docker Compose
```yaml
version: '3.8'
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - nginx-logs:/var/log/nginx
    depends_on:
      - nginx-defender
      - app
      
  nginx-defender:
    image: nginx-defender:latest
    ports:
      - "8080:8080"
    volumes:
      - nginx-logs:/var/log/nginx
    environment:
      - DEFENDER_LOG_LEVEL=info
      - DEFENDER_WEB_UI=true
      
  app:
    image: your-app:latest
    environment:
      - DEFENDER_ENDPOINT=http://nginx-defender:8080

volumes:
  nginx-logs:
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-with-defender
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        volumeMounts:
        - name: nginx-config
          mountPath: /etc/nginx/nginx.conf
          subPath: nginx.conf
        - name: logs
          mountPath: /var/log/nginx
          
      - name: nginx-defender
        image: nginx-defender:latest
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: logs
          mountPath: /var/log/nginx
          
      volumes:
      - name: nginx-config
        configMap:
          name: nginx-config
      - name: logs
        emptyDir: {}
```

## Migration Guide

### From Traditional WAF
1. **ModSecurity**: Replace rules with nginx-defender ML detection
2. **CloudFlare**: Use nginx-defender for on-premise protection
3. **AWS WAF**: Complement with nginx-defender for hybrid protection

### Integration Steps
1. Install nginx-defender service
2. Configure nginx with auth_request or Lua
3. Update application to use defender API
4. Monitor and tune configuration
5. Gradually migrate traffic

