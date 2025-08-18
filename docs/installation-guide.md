# nginx-defender: Complete Installation Guide

nginx-defender can be integrated into your security infrastructure in multiple ways. Here's how to install and use it across different ecosystems:

## Installation Options

### 1. Go Library (Native Integration)
**Best for**: Go applications, microservices, high-performance scenarios

```bash
# Install the library
go get github.com/Anipaleja/nginx-defender/lib

# Use in your Go application
import "github.com/Anipaleja/nginx-defender/lib"

def, err := defender.New(defender.DefaultConfig())
def.Start()
```

**Pros**: 
- Highest performance (in-process)
- Full feature access
- Type safety
- No network overhead

### 2. Python Package (pip install) 
**Best for**: Django, Flask, FastAPI applications

```bash
# Install via pip
pip install nginx-defender

# Use in Python
from nginx_defender import NginxDefender

with NginxDefender() as defender:
    if defender.should_block("192.168.1.100"):
        # Handle blocking
        pass
```

**Framework Integration**:
```python
# Django
MIDDLEWARE = ['nginx_defender.DjangoDefenderMiddleware']

# Flask
from nginx_defender import FlaskDefenderMiddleware
FlaskDefenderMiddleware(app, defender)
```

### 3. Node.js Package (npm install) 
**Best for**: Express, Koa, Next.js applications

```bash
# Install via npm
npm install nginx-defender

# Use in Node.js
const { NginxDefender, expressMiddleware } = require('nginx-defender');

const defender = new NginxDefender();
await defender.start();

// Express middleware
app.use(expressMiddleware(defender));
```

**Framework Integration**:
```javascript
// Express
app.use(expressMiddleware(defender));

// Koa
app.use(koaMiddleware(defender));
```

### 4. Direct nginx Integration 
**Best for**: Existing nginx deployments, multi-language stacks

```nginx
# nginx.conf
server {
    location = /defender-check {
        internal;
        proxy_pass http://127.0.0.1:8080/api/check;
    }
    
    location / {
        auth_request /defender-check;
        proxy_pass http://backend;
    }
}
```

### 5. Standalone Service 
**Best for**: Infrastructure-level protection, multiple applications

```bash
# Download and run
./nginx-defender-v2 --config config.yaml

# Or with Docker
docker run -p 8080:8080 nginx-defender:latest
```

## Which Option to Choose?

| Use Case | Recommended Option | Why |
|----------|-------------------|-----|
| **Go Application** | Go Library | Native performance, full features |
| **Python Web App** | pip install | Easy Django/Flask integration |
| **Node.js App** | npm install | Native async/await support |
| **Existing nginx** | nginx Integration | No code changes required |
| **Multi-language** | Standalone Service | Language agnostic |
| **Microservices** | Go Library + API | Best of both worlds |
| **Legacy Systems** | nginx Integration | Minimal disruption |

## Quick Start Examples

### Go Application
```go
package main

import (
    "net/http"
    "github.com/Anipaleja/nginx-defender/lib"
)

func main() {
    // Start defender
    def, _ := defender.New(defender.DefaultConfig())
    def.Start()
    defer def.Close()
    
    // HTTP handler with protection
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        clientIP := r.RemoteAddr
        
        if def.ShouldBlock(clientIP) {
            http.Error(w, "Access Denied", 403)
            return
        }
        
        w.Write([]byte("Protected by nginx-defender!"))
    })
    
    http.ListenAndServe(":8080", nil)
}
```

### Python Flask App
```python
from flask import Flask
from nginx_defender import NginxDefender, FlaskDefenderMiddleware

app = Flask(__name__)
defender = NginxDefender()
defender.start()

# Add protection middleware
FlaskDefenderMiddleware(app, defender)

@app.route('/')
def home():
    return "Protected by nginx-defender!"

if __name__ == '__main__':
    app.run()
```

### Node.js Express App
```javascript
const express = require('express');
const { NginxDefender, expressMiddleware } = require('nginx-defender');

const app = express();
const defender = new NginxDefender();

// Start defender
defender.start().then(() => {
    console.log('Protection active');
});

// Add middleware
app.use(expressMiddleware(defender));

app.get('/', (req, res) => {
    res.json({ 
        message: 'Protected by nginx-defender!',
        threatScore: req.threatScore 
    });
});

app.listen(3000);
```

### nginx Configuration
```nginx
# /etc/nginx/sites-available/protected-site
server {
    listen 80;
    server_name example.com;
    
    # nginx-defender auth endpoint
    location = /auth {
        internal;
        proxy_pass http://127.0.0.1:8080/api/check;
        proxy_pass_request_body off;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    # Protected application
    location / {
        auth_request /auth;
        
        # Add security headers
        auth_request_set $threat_score $upstream_http_x_threat_score;
        add_header X-Threat-Score $threat_score;
        add_header X-Protected-By "nginx-defender";
        
        proxy_pass http://your-backend;
    }
}
```

## Advanced Deployment

### Docker Compose
```yaml
version: '3.8'
services:
  app:
    build: .
    environment:
      - DEFENDER_ENDPOINT=http://nginx-defender:8080
    depends_on:
      - nginx-defender
      
  nginx-defender:
    image: nginx-defender:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/nginx-defender/config.yaml
      
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - app
      - nginx-defender
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: protected-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: your-app:latest
        env:
        - name: NGINX_DEFENDER_ENDPOINT
          value: "http://nginx-defender-service:8080"
          
      - name: nginx-defender
        image: nginx-defender:latest
        ports:
        - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-defender-service
spec:
  selector:
    app: protected-app
  ports:
  - port: 8080
```

## Feature Comparison

| Feature | Go Lib | Python | Node.js | nginx | Standalone |
|---------|--------|--------|---------|-------|-----------|
| **Performance** | 5/5 | 3/5 | 4/5 | 4/5 | 3/5 |
| **Ease of Use** | 3/5 | 5/5 | 5/5 | 2/5 | 4/5 |
| **Real-time** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Features** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Flexibility** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |

## Performance Guidelines

### Request Processing
- **Go Library**: <0.1ms per request
- **Python/Node.js**: 1-5ms per request (HTTP call)
- **nginx Integration**: 0.5-2ms per request
- **Standalone**: 2-10ms per request (network + processing)

### Memory Usage
- **Go Library**: 50-100MB embedded
- **Python/Node.js**: 20MB wrapper + 100MB service
- **nginx**: 10MB module + 100MB service
- **Standalone**: 100-200MB service

### Throughput
- **All options**: 10,000+ requests/second
- **Go Library**: Highest throughput (in-process)
- **Others**: Network-limited but still high performance

## Migration Paths

### From Basic nginx
1. Add `auth_request` to existing config
2. Start nginx-defender service
3. Test with monitoring mode
4. Enable blocking gradually

### From ModSecurity
1. Keep existing rules during transition
2. Deploy nginx-defender in parallel
3. Compare detection results
4. Gradually replace rules with ML detection

### From Cloud WAF
1. Deploy nginx-defender as additional layer
2. Compare threat detection
3. Fine-tune rules and ML models
4. Consider hybrid approach

## Best Practices

### Development
```bash
# Use development config
pip install nginx-defender
# or
npm install nginx-defender
# or
go get github.com/Anipaleja/nginx-defender/lib
```

### Production
```bash
# Use production config with all features
# Deploy as service for reliability
docker run -d nginx-defender:latest
```

### Monitoring
```bash
# All options provide metrics at :9090/metrics
curl http://localhost:9090/metrics
```

## Get Started Now!

Choose your preferred installation method and get enterprise-grade WAF protection in minutes:

1. **Go developers**: `go get github.com/Anipaleja/nginx-defender/lib`
2. **Python developers**: `pip install nginx-defender` 
3. **Node.js developers**: `npm install nginx-defender`
4. **nginx users**: Download binary + configure auth_request
5. **Infrastructure teams**: Deploy standalone service

All options provide the same core protection with different integration approaches. Pick what works best for your stack and get protected! 
