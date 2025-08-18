# nginx-defender Python Package

A Python wrapper for the nginx-defender Web Application Firewall.

## Installation

```bash
pip install nginx-defender
```

## Requirements

- Python 3.7+
- nginx-defender service binary
- requests library

## Quick Start

```python
from nginx_defender import NginxDefender

# Basic usage
with NginxDefender() as defender:
    # Check if IP should be blocked
    if defender.should_block("192.168.1.100"):
        print("IP should be blocked!")
    
    # Get threat score
    score = defender.get_threat_score("192.168.1.100")
    print(f"Threat score: {score}")
    
    # Monitor log files
    defender.monitor_log_file("/var/log/nginx/access.log", "combined")
    
    # Block IP manually
    defender.block_ip("203.0.113.1", duration_minutes=30, reason="Suspicious activity")
```

## Framework Integration

### Flask

```python
from flask import Flask
from nginx_defender import NginxDefender, FlaskDefenderMiddleware

app = Flask(__name__)
defender = NginxDefender()
defender.start()

# Add middleware
FlaskDefenderMiddleware(app, defender)

@app.route('/')
def home():
    return "Protected by nginx-defender!"
```

### Django

```python
# settings.py
MIDDLEWARE = [
    'nginx_defender.DjangoDefenderMiddleware',
    # ... other middleware
]
```

## Configuration

```python
config = {
    "log_level": "info",
    "dry_run": False,
    "web_ui": True,
    "web_ui_port": 8080,
    "metrics_port": 9090,
}

defender = NginxDefender(config)
```

## Event Handling

```python
def on_threat(event):
    print(f"Threat detected: {event.ip} (Score: {event.score})")

def on_block(event):
    print(f"IP blocked: {event.ip} for {event.duration}")

defender.on_threat_detected(on_threat)
defender.on_block_decision(on_block)
```
