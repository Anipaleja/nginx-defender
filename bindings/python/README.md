# nginx-defender Python Package

Python bindings for the nginx-defender Web Application Firewall and threat detection system.

## Installation

```bash
pip install nginx-defender
```

## Quick Start

```python
from nginx_defender import NginxDefender

# Initialize the defender
defender = NginxDefender()

# Start monitoring
defender.start()

# Check if an IP should be blocked
if defender.should_block("192.168.1.100"):
    print("IP should be blocked!")

# Monitor log files
defender.monitor_log_file("/var/log/nginx/access.log", "combined")
```

## Features

- Real-time threat detection
- IP blocking and monitoring
- Log file analysis
- Flask and Django middleware integration
- Configurable threat scoring
- Geolocation-based filtering

## Documentation

For full documentation, visit: <https://github.com/Anipaleja/nginx-defender>

## License

MIT License - see LICENSE file for details.
