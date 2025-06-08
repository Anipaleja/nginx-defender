# nginx-defender

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://golang.org/)  [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)  [![Stars](https://img.shields.io/github/stars/anipaleja/nginx-defender?style=social)](https://github.com/anipaleja/nginx-defender/stargazers)

> A real-time Nginx log monitor that detects abusive IPs and blocks them with 'iptables'. Lightweight, fast, and perfect for self-hosters, Raspberry Pi users, and small servers.

## Overview

**nginx-defender** watches your Nginx access logs and protects your server from brute-force attacks, DDoS floods, and scrapers by automatically blocking IPs that exceed a customizable request threshold within a time window.

No cloud dependencies. No bloated services. Just raw, efficient defense in pure Go.


## Features

- Real-time Nginx access log monitoring  
- Auto-blocks abusive IPs using `iptables`  
- Time window + request threshold logic  
- Unblocks IPs after timeout  
- Lightweight single-binary deployment  
- Thread-safe & efficient using Go routines and locks

## Example

If a single IP makes more than 100 requests in 60 seconds, it will be blocked via iptables for 1 hour.

This makes it ideal for:
- Self-hosted apps (like Ghost, WordPress, etc.)
- Raspberry Pi or home servers
- Lightweight VPS security


## Installation

```bash
git clone https://github.com/yourusername/nginx-defender.git
cd nginx-defender
go build -o nginx_defender ./cmd/nginx-defender
```

**Or run directly:**

```bash
sudo go run ./cmd/nginx-defender/nginx_defender.go
```
**NOTE:** sudo is required because the tool interacts with iptables
