# nginx-defender v2.0

[![Build Status](https://github.com/anipaleja/nginx-defender/workflows/Build%20and%20Publish/badge.svg)](https://github.com/anipaleja/nginx-defender/actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/ghcr.io/anipaleja/nginx-defender)](https://github.com/anipaleja/nginx-defender/pkgs/container/nginx-defender)
[![Go Report Card](https://goreportcard.com/badge/github.com/anipaleja/nginx-defender)](https://goreportcard.com/report/github.com/anipaleja/nginx-defender)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**nginx-defender** is an advanced, enterprise-grade Web Application Firewall (WAF) and threat detection system designed to protect your web applications from sophisticated attacks. Built with Go, it provides real-time threat detection, machine learning-based anomaly detection, and comprehensive security monitoring.

## Features

### Advanced Threat Detection
- **Machine Learning Integration**: Anomaly detection and behavioral analysis
- **Real-time Threat Intelligence**: Automated feeds from multiple sources
- **Multi-layered Protection**: Rate limiting, DDoS protection, brute force detection
- **Pattern-based Detection**: SQL injection, XSS, command injection, directory traversal
- **Geographic Filtering**: Country-based blocking with threat scoring
- **Behavioral Analysis**: Session tracking and navigation pattern analysis

### Firewall Management
- **Multiple Backend Support**: iptables, nftables, UFW, firewalld, pf
- **Async Rule Processing**: High-performance rule management
- **Automatic Cleanup**: Time-based rule expiration
- **Rule Persistence**: Backup and restore capabilities
- **IP Range Management**: Built-in threat intelligence data

### Monitoring & Analytics
- **Real-time Dashboard**: Web-based management interface
- **Prometheus Metrics**: Comprehensive metrics collection
- **WebSocket Updates**: Live threat feeds and notifications
- **Geographic Visualization**: Global threat mapping
- **Performance Monitoring**: System resource tracking

### Multi-channel Notifications
- **Telegram Integration**: Real-time threat alerts
- **Slack Notifications**: Team collaboration features
- **Email Alerts**: SMTP-based notifications
- **Webhook Support**: Custom integrations
- **Discord & PagerDuty**: Additional notification channels

### Honeypot System
- **Service Emulation**: SSH, HTTP, FTP, Telnet honeypots
- **Attack Intelligence**: Detailed interaction logging
- **Threat Boost**: Enhanced scoring for honeypot attackers

### High Performance
- **Clustering Support**: Multi-node deployment
- **Connection Pooling**: Optimized database connections
- **Caching Layer**: High-speed threat detection
- **Async Processing**: Non-blocking operations
