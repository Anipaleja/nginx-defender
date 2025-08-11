# Security Configuration Guide

## Overview

This guide provides comprehensive security configuration recommendations for deploying nginx-defender in production environments. Follow these guidelines to ensure maximum security posture while maintaining optimal performance.

## Core Security Configuration

### Primary Configuration File

Create a secure `config.yaml` with the following security-focused settings:

```yaml
# Security-hardened configuration for nginx-defender
server:
  # Network security
  bind_address: "0.0.0.0"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"
  
  # TLS configuration
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/nginx-defender.crt"
    key_file: "/etc/ssl/private/nginx-defender.key"
    ca_file: "/etc/ssl/certs/ca-bundle.crt"
    min_version: "1.3"
    max_version: "1.3"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
      - "TLS_AES_128_GCM_SHA256"
    curves:
      - "X25519"
      - "P-384"
      - "P-256"
    session_timeout: "5m"
    verify_client: true
    client_cas: ["/etc/ssl/certs/client-ca.crt"]

# Authentication and authorization
auth:
  # JWT configuration
  jwt:
    secret_key_file: "/etc/secrets/jwt-secret"
    token_expiry: "15m"
    refresh_expiry: "24h"
    issuer: "nginx-defender"
    audience: "nginx-defender-api"
    
  # Multi-factor authentication
  mfa:
    enabled: true
    totp:
      issuer: "nginx-defender"
      digits: 6
      period: 30
    backup_codes:
      enabled: true
      count: 10
      
  # Session management
  session:
    timeout: "30m"
    max_concurrent: 5
    secure_cookies: true
    same_site: "strict"
    http_only: true

# Firewall configuration
firewall:
  backend: "nftables"  # Use nftables for better performance
  default_action: "drop"
  
  # IP whitelist (private networks only in production)
  whitelist:
    - "127.0.0.1"
    - "::1"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    
  # IP blacklist for known threats
  blacklist_sources:
    - name: "abuse_ch"
      url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
      format: "text"
      update_interval: "1h"
    - name: "spamhaus"
      url: "https://www.spamhaus.org/drop/drop.txt"
      format: "cidr"
      update_interval: "24h"
      
  # Rule management
  rules:
    max_rules: 10000
    cleanup_interval: "5m"
    default_duration: "1h"
    max_duration: "168h"  # 7 days

# Rate limiting
rate_limiting:
  enabled: true
  
  # Global rate limits
  global:
    requests_per_second: 1000
    burst_capacity: 2000
    
  # Per-IP rate limits
  per_ip:
    requests_per_second: 10
    requests_per_minute: 300
    requests_per_hour: 3600
    burst_capacity: 50
    
  # Per-endpoint rate limits
  endpoints:
    "/api/auth/login":
      requests_per_minute: 5
      burst_capacity: 10
    "/api/rules":
      requests_per_second: 1
      burst_capacity: 5
      
  # Geographic rate limiting
  geographic:
    enabled: true
    high_risk_countries:
      - "CN"
      - "RU"
      - "KP"
    limits:
      high_risk: 1  # req/sec
      normal: 10    # req/sec

# Web Application Firewall
waf:
  enabled: true
  mode: "block"  # "monitor" for testing, "block" for production
  
  # Core protection rules
  core_rules:
    enabled: true
    paranoia_level: 2  # 1-4, higher = more strict
    
  # OWASP Core Rule Set
  owasp_crs:
    enabled: true
    version: "3.3.0"
    
  # SQL injection protection
  sql_injection:
    enabled: true
    sensitivity: "high"
    patterns_file: "/etc/nginx-defender/patterns/sqli.yaml"
    
  # XSS protection
  xss:
    enabled: true
    sensitivity: "high"
    patterns_file: "/etc/nginx-defender/patterns/xss.yaml"
    
  # File upload security
  file_upload:
    enabled: true
    max_file_size: "10MB"
    allowed_extensions:
      - ".jpg"
      - ".jpeg"
      - ".png"
      - ".gif"
      - ".pdf"
    scan_uploads: true
    
  # Request size limits
  request_limits:
    max_request_size: "1MB"
    max_header_size: "8KB"
    max_url_length: 2048

# Machine Learning
ml:
  enabled: true
  
  # Threat detection
  threat_detection:
    model_file: "/etc/nginx-defender/models/threat_detection.joblib"
    threshold: 0.8
    confidence_threshold: 0.7
    
  # Behavioral analysis
  behavioral:
    enabled: true
    learning_period: "168h"  # 7 days
    min_samples: 1000
    anomaly_threshold: 0.95
    
  # Model updates
  model_updates:
    enabled: true
    check_interval: "24h"
    auto_update: false  # Manual approval required
    backup_models: 3

# Logging and monitoring
logging:
  level: "info"
  format: "json"
  
  # Security event logging
  security:
    enabled: true
    file: "/var/log/nginx-defender/security.log"
    rotate_size: "100MB"
    rotate_count: 30
    
  # Audit logging
  audit:
    enabled: true
    file: "/var/log/nginx-defender/audit.log"
    rotate_size: "100MB"
    rotate_count: 90
    include_requests: true
    include_responses: false
    
  # Access logging
  access:
    enabled: true
    file: "/var/log/nginx-defender/access.log"
    format: "combined"
    
  # Error logging
  error:
    enabled: true
    file: "/var/log/nginx-defender/error.log"
    
# Metrics and monitoring
metrics:
  enabled: true
  endpoint: "/metrics"
  
  # Prometheus configuration
  prometheus:
    enabled: true
    namespace: "nginx_defender"
    
  # Custom metrics
  custom:
    - name: "security_events_total"
      type: "counter"
      labels: ["event_type", "severity"]
    - name: "threat_detection_latency"
      type: "histogram"
      buckets: [0.1, 0.5, 1.0, 2.5, 5.0, 10.0]

# Notification system
notifications:
  enabled: true
  
  # Email notifications
  email:
    enabled: true
    smtp_host: "smtp.company.com"
    smtp_port: 587
    smtp_user: "nginx-defender@company.com"
    smtp_password_file: "/etc/secrets/smtp-password"
    from: "nginx-defender@company.com"
    to: ["security@company.com"]
    
  # Slack notifications
  slack:
    enabled: true
    webhook_url_file: "/etc/secrets/slack-webhook"
    channel: "#security-alerts"
    
  # PagerDuty integration
  pagerduty:
    enabled: true
    routing_key_file: "/etc/secrets/pagerduty-key"
    
  # Alert thresholds
  thresholds:
    high_threat_count: 100
    failed_auth_attempts: 10
    system_error_rate: 0.05

# Database configuration
database:
  # For production, use external database
  type: "postgresql"
  host: "localhost"
  port: 5432
  database: "nginx_defender"
  username: "nginx_defender"
  password_file: "/etc/secrets/db-password"
  
  # Connection security
  ssl_mode: "require"
  ssl_cert: "/etc/ssl/certs/db-client.crt"
  ssl_key: "/etc/ssl/private/db-client.key"
  ssl_ca: "/etc/ssl/certs/db-ca.crt"
  
  # Connection pooling
  max_connections: 20
  max_idle_connections: 5
  connection_lifetime: "1h"

# GeoIP configuration
geoip:
  enabled: true
  database_path: "/etc/nginx-defender/geoip/GeoLite2-City.mmdb"
  update_interval: "168h"  # Weekly updates
  
  # Country blocking
  blocked_countries:
    - "CN"  # China
    - "RU"  # Russia
    - "KP"  # North Korea
    - "IR"  # Iran
    
  # Allowed countries (if using allowlist mode)
  allowed_countries: []  # Empty = all allowed except blocked

# Honeypot configuration
honeypot:
  enabled: true
  
  # HTTP honeypots
  http:
    enabled: true
    paths:
      - "/admin"
      - "/wp-admin"
      - "/phpmyadmin"
      - "/.env"
      - "/config"
    response_delay: "5s"
    
  # SSH honeypot
  ssh:
    enabled: false  # Disable if not needed
    port: 2222
    
  # Actions on honeypot trigger
  actions:
    block_duration: "24h"
    alert_level: "high"
    log_details: true

# API security
api:
  # Rate limiting
  rate_limit:
    requests_per_minute: 60
    burst_capacity: 100
    
  # CORS configuration
  cors:
    enabled: true
    allowed_origins:
      - "https://dashboard.company.com"
    allowed_methods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
    allowed_headers:
      - "Authorization"
      - "Content-Type"
    max_age: "3600"
    
  # API versioning
  versioning:
    strategy: "header"  # "path" or "header"
    header_name: "API-Version"
    default_version: "v1"

# Performance tuning
performance:
  # Worker configuration
  workers: 4  # Number of CPU cores
  worker_connections: 1024
  
  # Memory limits
  max_memory_usage: "1GB"
  gc_threshold: "800MB"
  
  # Cache configuration
  cache:
    rule_cache_size: 10000
    geoip_cache_size: 100000
    ml_cache_size: 50000
    cache_ttl: "300s"

# Development and testing
development:
  enabled: false  # Must be false in production
  debug_mode: false
  profiling: false
  test_mode: false
```

## Environment-Specific Configurations

### Production Environment

```bash
# Environment variables for production
export NGINX_DEFENDER_ENV="production"
export NGINX_DEFENDER_LOG_LEVEL="info"
export NGINX_DEFENDER_DEBUG="false"
export NGINX_DEFENDER_CONFIG_FILE="/etc/nginx-defender/config.yaml"

# Security-related environment variables
export NGINX_DEFENDER_JWT_SECRET_FILE="/etc/secrets/jwt-secret"
export NGINX_DEFENDER_DB_PASSWORD_FILE="/etc/secrets/db-password"
export NGINX_DEFENDER_TLS_CERT_FILE="/etc/ssl/certs/nginx-defender.crt"
export NGINX_DEFENDER_TLS_KEY_FILE="/etc/ssl/private/nginx-defender.key"
```

### Staging Environment

```yaml
# Staging-specific overrides
logging:
  level: "debug"
  
waf:
  mode: "monitor"  # Log but don't block in staging
  
ml:
  model_updates:
    auto_update: true  # Allow auto-updates in staging
    
development:
  enabled: true
  debug_mode: true
```

### Development Environment

```yaml
# Development-specific overrides
server:
  tls:
    enabled: false  # Use HTTP in development
    
auth:
  mfa:
    enabled: false  # Disable MFA in development
    
firewall:
  backend: "mock"  # Use mock firewall
  
database:
  type: "sqlite"
  path: "/tmp/nginx-defender.db"
  
development:
  enabled: true
  debug_mode: true
  profiling: true
  test_mode: true
```

## Security Hardening

### File System Permissions

```bash
#!/bin/bash
# Set secure file permissions

# Configuration files
chmod 600 /etc/nginx-defender/config.yaml
chown nginx-defender:nginx-defender /etc/nginx-defender/config.yaml

# Secret files
chmod 600 /etc/secrets/*
chown nginx-defender:nginx-defender /etc/secrets/*

# Certificate files
chmod 600 /etc/ssl/private/nginx-defender.key
chmod 644 /etc/ssl/certs/nginx-defender.crt
chown nginx-defender:nginx-defender /etc/ssl/private/nginx-defender.key
chown nginx-defender:nginx-defender /etc/ssl/certs/nginx-defender.crt

# Log directories
mkdir -p /var/log/nginx-defender
chmod 750 /var/log/nginx-defender
chown nginx-defender:nginx-defender /var/log/nginx-defender

# Data directories
mkdir -p /var/lib/nginx-defender
chmod 750 /var/lib/nginx-defender
chown nginx-defender:nginx-defender /var/lib/nginx-defender
```

### Systemd Service Configuration

```ini
[Unit]
Description=nginx-defender WAF
After=network.target
Wants=network.target

[Service]
Type=simple
User=nginx-defender
Group=nginx-defender
ExecStart=/usr/local/bin/nginx-defender -config /etc/nginx-defender/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/nginx-defender /var/lib/nginx-defender
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictNamespaces=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=2G
CPUQuota=200%

[Install]
WantedBy=multi-user.target
```

### Container Security

```dockerfile
# Security-hardened Dockerfile
FROM golang:1.21-alpine AS builder

# Security updates
RUN apk update && apk upgrade && apk add --no-cache git ca-certificates

# Create non-root user
RUN adduser -D -s /bin/sh -u 1001 appuser

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o nginx-defender .

# Final stage
FROM scratch

# Import CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Import user
COPY --from=builder /etc/passwd /etc/passwd

# Copy binary
COPY --from=builder /app/nginx-defender /nginx-defender

# Use non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nginx-defender", "-health-check"]

ENTRYPOINT ["/nginx-defender"]
```

### Kubernetes Security

```yaml
apiVersion: v1
kind: SecurityContext
metadata:
  name: nginx-defender-security-context
runAsNonRoot: true
runAsUser: 1001
runAsGroup: 1001
fsGroup: 1001
seccompProfile:
  type: RuntimeDefault
capabilities:
  drop:
    - ALL
  add:
    - NET_ADMIN  # Required for firewall operations
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: nginx-defender-netpol
spec:
  podSelector:
    matchLabels:
      app: nginx-defender
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    - namespaceSelector:
        matchLabels:
          name: ingress
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 9090  # Metrics
  egress:
  - to: []  # Allow all egress (can be restricted as needed)
    ports:
    - protocol: TCP
      port: 53    # DNS
    - protocol: UDP
      port: 53    # DNS
    - protocol: TCP
      port: 443   # HTTPS
```

## Monitoring and Alerting

### Prometheus Monitoring

```yaml
# Prometheus scrape configuration
scrape_configs:
  - job_name: 'nginx-defender'
    static_configs:
      - targets: ['nginx-defender:9090']
    scrape_interval: 15s
    metrics_path: /metrics
    scheme: https
    tls_config:
      ca_file: /etc/ssl/certs/ca-bundle.crt
      cert_file: /etc/ssl/certs/prometheus.crt
      key_file: /etc/ssl/private/prometheus.key
```

### Alerting Rules

```yaml
groups:
- name: nginx-defender.security
  rules:
  - alert: HighThreatDetectionRate
    expr: rate(nginx_defender_threats_detected_total[5m]) > 10
    for: 2m
    labels:
      severity: warning
      component: security
    annotations:
      summary: "High rate of threats detected"
      description: "nginx-defender is detecting {{ $value }} threats per second"
      
  - alert: AuthenticationFailures
    expr: rate(nginx_defender_auth_failures_total[5m]) > 5
    for: 1m
    labels:
      severity: critical
      component: auth
    annotations:
      summary: "High authentication failure rate"
      description: "{{ $value }} authentication failures per second"
      
  - alert: WAFBypassAttempt
    expr: nginx_defender_waf_bypass_attempts_total > 0
    for: 0s
    labels:
      severity: critical
      component: waf
    annotations:
      summary: "WAF bypass attempt detected"
      description: "Potential WAF bypass attempt detected"
      
  - alert: MLModelDrift
    expr: nginx_defender_ml_model_accuracy < 0.8
    for: 5m
    labels:
      severity: warning
      component: ml
    annotations:
      summary: "ML model accuracy degraded"
      description: "Model accuracy is {{ $value }}, below threshold"
```

## Compliance Configurations

### GDPR Compliance

```yaml
# GDPR-specific configuration
privacy:
  gdpr:
    enabled: true
    
    # Data retention
    data_retention:
      logs: "30d"
      user_data: "3y"
      security_events: "6y"
      
    # Data anonymization
    anonymization:
      ip_addresses: true
      user_agents: true
      sensitive_headers: true
      
    # Consent management
    consent:
      required: true
      cookie_consent: true
      
    # Data subject rights
    subject_rights:
      access: true
      rectification: true
      erasure: true
      portability: true
```

### PCI DSS Compliance

```yaml
# PCI DSS-specific configuration
compliance:
  pci_dss:
    enabled: true
    
    # Requirement 1: Firewall configuration
    firewall:
      default_deny: true
      documented_rules: true
      
    # Requirement 2: Default passwords
    passwords:
      no_defaults: true
      complexity_requirements: true
      
    # Requirement 3: Cardholder data protection
    data_protection:
      encryption_at_rest: true
      encryption_in_transit: true
      key_management: "hsm"
      
    # Requirement 10: Logging and monitoring
    logging:
      all_access: true
      failed_attempts: true
      changes_to_privileges: true
      audit_trail_protection: true
```

This comprehensive security configuration guide provides the foundation for a secure nginx-defender deployment across different environments while maintaining compliance with various security standards and regulations.
