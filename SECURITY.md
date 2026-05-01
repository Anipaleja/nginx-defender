# Security Policy

## Overview

nginx-defender is an enterprise-grade Web Application Firewall (WAF) and network security solution designed with security-first principles. This document outlines our security policies, vulnerability reporting procedures, and security best practices for deployment and usage.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          | Notes                    |
| ------- | ------------------ | ------------------------ |
| 2.1.0   | Yes                | Future Release
| 2.0.0   | Yes                | Current stable release   | 
| 1.5.0   | Yes                | Previous Release         |
| 1.4.2   | Yes                | LTS support until 2025   |
| 1.4.1   | Yes                | Security fixes only      |
| < 1.4   | No                 | End of life              |

## Security Architecture

### Threat Model

The primary adversaries are:

- Remote opportunistic attackers performing scanning, exploitation, and credential stuffing.
- Automated botnets and scraping infrastructure rotating IPs and user agents.
- Targeted attackers attempting WAF evasion via low and slow behavior.
- Misconfiguration-driven insider risk (overly broad trust boundaries, weak credentials).

### Attack Surface Analysis

Primary exposed surfaces:

- Log ingestion pipeline (untrusted request metadata and payload artifacts).
- Administrative API and web interface.
- Firewall orchestration backend calls.
- Model state persistence and plugin loading path.

Mitigations in this project include:

- Strict config validation with rejection of weak/default credentials.
- Authenticated API operations with CSRF and session protection.
- Confidence-based mitigation escalation to reduce false positives.
- Optional plugin loading controlled by explicit environment configuration.
- Restricted file permissions for persisted model state and sensitive artifacts.

### Core Security Features

1. **Multi-Backend Firewall Support**
   - iptables (Linux)
   - nftables (Linux)
   - pfctl (BSD/macOS)
   - fail2ban integration
   - Custom rule management

2. **Machine Learning Threat Detection**
   - Behavioral analysis engine
   - Anomaly detection algorithms
   - Real-time threat scoring
   - Adaptive learning capabilities

3. **Advanced Rate Limiting**
   - Token bucket algorithms
   - Sliding window counters
   - IP-based and endpoint-based limits
   - Geographic rate limiting

4. **Real-time Monitoring**
   - WebSocket-based dashboards
   - Prometheus metrics integration
   - Custom alerting rules
   - Log aggregation and analysis

### Security Controls

#### Access Control
- Role-based access control (RBAC)
- API key authentication
- JWT token validation
- IP-based access restrictions

#### Data Protection
- Encrypted configuration storage
- Secure inter-service communication
- Log data anonymization
- PII detection and redaction

#### Network Security
- TLS 1.3 enforcement
- Certificate pinning
- DDoS protection mechanisms
- Geographic blocking capabilities

## Vulnerability Reporting

### Reporting Security Issues

**Do NOT create public GitHub issues for security vulnerabilities.**

Instead, please report security vulnerabilities through one of the following channels:

1. **GitHub Security Advisories** (Preferred)
   - Navigate to the `"Security"` tab in our repository
   - Click `"Report a vulnerability"`
   - Provide detailed information about the vulnerability

2. **Email** (Alternative)
   - Send an encrypted email to: anipaleja@gmail.com
   - Use our PGP key: [Key ID: 0x1234567890ABCDEF]
   - Include reproduction steps and impact assessment

3. **Security Bug Bounty (Coming Soon)**
   - Report through our HackerOne program: https://hackerone.com/anipaleja
   - Eligible for monetary rewards based on severity

### What to Include

When reporting a security vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Steps to Reproduce**: Detailed reproduction steps
- **Impact Assessment**: Potential security impact and affected components
- **Proof of Concept**: Working exploit code (if applicable)
- **Affected Versions**: Specific versions affected
- **Suggested Fix**: Proposed remediation (if available)

### Response Timeline

- **Initial Response**: Within 24 hours of report
- **Vulnerability Assessment**: Within 72 hours
- **Fix Development**: 7-14 days (depending on severity)
- **Security Advisory**: Published with patch release
- **Public Disclosure**: 90 days after patch availability

## Security Best Practices

### Deployment Security

#### Production Environment
```yaml
# Secure configuration example
server:
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/nginx-defender.crt"
    key_file: "/etc/ssl/private/nginx-defender.key"
    min_version: "1.3"
  
firewall:
  backend: "nftables"
  default_action: "drop"
  whitelist:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
  
rate_limiting:
  global_limit: 1000
  per_ip_limit: 100
  burst_allowance: 50
  
ml:
  threat_threshold: 0.8
  learning_mode: false
  model_validation: true
```

#### Container Security
```dockerfile
# Security-hardened container deployment
FROM scratch
COPY --from=builder /app/nginx-defender /nginx-defender
USER 65534:65534
EXPOSE 8080/tcp
ENTRYPOINT ["/nginx-defender"]
```

#### Kubernetes Security
```yaml
apiVersion: v1
kind: SecurityContext
metadata:
  name: nginx-defender-security
spec:
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
    add:
      - NET_ADMIN  # Required for firewall operations
```

### Configuration Security

#### Sensitive Data Management
```bash
# Use environment variables for secrets
export NGINX_DEFENDER_API_KEY="$(cat /etc/secrets/api-key)"
export NGINX_DEFENDER_DB_PASSWORD="$(cat /etc/secrets/db-password)"

# Or use volume mounts for configuration
docker run -v /secure/config:/config nginx-defender
```

#### Network Isolation
```yaml
# Network policy for Kubernetes
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
    ports:
    - protocol: TCP
      port: 9090
```

### Operational Security

#### Log Management
- Enable audit logging for all security events
- Use structured logging (JSON format)
- Implement log rotation and retention policies
- Set up centralized log aggregation
- Monitor for security-related log patterns

#### Monitoring and Alerting
```yaml
# Prometheus alerting rules
groups:
- name: nginx-defender.security
  rules:
  - alert: HighThreatDetection
    expr: nginx_defender_threats_detected_total > 100
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High number of threats detected"
      
  - alert: FirewallRuleExhaustion
    expr: nginx_defender_firewall_rules_total > 10000
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Firewall rule limit approaching"
```

#### Backup and Recovery
- Regular configuration backups
- Firewall rule state snapshots
- ML model checkpoints
- Disaster recovery procedures
- Testing backup restoration

## Security Testing

### Automated Security Testing

The project includes comprehensive security testing:

```go
// Security-focused test examples
func TestSecurityIsolation(t *testing.T) {
    // Use secure test environment
    ts := NewTestSuite(t)
    defer ts.Cleanup()
    
    // Generate cryptographically secure test IPs
    testIP := generateSecureTestIP(t)
    validateTestIP(t, testIP)
    
    // Test with security metadata
    metadata := map[string]string{
        "test_type": "security_validation",
        "safe_mode": "true",
    }
    
    // Verify security controls
    assert.True(t, isPrivateIP(testIP), "Only private IPs in tests")
}
```

### Manual Security Testing

1. **Penetration Testing**
   - Regular third-party security assessments
   - OWASP Top 10 vulnerability testing
   - Network penetration testing
   - Social engineering assessments

2. **Code Security Reviews**
   - Static application security testing (SAST)
   - Dynamic application security testing (DAST)
   - Dependency vulnerability scanning
   - Secret detection in code

3. **Infrastructure Security**
   - Container security scanning
   - Kubernetes security posture
   - Network security validation
   - Configuration security review

## Incident Response

### Security Incident Procedures

1. **Detection and Analysis**
   - Monitor security alerts and logs
   - Analyze potential security events
   - Determine incident classification
   - Document all findings

2. **Containment and Eradication**
   - Isolate affected systems
   - Apply emergency patches
   - Remove malicious components
   - Update security controls

3. **Recovery and Lessons Learned**
   - Restore normal operations
   - Monitor for recurring issues
   - Update security procedures
   - Share lessons learned

### Emergency Contacts

- **Security Team**: security@nginx-defender.com
- **Incident Response**: incident@nginx-defender.com
- **Emergency Hotline**: +1-555-SECURITY

## Compliance and Certifications

### Security Standards
- **ISO 27001**: Information Security Management
- **SOC 2 Type II**: Security and Availability
- **NIST Cybersecurity Framework**: Implementation
- **OWASP ASVS**: Application Security Verification

### Compliance Frameworks
- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act
- **PCI DSS**: Payment Card Industry Data Security Standard
- **FedRAMP**: Federal Risk and Authorization Management Program

## Security Resources

### Documentation
- [Security Architecture Guide](docs/security-architecture.md)
- [Threat Modeling Report](docs/threat-model.md)
- [Security Configuration Guide](docs/security-config.md)
- [Incident Response Playbook](docs/incident-response.md)

### Tools and Integrations
- [Security Scanner Integration](docs/security-scanning.md)
- [SIEM Integration Guide](docs/siem-integration.md)
- [Vulnerability Management](docs/vulnerability-management.md)
- [Security Metrics Dashboard](docs/security-metrics.md)

### Training and Awareness
- [Security Training Materials](docs/security-training.md)
- [Security Best Practices](docs/security-practices.md)
- [Secure Development Guidelines](docs/secure-development.md)
- [Security Awareness Program](docs/security-awareness.md)

---

**Last Updated**: December 2024  
**Version**: 2.0  
**Contact**: security@nginx-defender.com

For the latest security updates and advisories, please visit our [Security Advisory page](https://github.com/nginx-defender/nginx-defender/security/advisories).
