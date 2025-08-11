# GitHub Security Advisory Template

This document provides templates and guidelines for creating security advisories for nginx-defender vulnerabilities.

## Security Advisory Template

When creating a security advisory on GitHub, use the following template:

### Title Format
```
[SEVERITY] Brief description of vulnerability in nginx-defender [Component]
```

**Examples:**
- `[HIGH] SQL Injection in WAF rule processing engine`
- `[CRITICAL] Authentication bypass in admin dashboard`
- `[MEDIUM] XSS vulnerability in log viewer interface`

### Advisory Content Template

```markdown
## Summary

[Provide a clear, concise summary of the vulnerability in 1-2 sentences]

## Details

### Affected Component
- **Component**: [e.g., WAF Engine, Admin Dashboard, ML Detection]
- **File(s)**: [List affected files]
- **Function(s)**: [List affected functions/methods]

### Vulnerability Description
[Detailed description of the vulnerability, including:]
- What the vulnerability is
- How it can be exploited
- What systems/data are at risk
- Under what conditions the vulnerability can be triggered

### Attack Vector
[Describe how an attacker would exploit this vulnerability:]
- **Attack Complexity**: [Low/Medium/High]
- **Privileges Required**: [None/Low/High]
- **User Interaction**: [Required/Not Required]
- **Scope**: [Unchanged/Changed]

### Impact Assessment
[Describe the potential impact:]
- **Confidentiality**: [None/Low/High]
- **Integrity**: [None/Low/High]
- **Availability**: [None/Low/High]
- **Business Impact**: [Description of business consequences]

## Affected Versions
- **Vulnerable**: nginx-defender < [version]
- **Fixed**: nginx-defender >= [version]
- **Backport**: [If applicable, mention backported fixes]

## Exploitation
[If safe to share, provide proof-of-concept or steps to reproduce]

### Prerequisites
- [List requirements for exploitation]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]
...

### Expected Result
[What should happen]

### Actual Result
[What actually happens - the vulnerability]

## Mitigation and Workarounds

### Immediate Workarounds
[Temporary measures to reduce risk before patching:]
1. [Workaround 1]
2. [Workaround 2]

### Long-term Fixes
1. **Upgrade**: Update to nginx-defender version [X.X.X] or later
2. **Configuration**: [Any configuration changes needed]
3. **Additional Security Measures**: [Recommended additional protections]

## Technical Analysis

### Root Cause
[Explain the technical root cause of the vulnerability]

### Code Analysis
```go
// Example of vulnerable code (sanitized)
func vulnerableFunction(input string) error {
    // Vulnerable implementation
    query := "SELECT * FROM users WHERE id = " + input
    // ... rest of code
}
```

### Security Fix
```go
// Example of fixed code
func secureFunction(input string) error {
    // Secure implementation using prepared statements
    query := "SELECT * FROM users WHERE id = ?"
    // ... rest of code with proper parameterization
}
```

## Detection

### Log Signatures
[Provide log patterns that indicate exploitation attempts]
```
# Example log patterns
2024-01-15 10:30:45 ERROR WAF blocked request: SQL injection detected
2024-01-15 10:30:45 ALERT Suspicious pattern in parameter: 'id'
```

### Monitoring Queries
[Provide queries for detecting exploitation in monitoring systems]
```sql
-- Prometheus query example
nginx_defender_blocked_requests_total{reason="sql_injection"} > 0
```

### IOCs (Indicators of Compromise)
- [List specific indicators that suggest successful exploitation]

## Timeline

- **[Date]**: Vulnerability discovered
- **[Date]**: Internal security team notified
- **[Date]**: Fix developed and tested
- **[Date]**: Security advisory created
- **[Date]**: Patch released
- **[Date]**: Public disclosure

## Credits

- **Discovered by**: [Researcher name/organization]
- **Reported via**: [Bug bounty program/responsible disclosure]
- **Fixed by**: [Development team members]

## References

- [CVE Number if assigned]
- [Related security advisories]
- [Technical blog posts or papers]
- [OWASP references]
- [CWE classification]

## Vendor Response

[nginx-defender team's response and actions taken]

## Additional Information

### Related Vulnerabilities
[Any related or similar vulnerabilities]

### Security Recommendations
1. [Recommendation 1]
2. [Recommendation 2]
3. [Recommendation 3]

### Contact Information
- **Security Team**: security@nginx-defender.com
- **Bug Bounty**: https://hackerone.com/nginx-defender
```

## Severity Classification

### CVSS v3.1 Calculator
Use the following guidelines for CVSS scoring:

```yaml
# Example CVSS calculation
attack_vector: "Network"      # Local/Adjacent Network/Network/Physical
attack_complexity: "Low"      # Low/High  
privileges_required: "None"   # None/Low/High
user_interaction: "None"      # None/Required
scope: "Changed"             # Unchanged/Changed
confidentiality: "High"      # None/Low/High
integrity: "High"            # None/Low/High
availability: "High"         # None/Low/High
```

### Severity Levels

| CVSS Score | Severity | Response Time | Disclosure |
|------------|----------|---------------|------------|
| 9.0 - 10.0 | Critical | 24 hours | 30 days |
| 7.0 - 8.9  | High     | 72 hours | 60 days |
| 4.0 - 6.9  | Medium   | 7 days   | 90 days |
| 0.1 - 3.9  | Low      | 30 days  | 120 days |

## Common Vulnerability Categories

### 1. Authentication and Authorization

```markdown
## Authentication Bypass (Example)

### Description
The admin authentication mechanism can be bypassed by manipulating the JWT token validation process.

### Technical Details
- **File**: `internal/auth/jwt.go`
- **Function**: `ValidateToken()`
- **Issue**: Improper signature verification

### Impact
- Complete administrative access
- Ability to modify security rules
- Access to sensitive configuration data

### Fix
Implement proper JWT signature verification using secure libraries.
```

### 2. Injection Vulnerabilities

```markdown
## SQL Injection in Rule Engine (Example)

### Description
User input in firewall rule creation is not properly sanitized, allowing SQL injection attacks.

### Technical Details
- **File**: `internal/firewall/rules.go`
- **Function**: `CreateRule()`
- **Issue**: Direct string concatenation in SQL queries

### Impact
- Database compromise
- Unauthorized data access
- Potential system compromise

### Fix
Use parameterized queries and input validation.
```

### 3. Cross-Site Scripting (XSS)

```markdown
## Stored XSS in Dashboard (Example)

### Description
The web dashboard does not properly sanitize user input, allowing stored XSS attacks.

### Technical Details
- **File**: `web/templates/dashboard.html`
- **Issue**: Unescaped user input in templates

### Impact
- Session hijacking
- Administrative privilege escalation
- Data theft

### Fix
Implement proper output encoding and Content Security Policy.
```

## Automated Advisory Creation

### Script for Advisory Generation

```bash
#!/bin/bash
# create-advisory.sh - Automated security advisory creation

set -e

# Configuration
REPO="nginx-defender/nginx-defender"
SEVERITY=""
TITLE=""
DESCRIPTION=""
AFFECTED_VERSIONS=""
CVSS_SCORE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --severity)
            SEVERITY="$2"
            shift 2
            ;;
        --title)
            TITLE="$2"
            shift 2
            ;;
        --description)
            DESCRIPTION="$2"
            shift 2
            ;;
        --affected-versions)
            AFFECTED_VERSIONS="$2"
            shift 2
            ;;
        --cvss-score)
            CVSS_SCORE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$SEVERITY" || -z "$TITLE" || -z "$DESCRIPTION" ]]; then
    echo "Error: Missing required parameters"
    echo "Usage: $0 --severity <severity> --title <title> --description <description>"
    exit 1
fi

# Create advisory JSON
cat > advisory.json << EOF
{
  "summary": "$TITLE",
  "description": "$DESCRIPTION",
  "severity": "$SEVERITY",
  "vulnerabilities": [
    {
      "package": {
        "ecosystem": "Go",
        "name": "github.com/nginx-defender/nginx-defender"
      },
      "vulnerable_version_range": "$AFFECTED_VERSIONS",
      "patched_versions": []
    }
  ],
  "references": [],
  "published": false,
  "state": "draft"
}
EOF

echo "Security advisory template created: advisory.json"
echo "Please review and submit via GitHub Security tab"
```

### GitHub CLI Integration

```bash
#!/bin/bash
# submit-advisory.sh - Submit security advisory via GitHub CLI

# Prerequisites: GitHub CLI installed and authenticated
# gh auth login

REPO="nginx-defender/nginx-defender"
ADVISORY_FILE="advisory.json"

if [[ ! -f "$ADVISORY_FILE" ]]; then
    echo "Error: Advisory file not found: $ADVISORY_FILE"
    exit 1
fi

echo "Submitting security advisory to $REPO..."

# Submit advisory (requires GitHub CLI with security advisory support)
gh api repos/$REPO/security-advisories \
    --method POST \
    --input "$ADVISORY_FILE"

echo "Security advisory submitted successfully"
echo "View at: https://github.com/$REPO/security/advisories"
```

## Best Practices for Security Advisories

### 1. Timing and Coordination

- **Discovery**: Document when and how the vulnerability was discovered
- **Notification**: Notify the security team immediately
- **Assessment**: Conduct thorough impact assessment
- **Fix Development**: Develop and test fixes
- **Disclosure**: Coordinate disclosure with stakeholders

### 2. Content Guidelines

- **Clarity**: Use clear, non-technical language for summary
- **Completeness**: Provide all necessary technical details
- **Accuracy**: Ensure all information is accurate and verified
- **Actionability**: Include clear remediation steps

### 3. Responsible Disclosure

```markdown
## Responsible Disclosure Policy

### Reporting Timeline
1. **0-24 hours**: Initial acknowledgment
2. **1-7 days**: Vulnerability assessment and classification
3. **7-30 days**: Fix development and testing
4. **30-90 days**: Coordinated disclosure

### Disclosure Coordination
- Work with security researchers
- Coordinate with affected organizations
- Provide advance notice to major users
- Ensure patches are available before disclosure
```

### 4. Post-Disclosure Activities

- Monitor for exploitation attempts
- Track patch adoption rates
- Update security documentation
- Conduct lessons learned sessions
- Improve security testing processes

This comprehensive security advisory framework ensures that vulnerabilities in nginx-defender are properly documented, communicated, and addressed in a coordinated manner that minimizes risk to users while maintaining transparency.
