# GitHub Security Advisory - nginx-defender v2.0.0

## Default Credentials in Configuration Files

### Summary
nginx-defender versions prior to 2.0.0 contain default credentials in example configuration files that could be used in production deployments.

### Details
The configuration files `config.yaml` and `docker-compose.yml` contain default credentials:
- `default_password: "change_me_please"`
- `GF_SECURITY_ADMIN_PASSWORD=admin123`

If users deploy nginx-defender without changing these defaults, attackers could gain administrative access.

### Severity
**Medium** (CVSS 5.3) - Requires network access to exposed interface

### Affected Versions
- All versions < 2.0.0

### Patched Versions  
- 2.0.0 and later

### Workarounds
Update default credentials in configuration files before deployment:

```yaml
# config.yaml
auth:
  default_password: "your_strong_password_here"
```

```yaml
# docker-compose.yml  
- GF_SECURITY_ADMIN_PASSWORD=your_strong_password
```

### References
- [Security Configuration Guide](docs/security-config.md)
- [Full Security Advisory](SECURITY_ADVISORY_v2.0.md)

---

## Library Integration Security Considerations

### Summary
The new library mode in v2.0.0 introduces considerations for applications embedding nginx-defender.

### Details
Applications integrating the nginx-defender library should follow secure coding practices:

1. **Input Validation**: Always validate IP addresses before passing to library functions
2. **Error Handling**: Don't expose internal error details to clients  
3. **Resource Limits**: Configure appropriate rate limits and timeouts

### Severity
**Low** - Informational security guidance

### Affected Versions
- 2.0.0 and later (new feature)

### Recommendations

```go
// Secure integration example
if net.ParseIP(clientIP) == nil {
    http.Error(w, "Bad Request", 400)
    return
}

if def.ShouldBlock(clientIP) {
    http.Error(w, "Access Denied", 403) 
    return // Don't leak blocking reason
}
```

### References
- [Library Integration Guide](lib/README.md)
- [Security Best Practices](SECURITY.md)
