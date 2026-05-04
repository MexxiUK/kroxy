# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Email:** security@kroxy.io

**Do NOT:**
- Open a public GitHub issue
- Post details in public forums
- Disclose before we've had a chance to fix it

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Proof of concept (if safe)
- Your contact information

### Response Timeline

| Stage | Target Time |
|-------|-------------|
| Initial response | 48 hours |
| Vulnerability confirmation | 7 days |
| Fix development | 14-30 days (severity dependent) |
| Public disclosure | After fix released |

### Disclosure Policy

- We practice **coordinated disclosure**
- Vulnerabilities are disclosed after a fix is released
- Credit is given to researchers (unless they prefer anonymity)
- We do not pursue legal action against good-faith security research

## Security Best Practices

When deploying Kroxy:

1. **Set environment variables** - Never commit secrets to version control
2. **Use HTTPS** - Configure TLS certificates or enable Auto-HTTPS
3. **Restrict admin access** - Bind admin interface to localhost
4. **Review audit logs** - Monitor security events regularly
5. **Keep updated** - Apply security patches promptly

## Security Features

Kroxy includes built-in security protections:

- OWASP Core Rule Set (WAF)
- Rate limiting and brute-force protection
- Session security (timeout, CSRF protection)
- Audit logging with tamper detection
- TLS/HTTPS with modern cipher suites

For configuration guidance, see our [documentation](docs/).

## Security Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

<!-- Researchers will be added here after disclosure -->

---

**Security Contact:** security@kroxy.io

**PGP Key:** [To be added]

**Response SLA:** We commit to responding within 48 hours.