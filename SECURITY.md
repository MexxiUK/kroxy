# Security Policy

## Security Contact

For security concerns, contact: **security@kroxy.dev**

For encrypted submissions, use our PGP key (fingerprint published in `.well-known/security.txt`).

## Supported Versions

| Version | Support Level      | End of Life  |
| ------- | ------------------ | ------------ |
| 1.x     | Active support     | TBD          |
| < 1.0   | End of life        | Retired      |

We recommend always running the latest stable release.

## Scope

**In scope for security research:**
- Core proxy functionality
- Authentication/authorization modules
- WAF implementation
- Admin API endpoints
- TLS/certificate handling

**Out of scope:**
- Third-party dependencies (report to upstream)
- Social engineering attacks
- Physical security
- Denial of service without demonstrable vulnerability

## Security Features

Kroxy is designed with security-first principles:

### Application Security
- **WAF Protection**: OWASP Core Rule Set v4 for common attacks (SQLi, XSS, RCE, LFI)
- **OIDC Authentication**: Secure single sign-on integration
- **Rate Limiting**: Per-IP and per-route rate limiting
- **CSRF Protection**: Token-based with constant-time comparison
- **Input Validation**: SSRF prevention, domain validation, path sanitization

### Infrastructure Security
- **Non-root Execution**: Runs as unprivileged user by default
- **Read-only Filesystem**: Container filesystem is immutable
- **Minimal Capabilities**: Drops all Linux capabilities
- **Security Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Audit Logging**: Comprehensive security event logging

### Data Security
- **Password Hashing**: bcrypt with default cost (12)
- **Session Security**: Cryptographically random session IDs
- **API Key Security**: Bcrypt-hashed secrets, database persistence
- **No Secrets in Logs**: Sensitive data excluded from logs

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

1. **GitHub Security Advisories** (preferred) - Use the "Security" tab in the repository
2. **Email**: security@kroxy.dev for critical issues
3. **PGP-encrypted reports** - Key available in `.well-known/security.txt`

### What to Include in a Report

Please provide:
- Vulnerability description and impact
- Affected versions
- Steps to reproduce
- Proof of concept (if safe)
- Your contact information
- Whether you want public credit

## Incident Response SLA

| Severity   | Acknowledgment | Initial Response | Fix Target    |
|------------|----------------|------------------|---------------|
| Critical   | 24 hours       | 48 hours         | 48 hours      |
| High       | 48 hours       | 7 days           | 7 days        |
| Medium     | 72 hours       | 14 days          | 30 days       |
| Low        | 1 week         | 30 days          | Next release  |

## Safe Harbor

We consider security research conducted in good faith to be authorized research. We will not pursue legal action against researchers who responsibly disclose vulnerabilities following this policy.

**Guidelines for good faith research:**
- Test only your own accounts/data
- Avoid privacy violations, destruction, or data exfiltration
- Report vulnerabilities promptly
- Do not publicly disclose until fix is released

## Security Advisories

Security updates are published via:
- GitHub Security Advisories
- Release notes (marked with `[SECURITY]` prefix)
- CVE database (when applicable)

To receive security notifications:
- Watch the repository on GitHub
- Subscribe to GitHub Security Advisories

## Security Attestations

- Software Bill of Materials (SBOM) published with each release
- Container images scanned for vulnerabilities
- Dependency updates monitored continuously
- All commits signed by maintainers

## Security Best Practices

When deploying Kroxy:
1. **Admin API**: Bind to localhost only (`127.0.0.1:8080`)
2. **TLS Certificates**: Use valid certificates from trusted CAs
3. **OIDC Providers**: Use HTTPS redirect URLs
4. **WAF Rules**: Enable OWASP CRS and add custom rules as needed
5. **Rate Limits**: Configure appropriate limits for your traffic
6. **Updates**: Keep Kroxy updated to the latest version
7. **Logs**: Monitor audit logs for suspicious activity

Thank you for helping keep Kroxy and its users safe!