# Kroxy

**Self-hosted reverse proxy with built-in WAF, OIDC auth, and rate limiting — no external dependencies required.**

One binary. One container. Zero infrastructure complexity.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardened-green?style=flat)](SECURITY.md)

---

## Why Kroxy?

Kroxy consolidates multiple infrastructure components into a single deployment:

- **Built-in WAF** — OWASP Core Rule Set v4, no external WAF container needed
- **Built-in OIDC** — Single sign-on out of the box, no separate auth service
- **Built-in Rate Limiting** — Per-route sliding window limits, no external service
- **Built-in Audit Logging** — Security event logging included
- **Admin REST API** — Full programmatic control of routes, WAF rules, certificates
- **Single Binary** — No dependencies, no external services required

---

## Features

### 🔒 Enterprise Security
- **Web Application Firewall (WAF)** - OWASP Core Rule Set v4 with custom rule support
- **OIDC Authentication** - Single sign-on with GitHub, Google, Azure AD, and custom providers
- **Rate Limiting** - Configurable per-route limits with sliding window algorithm
- **CSRF Protection** - Token-based with constant-time comparison
- **Security Headers** - HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and more
- **SSRF Prevention** - Validates backend URLs to prevent server-side request forgery

### 🚀 Reverse Proxy
- **Automatic HTTPS** - ACME/Let's Encrypt certificate management
- **Multiple Backends** - Route multiple domains to different services
- **Load Balancing** - Weighted round-robin with health checks
- **Compression** - Gzip and Brotli support
- **CORS Management** - Configurable per-route CORS policies

### 🛠️ Administration
- **REST API** - Full CRUD operations for routes, certificates, WAF rules
- **Metrics Endpoint** - Prometheus-compatible metrics
- **Audit Logging** - Comprehensive security event logging
- **Admin Dashboard** - Web-based management interface

### 🐳 Deployment Options
- **Docker** - Hardened container with non-root user, read-only filesystem
- **Systemd** - Production-ready service unit with security hardening
- **Kubernetes-ready** - Lightweight, stateless design

---

## Quick Start

### Docker (Recommended)

```bash
# Create data directory
mkdir -p ./data

# Run with Docker
docker run -d \
  --name kroxy \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -p 127.0.0.1:8080:8080 \
  -v ./data:/data \
  mexxiuk/kroxy:latest

# Verify it's running
curl http://localhost:8080/health
# Expected: {"status":"ok"}
```

### Binary

```bash
# Download
curl -sL https://github.com/MexxiUK/kroxy/releases/latest/download/kroxy-linux-amd64 -o kroxy
chmod +x kroxy

# Run
./kroxy --listen :443 --admin :8080 --db ./kroxy.db
```

### First-Time Setup

Create an API key to use the admin API:

```bash
# Generate an API key
curl -X POST http://localhost:8080/api/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "admin"}'
# Response: {"key":"k_xxx","secret":"s_xxx"} - save these!
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KROXY_LISTEN` | `:443` | HTTPS listen address |
| `KROXY_ADMIN` | `:8080` | Admin API (bind to localhost!) |
| `KROXY_DB` | `/data/kroxy.db` | SQLite database path |

---

## API Examples

### Authentication

All API requests require an API key header:
```bash
-H "Authorization: ApiKey k_live_xxx:s_live_xxx"
```

### Create a Route

```bash
curl -X POST http://localhost:8080/api/routes \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey your-key:your-secret" \
  -d '{
    "domain": "example.com",
    "backend": "http://localhost:3000",
    "enabled": true,
    "waf_enabled": true
  }'
# Response: {"id":"route_123","domain":"example.com",...}
```

### List Routes

```bash
curl http://localhost:8080/api/routes \
  -H "Authorization: ApiKey your-key:your-secret"
```

### Add a WAF Rule

```bash
curl -X POST http://localhost:8080/api/waf/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey your-key:your-secret" \
  -d '{
    "name": "Block SQL Injection",
    "rule": "SecRule REQUEST_URI \"(?i:union.*select)\" \"deny,log,id:1001\"",
    "enabled": true
  }'
```

---

## Security

Kroxy is built with security as a priority:

| Feature | Status |
|---------|--------|
| Non-root container | ✅ |
| Read-only filesystem | ✅ |
| Minimal capabilities | ✅ |
| WAF (OWASP CRS) | ✅ |
| OIDC authentication | ✅ |
| Rate limiting | ✅ |
| CSRF protection | ✅ |
| Security headers | ✅ |
| Audit logging | ✅ |
| SSRF prevention | ✅ |

See [SECURITY.md](SECURITY.md) for full security policy.

---

## Architecture

```
                         ┌──────────────────────────────────┐
                         │            Kroxy                 │
                         │                                  │
    Client ───HTTPS────► │  ┌─────────┐    ┌─────────────┐  │    ┌─────────────┐
                         │  │  SSL/   │───►│    WAF      │──┼───► │  Backend 1  │
                         │  │  ACME   │    │  (OWASP)    │  │    │ (app:3000)  │
                         │  └─────────┘    └─────────────┘  │    └─────────────┘
                         │                       │         │
                         │                       ▼         │    ┌─────────────┐
    Admin API ──────────►│                 ┌─────────────┐ ├───► │  Backend 2  │
    (localhost:8080)     │                 │ Rate Limiter│ │    │ (app:3001)  │
                         │                 └─────────────┘ │    └─────────────┘
                         │                       │         │
                         │                       ▼         │
                         │                 ┌─────────────┐ │
                         │                 │    Load     │ │
                         │                 │   Balancer  │─┘
                         │                 └─────────────┘
                         └──────────────────────────────────┘

Request Flow:
  1. SSL termination (auto cert from Let's Encrypt)
  2. WAF inspection (block malicious requests)
  3. Rate limiting (per-route sliding window)
  4. Load balancing (weighted round-robin with health checks)
  5. Proxy to backend
```

---

## FAQ

**Q: How does automatic HTTPS work?**

Kroxy uses ACME (Let's Encrypt) to obtain certificates automatically. Point your domain's DNS to the server and Kroxy handles the rest.

**Q: Can I use Kroxy without a domain?**

Yes, but HTTPS won't be automatic. Use `--insecure` flag for testing (not recommended for production).

**Q: What's the performance overhead?**

With WAF enabled, expect ~5-10ms per request. Without WAF, <1ms overhead.

**Q: How do I configure OIDC?**

See the [Authentication Guide](./docs/authentication.md) for provider-specific configuration.

---

## Development

```bash
# Clone
git clone git@github.com:MexxiUK/kroxy.git
cd kroxy

# Build
go build -o kroxy ./cmd/kroxy

# Test
go test ./...

# Run
./kroxy --listen :443 --admin :8080 --db ./kroxy.db
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.