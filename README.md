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
- **DNS Rebinding Protection** - Periodic revalidation of backend DNS records

### 🚀 Reverse Proxy
- **HTTPS/TLS** - Automatic ACME (Let's Encrypt) or manual certificate support
- **Multiple Backends** - Route multiple domains to different services
- **Compression** - Gzip and Brotli support
- **HTTP-to-HTTPS Redirect** - Automatic redirect from port 80 to 443

### 🛠️ Administration
- **REST API** - Full CRUD operations for routes, certificates, WAF rules, settings
- **Metrics Endpoint** - Prometheus-compatible metrics
- **Audit Logging** - Comprehensive security event logging
- **Admin Dashboard** - Web-based management interface with first-time setup wizard

### 🐳 Deployment Options
- **Docker** - Hardened container with non-root user, read-only filesystem
- **Kubernetes-ready** - Lightweight, stateless design

---

## Quick Start

### Docker (Recommended)

```bash
# HTTP-only (development)
docker run -d --name kroxy \
  --restart unless-stopped \
  -p 80:80 \
  -p 127.0.0.1:8080:8080 \
  -v kroxy-data:/data \
  kroxy/kroxy:latest

# With automatic HTTPS (production)
docker run -d --name kroxy \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -p 127.0.0.1:8080:8080 \
  -v kroxy-data:/data \
  -e KROXY_TLS_ENABLED=true \
  -e KROXY_AUTO_HTTPS=true \
  -e KROXY_ACME_EMAIL=admin@example.com \
  kroxy/kroxy:latest

# Verify it's running
curl http://localhost:8080/health
```

### Docker Compose

See `docs/examples/` for ready-to-use compose files:
- `docker-compose.nextjs.yml` — Kroxy + Next.js with ACME
- `docker-compose.express.yml` — Kroxy + Express with manual certs
- `docker-compose.django.yml` — Kroxy + Django with ACME

### First-Time Setup

When you first access `http://localhost:8080`, you'll be guided through a setup wizard to create your admin account and configure your first route.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KROXY_PROXY` | `:80` | HTTP listen address |
| `KROXY_HTTPS_ADDR` | `:443` | HTTPS listen address (when TLS enabled) |
| `KROXY_ADMIN` | `127.0.0.1:8081` | Admin API listen address (localhost by default for security) |
| `KROXY_DB` | `./kroxy.db` | SQLite database path |
| `KROXY_PRODUCTION` | `false` | Production mode (stricter defaults) |
| `KROXY_MAX_REQUEST_SIZE` | `10MB` | Max request body size |
| `KROXY_ENABLE_METRICS` | `false` | Enable Prometheus metrics |
| `KROXY_ALLOW_PRIVATE_BACKENDS` | `false` | Allow private IP backends (dev only) |
| `KROXY_TLS_ENABLED` | `false` | Enable HTTPS/TLS |
| `KROXY_AUTO_HTTPS` | `false` | Enable automatic ACME certificate provisioning |
| `KROXY_ACME_EMAIL` | — | Email for Let's Encrypt notifications |
| `KROXY_TLS_CERT` | — | Path to TLS certificate PEM (manual mode) |
| `KROXY_TLS_KEY` | — | Path to TLS private key PEM (manual mode) |
| `KROXY_TLS_MIN_VERSION` | `1.2` | Minimum TLS version (1.2 or 1.3) |
| `KROXY_HSTS_ENABLED` | `true` | Enable HSTS headers |
| `KROXY_REDIRECT_HTTP` | `true` | Redirect HTTP to HTTPS |

---

## API Examples

### Create a Route

```bash
curl -X POST http://localhost:8080/api/routes \
  -H "Content-Type: application/json" \
  -H "Cookie: kroxy_session=$SESSION" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{
    "domain": "example.com",
    "backend": "http://localhost:3000",
    "enabled": true,
    "waf_enabled": true
  }'
```

### Add a WAF Rule

```bash
curl -X POST http://localhost:8080/api/waf/rules \
  -H "Content-Type: application/json" \
  -H "Cookie: kroxy_session=$SESSION" \
  -H "X-CSRF-Token: $CSRF" \
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
| DNS rebinding protection | ✅ |
| Signed WAF verification headers | ✅ |

See [SECURITY.md](SECURITY.md) for full security policy.

---

## Architecture

```
                         ┌──────────────────────────────────┐
                         │            Kroxy                 │
                         │                                  │
    Client ───HTTPS────► │  ┌─────────┐    ┌─────────────┐  │    ┌─────────────┐
                         │  │  TLS    │───►│    WAF      │──┼───► │  Backend 1  │
                         │  │  ACME   │    │  (OWASP)    │  │    │ (app:3000)  │
                         │  └─────────┘    └─────────────┘  │    └─────────────┘
                         │                       │         │
                         │                       ▼         │    ┌─────────────┐
    Admin API ──────────►│                 ┌─────────────┐ ├───► │  Backend 2  │
    (localhost:8080)     │                 │ Rate Limiter│ │    │ (app:3001)  │
                         │                 └─────────────┘ │    └─────────────┘
                         │                                 │
                         └──────────────────────────────────┘

Request Flow:
  1. TLS termination (auto cert from Let's Encrypt or manual)
  2. WAF inspection (block malicious requests)
  3. Rate limiting (per-route sliding window)
  4. Proxy to backend
```

---

## FAQ

**Q: How does automatic HTTPS work?**

Set `KROXY_TLS_ENABLED=true` and `KROXY_AUTO_HTTPS=true` with your email. Kroxy uses ACME (Let's Encrypt) to obtain certificates automatically. Point your domain's DNS to the server and Kroxy handles the rest.

**Q: Can I use custom certificates?**

Yes. Set `KROXY_TLS_ENABLED=true` with `KROXY_TLS_CERT=/path/to/cert.pem` and `KROXY_TLS_KEY=/path/to/key.pem`. You can also add certificates via the admin dashboard.

**Q: Can I use Kroxy without HTTPS?**

Yes. By default, Kroxy runs HTTP-only on port 80. Enable TLS when you're ready for production.

**Q: What's the performance overhead?**

With WAF enabled, expect ~2ms per request. Without WAF, <1ms overhead.

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
./kroxy
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.