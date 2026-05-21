# Kroxy Production-Readiness Report — Synthesized Executive Summary

**Date:** 2026-05-19
**Auditors:** 6 parallel specialized agents
**Scope:** Security, code quality, tests, deployment, API/web layer, configuration/secrets

---

## P0 — Blockers (Deploying without these is reckless)

| # | Issue | Source File | Why It Blocks |
|---|-------|-------------|---------------|
| 1 | **Missing `.dockerignore`** | `Dockerfile:19` (`COPY . .`) | Encryption keys (`internal/auth/.kroxy-encryption-key`, `internal/store/.kroxy-encryption-key`), audit logs (`data/audit.log`), and 86MB pre-built binaries get baked into every image. |
| 2 | **SQLite connection pool misconfigured** | `internal/store/store.go:20-44` | No `SetMaxOpenConns(1)`. SQLite will hit `database is locked` under any concurrent write load. |
| 3 | **Silent data loss from missing `rows.Err()`** | `internal/store/store.go` (most query methods) | After every `for rows.Next()` loop, `rows.Err()` is never checked. If the DB connection fails mid-iteration, partial results are returned as if complete. |
| 4 | **Alert webhook signature is NOT HMAC** | `internal/alerts/alerts.go:144-150` | Uses `SHA256(secret || payload)` instead of HMAC-SHA256. Vulnerable to length-extension attacks. |
| 5 | **Webhook secrets exposed in REST API** | `internal/api/webhooks.go:23,63,110` | `GET /api/webhooks`, `POST /api/webhooks`, `PUT /api/webhooks/:id` return the raw `Secret` field in JSON responses to any authenticated admin. |
| 6 | **Plaintext fallbacks for TOTP/OIDC secrets** | `internal/auth/auth.go:1248-1253`, `internal/store/store.go:161-168` | When encryption is unavailable or decrypt fails, raw DB values are silently used. At-rest confidentiality is defeated. |
| 7 | **K8s secrets committed with placeholder values** | `deploy/k8s/secret.yaml:10-26` | Hardcoded `CHANGE_ME_*` strings in git. Deploying without editing them runs the app with predictable credentials. |
| 8 | **K8s admin API exposed to entire cluster** | `deploy/k8s/configmap.yaml:11`, `service.yaml:11-24` | `KROXY_ADMIN: "0.0.0.0:8080"` overrides secure localhost default. No `NetworkPolicy` exists. Admin API is plaintext HTTP and reachable by any pod. |
| 9 | **gosec CI scan suppressed** | `.github/workflows/ci.yml:90` | `gosec ... || true` means ALL security findings are ignored. The pipeline gives false confidence. |
| 10 | **Systemd service wrong env var** | `scripts/kroxy.service:18` | Sets `KROXY_LISTEN=:443`, but app reads `KROXY_PROXY`. Proxy silently falls back to `:80`. |
| 11 | **Docker Compose health check is wrong endpoint** | `docker-compose.yml:60` | Hits `/api/status` (lightweight stub) instead of `/ready` (DB connectivity check). DB failures are masked. |
| 12 | **Stored XSS via unescaped `innerHTML`** | `web/templates/pages/users.html:163-178`, `api-keys.html:141-163`, `dashboard.html:212-214` | User-controlled fields (`name`, `email`, `api-key-name`, `cert.domain`) rendered into `innerHTML` without escaping. |

---

## P1 — High Risk (Fix before public exposure)

| # | Issue | Source File |
|---|-------|-------------|
| 13 | **Core proxy engine completely untested** | `internal/proxy/` (1,389 LOC, 0% coverage) |
| 14 | **Encryption/TOTP completely untested** | `internal/crypto/encryption.go`, `internal/totp/` |
| 15 | **OIDC provider secret wiped on partial update** | `internal/api/api.go:1719-1770` |
| 16 | **OIDC manager cache never updated/deleted** | `internal/api/api.go:1719-1794` |
| 17 | **Access log errors silently ignored** | `internal/proxy/accesslog.go:71-75` |
| 18 | **Admin token hashed with SHA256 (not bcrypt)** | `internal/auth/auth.go:1414-1416` |
| 19 | **Sessions not bound to IP/User-Agent** | `internal/auth/auth.go:504-620` |
| 20 | **API key/admin token rate limiting broken behind reverse proxy** | `internal/auth/auth.go:430,655` |
| 21 | **IPv6 address parsing broken** | `internal/auth/auth.go:871-879`, `internal/security/security.go:14-18` |
| 22 | **Admin route self-reference bypass** | `internal/api/api.go:1250-1302` |
| 23 | **WAF fail-open on body processing error** | `internal/waf/waf.go:710-718` |
| 24 | **Unbounded fire-and-forget goroutines** | `internal/auth/auth.go:553,596,728` |
| 25 | **Static file handler panic risk** | `internal/api/api.go:371` |
| 26 | **Shutdown ignores all critical errors** | `cmd/kroxy/main.go:219-224` |
| 27 | **Abrupt `log.Fatalf` on crypto/rand failure** | Multiple files |
| 28 | **Request body silently truncated** | `internal/api/api.go:252-259` |
| 29 | **Integration test failing (`TestSetup_FirstUser`)** | `internal/api/api_integration_test.go:122` |
| 30 | **Docker Compose insecure defaults** | `docker-compose.yml:44-45` |
| 31 | **Trivy mounts Docker socket unnecessarily** | `.github/workflows/ci.yml:206` |
| 32 | **Webhook URLs lack SSRF validation** | `internal/alerts/alerts.go:92` |
| 33 | **Logout lacks CSRF protection** | `internal/api/api.go:387` |

---

## P2 — Medium (Address within next sprint)

- K8s ingress `nginx.ingress.kubernetes.io/configuration-snippet` allows raw nginx config injection
- K8s init container runs as root with `busybox:latest`
- K8s uses `latest` tag with `IfNotPresent`
- CI Actions use floating tags (`@v4`, `@v5`) instead of commit SHAs
- CI unpins security tools (`go install ...@latest`)
- HSTS sent over HTTP connections
- Deprecated `X-XSS-Protection` header
- Missing `Clear-Site-Data` on logout
- Missing `Cache-Control` on authenticated responses
- CSP missing `font-src`, `form-action`, `connect-src`, `img-src`
- `docker-compose.secure.yml` disables seccomp (`seccomp=unconfined`)
- WAF instance memory leak on reload
- Cascading config reload in DNS revalidation
- Health check misclassifies HTTP 400 as healthy
- Config silently swallows parse errors (`getEnvBool`, `getEnvInt64`)
- Double rate limiting on login endpoint
- Bot challenge brute-force tests are computationally expensive
- `HexSecret()` exposes bot detection secret
- Missing `.env.example`
- Pre-built binaries and SQLite DB in working tree
- `data/audit.log` present in working tree
- `KROXY_INSECURE_COOKIES` double-negative naming
- Dev encryption key written to unpredictable path
- `getEnv` treats empty string as unset

---

## Positive Findings (What's Working Well)

- **Bcrypt cost 12** for passwords and API key secrets
- **AES-GCM encryption** for TOTP and OIDC secrets at rest
- **HMAC-signed WAF headers** prevent downstream bypass
- **DNS rebinding protection** with cached resolutions
- **SSRF prevention** blocks private IPs and encoded variants
- **Parameterized SQL** throughout `internal/store/` — no injection vectors
- **CSP with nonces**, `X-Frame-Options: DENY`, secure session cookies
- **Rate limiting** on login, API keys, admin tokens, setup
- **Audit logging** with HMAC signatures for tamper detection
- **WAF fails closed** (returns 503 if engine missing)
- **Race detector passes** on all tested code
- **K8s manifests** have `runAsNonRoot`, `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`

---

## Verdict

**Not production-ready yet.** The P0 blockers span data integrity (SQLite, `rows.Err()`), secrets exposure (webhook API, plaintext fallbacks), deployment hygiene (`.dockerignore`, K8s placeholders, systemd env var), CI security theater (`gosec || true`), and XSS in the admin panel. These are fixable, but they must be addressed before this is safe to deploy publicly.

**Recommended order:** Fix P0 blockers first, then add unit tests for `internal/proxy`, `internal/crypto/encryption.go`, and `internal/totp` before releasing.
