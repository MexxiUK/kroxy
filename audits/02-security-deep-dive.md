# Kroxy Production-Readiness Security Audit Report

**Date:** 2026-05-19
**Scope:** Application code (`internal/`), CI/CD, deployment artifacts, and frontend templates
**Methodology:** Manual code review of recent security fixes (`8823725`, `879b512`, `c5d4e9c`) and remaining audit findings.

---

## Executive Summary

The recent commits closed several critical gaps (WAF newline injection, hardcoded AES dev key, setup race condition, login timing enumeration, and RequireStrongAuth proxy bypass). **However, multiple critical and high severity issues remain unfixed**, particularly:

- **Plaintext fallbacks** for TOTP and OIDC secrets when encryption is unavailable.
- **Kubernetes manifests** that expose the admin API to the entire cluster and ship hardcoded placeholder secrets.
- **CI/CD** that still suppresses `gosec` failures with `|| true`.
- **Rate-limiting** for API keys and admin tokens that uses raw `RemoteAddr`, making it ineffective (and self-DoS-ing) behind reverse proxies.
- **Numerous high issues** in session management, XSS, webhook signing, and infrastructure hardening.

---

## Critical Issues (must fix before production)

| # | Issue | Location(s) |
|---|-------|-------------|
| 1 | **Production encryption key not enforced; plaintext fallbacks remain.** `crypto.RequireEncryptionInProduction` only logs a warning. When `KROXY_ENCRYPTION_KEY` is missing, `store.GetOIDCProvider` and TOTP verification in `auth.go` / `api.go` silently fall back to raw database values, defeating at-rest confidentiality. | `internal/crypto/encryption.go:113-120`, `internal/store/store.go:161-168`, `internal/auth/auth.go:1248-1253`, `internal/api/api.go:915-918`, `internal/api/api.go:980-983` |
| 2 | **gosec security scan silently ignored in CI (CRIT-006 regression).** `.github/workflows/ci.yml:90` runs `gosec -exclude=G104,G307,G115 ./... || true`. The `|| true` suppresses all failures, allowing vulnerable code to pass CI. | `.github/workflows/ci.yml:87-90` |
| 3 | **Hardcoded placeholder secrets in Kubernetes manifests (CRIT-007).** `deploy/k8s/secret.yaml` contains hardcoded placeholders (`CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_BASE64_32`, `CHANGE_ME_32_BYTES_BASE64_ENCODED`, `CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32`). Committed to Git. | `deploy/k8s/secret.yaml:10-26` |
| 4 | **Kubernetes manifests expose admin API to entire cluster network.** `configmap.yaml` sets `KROXY_ADMIN: "0.0.0.0:8080"`; `service.yaml` exposes port 8080 cluster-wide; no NetworkPolicy exists. Overrides the secure localhost default and exposes plaintext HTTP admin to any pod in the cluster. | `deploy/k8s/configmap.yaml:11`, `deploy/k8s/service.yaml:11-24`, *no NetworkPolicy file* |
| 5 | **API key and admin token rate limiting broken behind reverse proxy.** `validateAPIKey` and `RequireAuth` (admin token) still use `getIPFromRequest` (raw `RemoteAddr`) instead of `security.GetClientIP`. When behind a reverse proxy, all traffic appears from the same internal IP, causing the per-IP rate limits (10/min for API keys, 5/min for admin tokens) to become global lockouts after a handful of failed attempts from any source. | `internal/auth/auth.go:430`, `internal/auth/auth.go:655`, `internal/auth/auth.go:872-879` |

---

## High Issues (should fix before production)

| # | Issue | Location(s) |
|---|-------|-------------|
| 1 | **TOTP plaintext fallback on decrypt failure (HIGH-001).** Decrypt failures silently use the raw database value as the TOTP secret. | `internal/auth/auth.go:1248-1253`, `internal/api/api.go:915-918`, `internal/api/api.go:980-983` |
| 2 | **OIDC client secret plaintext fallback (HIGH-008).** `GetOIDCProvider` silently uses the raw database value when decryption fails. | `internal/store/store.go:161-168` |
| 3 | **Sessions not bound to IP or User-Agent (HIGH-002).** `validateSession` never compares stored `IP`/`UserAgent` against the request. A stolen cookie works from any IP/browser. | `internal/auth/auth.go:504-620` |
| 4 | **Admin tokens hashed with fast SHA256 (HIGH-003).** `CreateAdminToken` uses `sha256Sum` instead of bcrypt, enabling offline brute-force. | `internal/auth/auth.go:1414-1416` |
| 5 | **Session cookie Secure flag tied to production mode (HIGH-005).** `Secure: a.productionMode` means cookies are sent over HTTP if an operator deploys over HTTPS without setting `KROXY_PRODUCTION=true`. | `internal/auth/auth.go:1733` |
| 6 | **Webhook signature uses raw SHA-256 instead of HMAC (HIGH-006).** Concatenates secret + payload and hashes with SHA-256. Vulnerable to length-extension attacks. | `internal/alerts/alerts.go:144-150` |
| 7 | **Webhook secrets stored in plaintext (HIGH-007).** Webhook secrets are stored as plaintext text in SQLite. No encryption or hashing. | `internal/store/store.go:1082-1104` |
| 8 | **XSS vulnerabilities in frontend templates (HIGH-009).** Multiple `innerHTML` assignments in `users.html`, `dashboard.html`, etc., use unescaped user data (names, emails, certificate domains). Stored XSS. | `web/templates/pages/users.html:163-179`, `web/templates/pages/dashboard.html:212`, and others |
| 9 | **Backup export includes sensitive data and lacks HMAC signature (HIGH-010).** Backup exports `CustomHeaders` (may contain auth tokens), certificate key paths, and other sensitive fields. No HMAC signature on export; import is partial (only routes). | `internal/api/backup.go:33-71` |
| 10 | **No IP allowlisting for admin access (HIGH-011).** No `ADMIN_IP_ALLOWLIST` environment variable or enforcement in `RequireAuth`. | `internal/api/api.go`, `internal/auth/auth.go` |
| 11 | **Docker Compose insecure defaults (HIGH-012).** Sets `KROXY_PRODUCTION=false` and `KROXY_ALLOW_PRIVATE_BACKENDS=true`. | `docker-compose.yml:44-45` |
| 12 | **Docker Compose disables seccomp (HIGH-013).** `docker-compose.secure.yml:29` still uses `seccomp=unconfined`. | `docker-compose.secure.yml:29` |
| 13 | **CI/CD floating action tags (HIGH-014).** All GitHub Actions use floating tags (`@v4`, `@v5`, `@v1`) instead of commit SHAs. | `.github/workflows/ci.yml` (multiple lines) |
| 14 | **CI/CD unpinned security tools (HIGH-015).** `go install ...@latest` for govulncheck, gosec, and golangci-lint. | `.github/workflows/ci.yml:78`, `84`, `116` |
| 15 | **Trivy mounts Docker socket and uses floating tag (HIGH-016).** Mounts `/var/run/docker.sock` and uses `aquasec/trivy:latest`. | `.github/workflows/ci.yml:206-212` |
| 16 | **Kubernetes init container runs as root with floating tag (HIGH-017).** Uses `busybox:latest` and `runAsUser: 0`. | `deploy/k8s/deployment.yaml:37-45` |
| 17 | **Kubernetes uses `latest` with `IfNotPresent` (HIGH-018).** `deployment.yaml:49` and `kustomization.yaml:22`. | `deploy/k8s/deployment.yaml:49`, `deploy/k8s/kustomization.yaml:22` |
| 18 | **Kubernetes Ingress allows config injection (HIGH-019).** `nginx.ingress.kubernetes.io/configuration-snippet` allows raw nginx config injection. | `deploy/k8s/ingress.yaml:15-19` |
| 19 | **Kubernetes default ServiceAccount token auto-mounted (HIGH-020).** No dedicated ServiceAccount with `automountServiceAccountToken: false`. | `deploy/k8s/deployment.yaml` (no ServiceAccount definition) |
| 20 | **Docker base image end-of-life (HIGH-021).** Uses `alpine:3.19` (EOL November 2025). | `Dockerfile:28` |
| 21 | **Error messages leak internal validation details (HIGH-022).** Route/webhook creation returns specific errors (`ErrInternalIP`, `ErrDNSRebind`) to the client. | `internal/api/api.go:1262-1264`, `internal/api/api.go:1268-1270`, `internal/api/api.go:2062-2064` |
| 22 | **OAuth logout omits RP-initiated logout (HIGH-004).** Clears local session but does not call the OIDC provider's `end_session_endpoint`. | `internal/api/api.go:1555-1585` |

---

## Medium Issues (fix soon)

| # | Issue | Location(s) |
|---|-------|-------------|
| 1 | **2FA setup lacks re-authentication (MED-001).** No current password required to initiate TOTP setup. | `internal/api/api.go:838-882` |
| 2 | **Bot challenge nonce freshness not validated (MED-004).** `ValidateTimestamp` only checks nonce length; replays possible within the 5-minute consumption window. | `internal/bot/challenge.go:96-100` |
| 3 | **Password change allows reusing same password (MED-005).** `ChangePassword` does not check if new password matches current. | `internal/auth/auth.go:1188-1208` |
| 4 | **Default TLS minimum version is 1.2 (MED-006).** Should default to 1.3. | `internal/config/config.go:102` |
| 5 | **WAF signing key uses raw string without base64 decoding (MED-007).** `KROXY_WAF_SIGNING_KEY` is used as raw ASCII bytes. | `internal/crypto/hmac.go:63-70` |
| 6 | **Bot detection secret auto-generated per startup (MED-009).** If `KROXY_BOT_SECRET` is unset, a new random secret is generated each restart, invalidating existing bypass cookies. | `internal/bot/globals.go:29-35` |
| 7 | **JWT secret loaded but never used (dead code) (MED-010).** `jwtSecret` field is set but never referenced. | `internal/auth/auth.go:147`, `236-259` |
| 8 | **Session cookie SameSite=Lax allows cross-site GET (MED-011).** `SameSiteLaxMode` is used. | `internal/auth/auth.go:1734` |
| 9 | **CSP missing directives (MED-012).** CSP lacks `font-src`, `connect-src`, `img-src`, etc. | `internal/api/api.go:288-291` |
| 10 | **Deprecated X-XSS-Protection header enabled (MED-013).** Still sent. | `internal/api/api.go:282` |
| 11 | **HSTS sent on HTTP responses (MED-014).** `Strict-Transport-Security` set unconditionally. | `internal/api/api.go:284` |
| 12 | **CSRF cookie Secure flag logic inconsistent (MED-015).** Tied to `KROXY_PRODUCTION` env var instead of production mode flag. | `internal/api/templates.go:234` |
| 13 | **Admin token rate limiting in-memory only (MED-016).** Counters reset on restart. | `internal/auth/auth.go:766-796` |
| 14 | **Certificate filename sanitization insufficient (MED-017).** Only replaces `/` and `..`. Path traversal via encoded sequences possible. | `internal/api/api.go:2093-2095` |
| 15 | **PEM content not validated before writing to disk (MED-018).** Raw user-supplied bytes written without parsing. | `internal/api/api.go:2098-2105` |
| 16 | **No `.dockerignore` (MED-019).** Entire repo is baked into image layers. | *missing* |
| 17 | **Kubernetes namespace lacks Pod Security Standard labels (MED-021).** Missing `pod-security.kubernetes.io/enforce: restricted`. | `deploy/k8s/namespace.yaml` |
| 18 | **Missing CORS configuration (MED-023).** No CORS headers or origin validation. | `internal/api/api.go` |
| 19 | **Template injection risk via `template.JS` for WAF presets (MED-024).** `WAFPresetJS` uses `template.JS`. | `internal/api/templates.go:490` |
| 20 | **DOM XSS via unescaped certificate domain in dashboard (MED-025).** `cert.domain` rendered into `innerHTML` without escaping. | `web/templates/pages/dashboard.html:212` |
| 21 | **Backup import is partial and lacks integrity verification (MED-026).** Only routes imported; no HMAC verification. | `internal/api/backup.go:81-136` |
| 22 | **WAF rule validation does not reject non-printable/zero-width characters.** Only `\n`, `\r`, ` `, ` `, `\x00` are rejected. Zero-width characters like `​` could bypass substring checks. | `internal/validation/validation.go:778-890` |
| 23 | **Distributed attack tracker unbounded memory growth (MED-002).** Mitigated by periodic cleanup but no hard limit on `ipAttempts` map size. | `internal/auth/auth.go:1740-1819` |

---

## Positive Findings (good security practices observed)

- **WAF newline injection (CRIT-001) fixed:** `ValidateWAFRule` now rejects `\n`, `\r`, ` `, ` `, and `\x00`; `ValidateWAFExclusions` enforces purely numeric rule IDs; `createWAFEngine` adds a defense-in-depth numeric check before writing exclusions.
- **Hardcoded AES dev key (CRIT-002) partially fixed:** `loadOrGenerateDevKey` in `internal/crypto/encryption.go` generates a random 32-byte key and persists it with `0600` permissions. `Decrypt` no longer has plaintext fallbacks.
- **Admin API binding (CRIT-003) fixed:** `config.go` enforces localhost-or-TLS in production; `main.go` uses `ListenAndServeTLS` when TLS is enabled.
- **Setup race condition (CRIT-005) fixed:** `setup` handler in `internal/api/api.go` is protected by `sync.Mutex`.
- **Login timing enumeration (LOW-009) fixed:** `dummyPasswordHash` ensures all failure paths (non-existent user, disabled user, wrong password) run `bcrypt.CompareHashAndPassword` with the same cost, equalizing timing.
- **RequireStrongAuth proxy bypass (HIGH-024) fixed:** Now uses `security.GetClientIP` which respects `X-Forwarded-For` and `KROXY_TRUSTED_PROXIES`.
- **Per-IP rate limiting added** to `/api/cert-allowed` (10/min) and `/api/setup` (3/min).
- **Audit and access log file permissions** fixed to `0600`.
- **`.kroxy-encryption-key`** added to `.gitignore`.
- **SQL injection mitigated:** All queries in `internal/store/store.go` use parameterized statements (`?` placeholders).
- **Security headers present:** HSTS, CSP with nonces, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
- **Bot challenge bypass cookie** uses HMAC-SHA256 with `subtle.ConstantTimeCompare`.
- **WAF fails closed:** When no WAF instance is available, `WAFHandler` returns `503 Service Unavailable`.
- **Cryptographic randomness:** Session IDs, API keys, CSRF tokens, and nonces all use `crypto/rand`.
- **Password hashing:** Uses bcrypt cost 12.
- **Account lockout:** Enforced after 3 failed login attempts.
- **OAuth state parameters:** Bound via HMAC-SHA256.

---

## Recommended Immediate Actions (P0)

1. **Remove all plaintext decryption fallbacks** in `store.go`, `auth.go`, and `api.go` for TOTP and OIDC secrets. Fail closed on decrypt failure.
2. **Enforce `KROXY_ENCRYPTION_KEY`** in production by failing startup if it is unset (do not just log a warning).
3. **Fix `gosec` in CI** by removing `|| true` and making it blocking; establish a baseline of accepted issues.
4. **Remove hardcoded placeholder secrets** from `deploy/k8s/secret.yaml` from Git; provide a `secret.yaml.example` and document generation steps.
5. **Lock down K8s admin exposure:** Change `KROXY_ADMIN` in `configmap.yaml` to `127.0.0.1:8080`, remove the admin port from `service.yaml`, and add a `NetworkPolicy` that denies ingress to port 8080 from all except the ingress controller or a bastion pod.
6. **Replace `getIPFromRequest`** with `security.GetClientIP` in `internal/auth/auth.go` lines 430 and 655 so API key and admin token rate limiting works correctly behind reverse proxies.
