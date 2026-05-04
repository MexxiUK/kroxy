# Kroxy Comprehensive Security Audit Report
**Date:** 2026-05-04
**Scope:** Application code, deployment artifacts, CI/CD pipeline, cryptography, infrastructure
**Methodology:** 10 parallel security agents (5 Red Team offensive, 5 Blue Team defensive)

---

## Executive Summary

The audit identified **7 Critical**, **24 High**, **26 Medium**, and **10 Low** severity findings across Kroxy's codebase, deployment artifacts, and CI/CD pipeline. The most severe issues are:

1. **WAF rule newline injection** — any admin can inject `\nSecRuleEngine Off` to completely disable the WAF for any route
2. **WAF regex bypass via quoted strings** — admin can set default action to `pass`, disabling blocking
3. **RequireStrongAuth bypass behind reverse proxy** — all external traffic treated as internal, 2FA not enforced
4. **Hardcoded AES-256 development encryption key** that defeats all at-rest confidentiality
5. **Admin API serves over plaintext HTTP**, exposing session cookies and admin tokens
6. **API key authentication triggers bcrypt-12 on every request** — a direct DoS vector
7. **Setup endpoint has a race condition** allowing multiple initial admins
8. **CI/CD silently ignores all security scan failures**, publishing potentially vulnerable artifacts
9. **Hardcoded placeholder secrets committed to Kubernetes manifests**

---

## Critical Findings

### CRIT-001: WAF Rule Newline Injection (Rule & Exclusions Fields)
- **Severity:** Critical
- **Location:** `internal/validation/validation.go:778-884`, `internal/waf/waf.go:543-566`, `internal/api/api.go:2285-2355`
- **Description:** `ValidateWAFRule` does not reject newline (`\n`) or carriage return (`\r`) characters in WAF rules. Rules are concatenated into a directives string with a trailing newline. An attacker can inject `\nSecRuleEngine Off` into a rule, causing Coraza to interpret it as a separate directive. The `Exclusions` field is completely unvalidated.
- **Impact:** Any authenticated admin can completely disable the WAF for any route by creating a malicious WAF rule. All WAF protections (including bot detection, rate limiting, and OWASP CRS) are bypassed.
- **Proof of Concept:**
  ```json
  {
    "name": "Bypass",
    "rule": "SecRule ARGS \"@rx test\" \"id:9999,phase:2,deny\"\nSecRuleEngine Off\n",
    "enabled": true
  }
  ```
- **Fix:**
  1. Reject any WAF rule containing `\n`, `\r`, ` `, or ` `
  2. Sanitize `Exclusions` by splitting on commas, trimming whitespace, validating each element is purely numeric
  3. Use a strict parser rather than concatenating raw strings into Coraza directives

### CRIT-002: Hardcoded AES-256 Development Encryption Key
- **Severity:** Critical
- **Location:** `internal/crypto/encryption.go:32`
- **Description:** When `KROXY_PRODUCTION` is not `"true"`, the app derives the AES-256 key from the static string `"kroxy-dev-key-v1"` via SHA256. All dev/staging/misconfigured-prod instances share the same key. Additionally, `Decrypt` has plaintext fallbacks (`PLAIN:` prefix and raw return on base64 failure).
- **Impact:** Complete confidentiality breach. Anyone with source code access can decrypt all TOTP secrets, OIDC client secrets, and encrypted fields.
- **Fix:** Remove hardcoded fallback entirely. Require `KROXY_ENCRYPTION_KEY` in all environments. Generate random persistent key for dev mode stored at `0600` file.

### CRIT-003: Admin API Serves Over Plaintext HTTP
- **Severity:** Critical
- **Location:** `cmd/kroxy/main.go:173-188`
- **Description:** The admin API unconditionally calls `ListenAndServe()` (HTTP). Even when `TLSEnabled=true`, the admin port never uses HTTPS.
- **Impact:** Session cookies (`kroxy_session`) and `X-Admin-Token` transmitted in plaintext. Susceptible to network sniffing, ARP spoofing, DNS hijacking.
- **Fix:** Bind admin to `127.0.0.1` by default. Use `ListenAndServeTLS` when `TLSEnabled=true`, or front with TLS-terminating proxy. Add `AdminTLSEnabled` config flag.

### CRIT-004: API Key Authentication — bcrypt DoS Vector
- **Severity:** Critical
- **Location:** `internal/auth/auth.go:686`
- **Description:** Every API request with an API key performs `bcrypt.CompareHashAndPassword` at cost 12 (~150-300ms per comparison). An attacker can exhaust CPU with random key ID + secret requests.
- **Impact:** Denial of service. 1000 req/s with random secrets pegs all CPU cores.
- **Fix:** Cache successful API key validations in memory (short TTL). Or use fast HMAC-SHA256 verification alongside bcrypt: verify HMAC first, fall back to bcrypt only on match.

### CRIT-005: Setup Endpoint Race Condition (Multiple Initial Admins)
- **Severity:** Critical
- **Location:** `internal/api/api.go:607-686`
- **Description:** Setup checks `len(users) > 0` then creates the first admin. No mutex or DB transaction wraps the check-and-create.
- **Impact:** Two concurrent setup requests can both observe zero users and create separate admin accounts, giving an attacker persistent admin access.
- **Fix:** Wrap check+insert in a single SQLite transaction with `BEGIN IMMEDIATE`, or use an app-level mutex.

### CRIT-006: CI/CD Security Scans Are Silently Ignored
- **Severity:** Critical
- **Location:** `.github/workflows/ci.yml`
- **Description:** `govulncheck ./... || true`, `gosec ./... || true`, `semgrep-action` with `continue-on-error: true`, and trivy without `--exit-code 1`.
- **Impact:** Supply chain compromises, newly disclosed CVEs, and security vulnerabilities pass CI undetected. Vulnerable binaries and images are published.
- **Fix:** Remove all `|| true` and `continue-on-error` from security scans. Establish vulnerability baselines and use `.trivyignore` for accepted risks only.

### CRIT-007: Hardcoded Placeholder Secrets in Kubernetes Manifests
- **Severity:** Critical
- **Location:** `deploy/k8s/secret.yaml`
- **Description:** `kroxy-secrets` and `kroxy-admin-token` contain hardcoded placeholder values (`CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_BASE64_32`). Committed to Git.
- **Impact:** Any operator who deploys without modification uses publicly known secrets. Full admin compromise.
- **Fix:** Remove `secret.yaml` from Git. Provide `secret.yaml.example`. Use External Secrets Operator or Sealed Secrets for production.

---

## High Findings

### HIGH-001: TOTP Secret Plaintext Fallback on Decrypt Failure
- **Location:** `internal/auth/auth.go:1165-1169`, `internal/api/api.go:903-905`
- **Description:** If `crypto.Decrypt` fails, the code silently falls back to using the raw database value as the TOTP secret. Combined with dev-mode plaintext fallback, this means TOTP secrets can be stored and operated on in plaintext.
- **Fix:** Never swallow decryption errors. Force 2FA re-enrollment on decrypt failure.

### HIGH-002: Sessions Not Bound to IP or User-Agent
- **Location:** `internal/auth/auth.go:485-601`
- **Description:** `Session` struct stores `IP` and `UserAgent`, but `validateSession` never compares them. A stolen cookie works from any IP/browser.
- **Fix:** Add IP/User-Agent validation. Invalidate session on significant changes. Allow IPv6 /64 prefix tolerance.

### HIGH-003: Admin Tokens Hashed with Fast SHA256
- **Location:** `internal/auth/auth.go:1337-1370`
- **Description:** Admin setup tokens are hashed with SHA256 before storage. SHA256 is designed for speed, making offline brute-force feasible.
- **Fix:** Hash admin tokens with bcrypt cost 12, same as passwords.

### HIGH-004: OAuth Logout Omits RP-Initiated Logout
- **Location:** `internal/api/api.go:1542-1572`
- **Description:** Logout clears local session but does not call the OIDC provider's `end_session_endpoint`. User remains authenticated at the IdP.
- **Fix:** Implement RP-initiated logout. Redirect to provider's end-session endpoint with `post_logout_redirect_uri`.

### HIGH-005: Session Cookie Secure Flag Tied to Production Mode
- **Location:** `internal/auth/auth.go:1657`
- **Description:** `Secure: a.productionMode` means cookies are sent over HTTP in non-production. If an operator deploys over HTTPS but forgets `KROXY_PRODUCTION=true`, cookies leak.
- **Fix:** Make `Secure: true` unconditional. Add explicit `KROXY_INSECURE_COOKIES=true` dev override.

### HIGH-006: Webhook Signature Uses Raw SHA-256 Instead of HMAC
- **Location:** `internal/alerts/alerts.go:144-150`
- **Description:** Webhook signing concatenates secret + payload and hashes with raw SHA-256. Not an HMAC. Vulnerable to length-extension attacks.
- **Fix:** Replace with `crypto/hmac` using HMAC-SHA256.

### HIGH-007: Webhook Secrets Stored in Plaintext
- **Location:** `internal/store/store.go:1082-1104`
- **Description:** Webhook secrets are stored in SQLite as plaintext text. No encryption or hashing.
- **Fix:** Encrypt webhook secrets with AES-256-GCM (same as OIDC secrets) before storage.

### HIGH-008: OIDC Client Secrets Silently Fall Back to Plaintext
- **Location:** `internal/store/store.go:162-168`
- **Description:** `GetOIDCProvider` attempts to decrypt client_secret. If decryption fails, silently uses raw database value.
- **Fix:** Remove plaintext fallback. Return explicit error on decrypt failure. Fail closed.

### HIGH-009: XSS Vulnerabilities in Frontend Templates
- **Location:** `web/templates/pages/dashboard.html`, `web/templates/pages/users.html`, `web/templates/pages/setup.html`
- **Description:** Multiple `innerHTML` assignments use unescaped user data (display names, emails, domains, avatar initials). Stored XSS: an admin sets malicious name, another admin views the page, script executes.
- **Fix:** Audit all `innerHTML` assignments. Apply `escapeHtml()` to every interpolated variable. Prefer `textContent` where HTML is not required.

### HIGH-010: Backup Export Includes Plaintext Secrets
- **Location:** `internal/api/backup.go`
- **Description:** Backup export includes OIDC `client_secret`, certificate private keys, and other sensitive data in unencrypted JSON.
- **Fix:** Strip/redact secrets from backup export. Sign backups with HMAC using `KROXY_BACKUP_KEY`. Verify signature on import.

### HIGH-011: No IP Allowlisting for Admin Access
- **Location:** `internal/api/api.go`, `internal/api/templates.go`
- **Description:** Any user with valid credentials can access the admin panel from anywhere. `RequireStrongAuth` only enforces 2FA for public IPs.
- **Fix:** Add optional `ADMIN_IP_ALLOWLIST` environment variable. Enforce in `RequireAuth` middleware.

### HIGH-012: Docker Compose Insecure Defaults
- **Location:** `docker-compose.yml:44-45`
- **Description:** `KROXY_PRODUCTION=false` and `KROXY_ALLOW_PRIVATE_BACKENDS=true` by default.
- **Impact:** SSRF vulnerability to cloud metadata endpoints and internal networks.
- **Fix:** Set `KROXY_PRODUCTION=true` and `KROXY_ALLOW_PRIVATE_BACKENDS=false` by default. Use `docker-compose.override.yml` for dev.

### HIGH-013: Docker Compose Disables Seccomp
- **Location:** `docker-compose.secure.yml:29`
- **Description:** `seccomp=unconfined` completely disables syscall filtering.
- **Fix:** Remove `seccomp=unconfined`. SQLite works fine with default seccomp profile.

### HIGH-014: CI/CD Floating Action Tags
- **Location:** `.github/workflows/ci.yml`
- **Description:** All GitHub Actions use floating tags (`@v4`, `@v5`, `@v1`). Compromised publishers could redirect tags to malicious commits.
- **Fix:** Pin all actions to specific commit SHAs with version comments.

### HIGH-015: CI/CD Unpinned Security Tools
- **Location:** `.github/workflows/ci.yml:78, 84, 114`
- **Description:** `go install ...@latest` for govulncheck, gosec, golangci-lint.
- **Fix:** Pin to specific versions in `tools.go` or use versioned GitHub Actions.

### HIGH-016: CI/CD Trivy Mounts Docker Socket
- **Location:** `.github/workflows/ci.yml:203-210`
- **Description:** Trivy runs with `-v /var/run/docker.sock:/var/run/docker.sock`. Grants root-equivalent access. Uses `aquasec/trivy:latest` floating tag.
- **Fix:** Use `aquasecurity/trivy-action` GitHub Action instead. Avoid socket mounts.

### HIGH-017: Kubernetes Init Container Runs as Root with Floating Tag
- **Location:** `deploy/k8s/deployment.yaml:37-45`
- **Description:** `busybox:latest` init container runs as `runAsUser: 0`. Redundant because `fsGroup: 1000` already handles volume permissions.
- **Fix:** Remove init container entirely. Rely on `fsGroup`.

### HIGH-018: Kubernetes Uses `latest` with `IfNotPresent`
- **Location:** `deploy/k8s/deployment.yaml:49`
- **Description:** `imagePullPolicy: IfNotPresent` with `latest` tag means nodes may run stale cached images.
- **Fix:** Pin to digest in `kustomization.yaml`. Set `imagePullPolicy: Always` if using floating tags.

### HIGH-019: Kubernetes Ingress Allows Config Injection
- **Location:** `deploy/k8s/ingress.yaml:15-19`
- **Description:** `nginx.ingress.kubernetes.io/configuration-snippet` allows raw nginx config injection.
- **Fix:** Move headers to application code or use a dedicated WAF/edge proxy. Remove config-snippet.

### HIGH-020: Kubernetes Default SA Token Auto-Mounted
- **Location:** `deploy/k8s/deployment.yaml`
- **Description:** No dedicated ServiceAccount. Default SA token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`.
- **Fix:** Create dedicated `ServiceAccount` with `automountServiceAccountToken: false`.

### HIGH-021: Docker Base Image End-of-Life
- **Location:** `Dockerfile:28`
- **Description:** `alpine:3.19` support ended November 2025. No more security patches.
- **Fix:** Upgrade to `alpine:3.20` or `alpine:3.21` (latest stable).

### HIGH-022: Error Messages Leak Internal Validation Details
- **Location:** `internal/api/api.go`
- **Description:** Route/webhook creation returns specific validation errors (`ErrInternalIP`, `ErrDNSRebind`) to the client, aiding attacker reconnaissance.
- **Fix:** Return generic "Invalid URL" to client. Log specific error server-side with request IDs.

### HIGH-023: WAF Disable Regex Bypass via Quoted Strings
- **Location:** `internal/validation/validation.go:44-51`
- **Description:** WAF validation regexes like `(?i)secdefaultaction\s+[^"]*pass` assume `pass` appears before any quoted string. Coraza directives commonly use quoted arguments (e.g., `SecDefaultAction "phase:1,pass,nolog,status:200"`). The regex cannot match across quote boundaries.
- **Impact:** An admin can create a WAF rule that sets the default action to `pass`, causing all detections to become log-only — effectively disabling the WAF in blocking mode.
- **Proof of Concept:**
  ```json
  {"name": "Bypass", "rule": "SecDefaultAction \"phase:2,pass,nolog,status:200\"", "enabled": true}
  ```
- **Fix:** Normalize rules by removing quotes before applying regex, or maintain a strict allowlist of permitted directives and reject any rule containing `SecDefaultAction`, `SecRuleEngine`, or `SecRuleRemoveById` via case-insensitive substring search.

### HIGH-024: RequireStrongAuth Bypass Behind Reverse Proxy
- **Location:** `internal/auth/auth.go:1247-1296`, `internal/auth/auth.go:792-798`
- **Description:** `RequireStrongAuth` uses `getIPFromRequest`, which only inspects `r.RemoteAddr` (strips port). When behind a reverse proxy, `RemoteAddr` is the proxy's internal IP (e.g., `10.0.0.1`), classified as private. All external traffic is treated as internal, and password-only authentication is permitted without 2FA.
- **Impact:** Complete bypass of 2FA enforcement for all users when Kroxy is deployed behind a load balancer or ingress controller.
- **Fix:** Use `security.GetClientIP(r)` (which respects `X-Forwarded-For` from `KROXY_TRUSTED_PROXIES`) instead of `getIPFromRequest` in `RequireStrongAuth`. Document `KROXY_TRUSTED_PROXIES` as mandatory for reverse proxy deployments.

---

## Medium Findings

| ID | Description | Location |
|----|-------------|----------|
| MED-001 | 2FA setup lacks re-authentication (password not required) | `api.go:825-869` |
| MED-002 | Distributed attack tracker unbounded memory growth | `auth.go:1725-1745` |
| MED-003 | Inconsistent IP extraction (auth.go vs security.go) | `auth.go:792-798` |
| MED-004 | Bot challenge nonce freshness not validated | `bot/challenge.go:96-100` |
| MED-005 | Password change allows reusing same password | `auth.go:1104-1124` |
| MED-006 | Default TLS minimum version is 1.2 | `config.go:90` |
| MED-007 | WAF signing key uses raw string without base64 decoding | `crypto/hmac.go:49-70` |
| MED-008 | AES decrypt returns raw ciphertext on base64 failure (dev) | `crypto/encryption.go:127-131` |
| MED-009 | Bot detection secret auto-generated per startup | `bot/globals.go:29-35` |
| MED-010 | JWT secret loaded but never used (dead code) | `auth.go:128, 216-240` |
| MED-011 | Session cookie SameSite=Lax allows cross-site GET | `auth.go:1658` |
| MED-012 | CSP breaks admin UI (missing font-src, connect-src) | `api.go` |
| MED-013 | X-XSS-Protection header enabled (deprecated, can introduce XSS) | `api.go` |
| MED-014 | HSTS sent on HTTP responses (non-compliant) | `api.go` |
| MED-015 | CSRF token Secure flag logic inconsistent (env var vs production mode) | `api.go`, `templates.go` |
| MED-016 | Admin token rate limiting in-memory only (resets on restart) | `auth.go` |
| MED-017 | Certificate filename sanitization insufficient | `api.go` |
| MED-018 | PEM content not validated before writing to disk | `api.go` |
| MED-019 | No `.dockerignore` — entire repo baked into image layers | Repository root |
| MED-020 | K8s admin API exposed cluster-wide without NetworkPolicy | `deploy/k8s/` |
| MED-021 | K8s namespace lacks Pod Security Standard labels | `deploy/k8s/namespace.yaml` |
| MED-022 | Prometheus metrics exposed on admin port without auth | `deploy/k8s/` |
| MED-023 | Missing CORS configuration | `api.go` |
| MED-024 | Template injection risk via `template.JS` for WAF presets | `templates.go` |
| MED-025 | DOM XSS via unescaped certificate domain in dashboard | `dashboard.html:212` |
| MED-026 | Backup import DoS (no body size limit) and partial restore | `backup.go:81-136` |

---

## Low Findings

| ID | Description | Location |
|----|-------------|----------|
| LOW-001 | TOTP uses SHA1 algorithm (RFC 6238 compliant but dated) | `totp/totp.go` |
| LOW-002 | Dockerfile `go mod tidy` can mutate dependencies during build | `Dockerfile:22` |
| LOW-003 | Docker Compose hardcoded subnets may conflict | `docker-compose.yml` |
| LOW-004 | CI checkout persists credentials | `.github/workflows/ci.yml` |
| LOW-005 | K8s `tmpfs` config directories world-writable | `docker-compose.yml` |
| LOW-006 | Dockerfile installs unnecessary `curl` in final image | `Dockerfile` |
| LOW-007 | Makefile invokes insecure Docker Compose by default | `Makefile:36-37` |
| LOW-008 | Page routes bypass `RequireStrongAuth` middleware | `templates.go` |
| LOW-009 | Public domain enumeration via `/api/cert-allowed` endpoint | `api.go:2218-2246` |
| LOW-010 | Unconditional HSTS header on HTTP responses | `api.go:283` |

---

## Positive Security Controls

- Passwords hashed with bcrypt cost 12
- AES-256-GCM correctly implemented with random 12-byte nonces
- All tokens use `crypto/rand` (session IDs, API keys, CSRF tokens, nonces)
- Constant-time comparisons for HMAC and cookie validation
- Account lockout after 3 failed attempts
- OAuth state parameters bound via HMAC
- Parameterized SQL queries (no SQL injection)
- HSTS, CSP with nonces, X-Frame-Options headers
- Non-root execution in containers (UID 1000)
- Read-only root filesystem in K8s/Docker
- Capability dropping (drop ALL, add only NET_BIND_SERVICE)
- seccompProfile: RuntimeDefault in K8s
- Systemd hardening (ProtectSystem, ProtectHome, PrivateTmp, MemoryDenyWriteExecute)

---

## Remediation Priority Matrix

### P0 — Immediate (This Week)
1. Fix WAF rule newline injection (reject `\n`, `\r` in rules; validate exclusions)
2. Fix WAF regex bypass (normalize/remove quotes before regex matching)
3. Fix `RequireStrongAuth` to use `security.GetClientIP` instead of naive `getIPFromRequest`
4. Remove hardcoded AES dev key; require `KROXY_ENCRYPTION_KEY`
5. Enable TLS for admin API or bind to localhost
6. Fix API key bcrypt DoS (add caching or fast HMAC pre-check)
7. Fix setup endpoint race condition (DB transaction)
8. Stop ignoring security scan failures in CI
9. Remove hardcoded secrets from K8s manifests
10. Create `.dockerignore`

### P1 — This Sprint
1. Remove all plaintext decryption fallbacks (TOTP, OIDC)
2. Bind sessions to IP/User-Agent
3. Switch admin token hashing to bcrypt
4. Implement RP-initiated OAuth logout
5. Make Secure cookie flag unconditional
6. Fix webhook signature to use HMAC-SHA256
7. Encrypt webhook secrets at rest
8. Fix XSS in all frontend templates (unescaped `innerHTML`, `escapeHtml`)
9. Fix DOM XSS in dashboard (escape certificate domain)
10. Redact secrets from backup exports; add HMAC signature
11. Add backup import size limit (50MB); implement full restore
12. Add admin IP allowlist option
13. Fix Docker Compose defaults and seccomp
14. Pin CI action SHAs and tool versions
15. Remove Docker socket mount from Trivy
16. Remove root init container from K8s
17. Pin K8s image digest
18. Add NetworkPolicy for admin port
19. Create dedicated ServiceAccount
20. Upgrade Alpine base image

### P2 — Next Sprint
1. Add zxcvbn password strength validation
2. Add Have I Been Pwned breach detection
3. Implement exponential backoff for account lockout
4. Add API key IP allowlists and scopes
5. Add per-endpoint rate limiting
6. Add idle timeout to sessions
7. Add recovery codes for 2FA
8. Improve CSP (add report-uri, font-src, connect-src)
9. Add CORS configuration
10. Add input validation hardening (certificate filenames, PEM)
11. Add topology spread constraints to K8s
12. Add Pod Security Standard labels to namespace
13. Sign container images with Cosign
14. Generate and publish SBOMs
