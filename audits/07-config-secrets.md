# Kroxy Production-Readiness Configuration & Secrets Hygiene Audit Report

**Scope:** Configuration loading, secrets management, defaults, and environment handling

---

## CRITICAL

### 1. Webhook HMAC Secrets Exposed in REST API Responses
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/api/webhooks.go`
**Lines**: 23, 63, 110

The `listWebhooks`, `createWebhook`, and `updateWebhook` handlers serialize the raw `store.Webhook` struct directly to JSON in API responses. The `store.Webhook` model includes `Secret string \`json:"secret,omitempty"\`` (`/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/store/models.go:138`). When the secret is non-empty (the normal case), it is returned to any authenticated admin caller in plaintext. This is a critical secrets leakage vulnerability.

Affected endpoints:
- `GET /api/webhooks` — returns all webhook secrets
- `POST /api/webhooks` — returns newly created webhook secret
- `PUT /api/webhooks/:id` — returns updated webhook secret

---

## HIGH

### 2. Kubernetes ConfigMap Exposes Admin API to All Interfaces
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/deploy/k8s/configmap.yaml`
**Line**: 11

```yaml
KROXY_ADMIN: "0.0.0.0:8080"
```

Combined with `KROXY_PRODUCTION: "true"` (line 13) and no app-level TLS (`KROXY_TLS_ENABLED` is absent), the application will fail config validation because production mode requires the admin API to use TLS or bind to localhost. The manifest is effectively broken as-is, but if an operator bypasses validation or adds ingress-level TLS without enabling app-level TLS, the admin API becomes network-reachable without transport encryption.

### 3. docker-compose.yml Uses Insecure Development Defaults
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/docker-compose.yml`
**Lines**: 41, 44, 45

```yaml
- KROXY_ADMIN=:8080          # binds 0.0.0.0 inside container
- KROXY_PRODUCTION=false
- KROXY_ALLOW_PRIVATE_BACKENDS=true
```

This file is suitable for local development but poses a significant risk if copied to production unchanged. `KROXY_ALLOW_PRIVATE_BACKENDS=true` permits SSRF to internal IPs, and `KROXY_PRODUCTION=false` disables production hardening.

### 4. `HexSecret()` Exposes Bot Detection Secret
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/bot/globals.go`
**Lines**: 82-86

```go
// HexSecret returns the current secret as a hex string for persistence/debug.
func HexSecret() string {
    globalMu.RLock()
    defer globalMu.RUnlock()
    return hex.EncodeToString(globalSecret)
}
```

An exported function returns the current bot-detection HMAC secret in hex with no access controls or build-tag restrictions. If called from any debug endpoint or accidentally wired into a log line, it leaks a security key.

### 5. Missing `.env.example` File
**File**: (none found)

No `.env.example` exists in the repository, making it difficult for operators to discover required secrets and environment variables:
- `KROXY_JWT_SECRET`
- `KROXY_ENCRYPTION_KEY`
- `KROXY_WAF_SIGNING_KEY`
- `KROXY_BOT_SECRET`
- `KROXY_AUDIT_SIGNING_KEY`

### 6. Pre-built Binaries and SQLite Database in Working Tree
**Files**:
- `/run/media/david-lee/SabrentRAID/Projects/kroxy/kroxy` (85MB binary)
- `/run/media/david-lee/SabrentRAID/Projects/kroxy/kroxy-fixed` (86MB binary)
- `/run/media/david-lee/SabrentRAID/Projects/kroxy/kroxy.db` (212KB SQLite database)

While `*.db`, `/kroxy`, and `/kroxy-fixed` are listed in `.gitignore`, these files exist on disk in the repository root. They risk accidental inclusion in Docker build contexts (`COPY . .`), release archives, or SCP deployments. The `kroxy.db` file may contain actual user data, sessions, or hashed credentials.

---

## MEDIUM

### 7. Webhook Store Model Reused for API Responses
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/store/models.go`
**Line**: 138

The project lacks a dedicated API response DTO for webhooks. Reusing the persistence model for JSON serialization is an architectural anti-pattern that directly enabled finding #1.

### 8. Example docker-compose Files Use Placeholder ACME Email
**Files**:
- `/run/media/david-lee/SabrentRAID/Projects/kroxy/docker-compose.secure.yml:49`
- `/run/media/david-lee/SabrentRAID/Projects/kroxy/docs/examples/docker-compose.django.yml:28`
- `/run/media/david-lee/SabrentRAID/Projects/kroxy/docs/examples/docker-compose.nextjs.yml:28`

All set `KROXY_ACME_EMAIL=admin@example.com`. While documented with "Change this!" comments, it is easy to miss during rapid deployments.

### 9. Bot Detection Auto-Generates Short Secret in Dev Mode
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/bot/globals.go`
**Line**: 30

```go
b := make([]byte, 16)
```

When `KROXY_BOT_SECRET` is unset, only 16 random bytes are generated. The recommended minimum for HMAC signing keys is 32 bytes (256 bits).

### 10. `data/audit.log` Present in Working Tree
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/data/audit.log`

The file contains actual login audit events with email addresses and session IDs. While `*.log` is in `.gitignore`, it is present on disk and could be captured in Docker build contexts or backups.

### 11. Silent Error Handling in Config Parsers
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/config/config.go`
**Lines**: 132-142, 144-154

`getEnvBool` and `getEnvInt64` silently swallow parse errors and fall back to defaults without logging. For example, setting `KROXY_MAX_REQUEST_SIZE=1O_MB` (letter O instead of zero) would silently use the 10MB default.

---

## LOW

### 12. Double-Negative Environment Variable Naming
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/api/api.go`
**Line**: 585

```go
secureCookies := os.Getenv("KROXY_INSECURE_COOKIES") != "true"
```

Setting `KROXY_INSECURE_COOKIES=true` disables security. This inverted logic is confusing and error-prone.

### 13. Dev Encryption Key Written to Unpredictable Path
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/crypto/encryption.go`
**Lines**: 24-31

When `KROXY_DATA_DIR` is unset, the dev encryption key is written to `./.kroxy-encryption-key` (current working directory). In containerized environments the working directory may be unexpected or ephemeral.

### 14. Test Utilities Contain Realistic-Looking Passwords
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/testutil/api.go`
**Lines**: 25, 40

```go
"password": "AdminPass1!123",
```

Low risk because these are in `internal/testutil`, but automated secret scanners may flag them.

### 15. `getEnv` Treats Empty String as Unset
**File**: `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/config/config.go`
**Lines**: 125-130

```go
if val := os.Getenv(key); val != "" {
    return val
}
return defaultVal
```

There is no way to intentionally set an environment variable to an empty string. This prevents clearing optional values via the environment.

---

## POSITIVE FINDINGS (Secure by Default)

1. **Admin API binds to `127.0.0.1:8081` by default** — prevents accidental network exposure.
2. **Production mode requires absolute DB path** — `KROXY_DB` must be explicitly set and absolute.
3. **`KROXY_ALLOW_PRIVATE_BACKENDS` defaults to `false`** — SSRF protection is on by default.
4. **`KROXY_HSTS_ENABLED` defaults to `true`** and `KROXY_REDIRECT_HTTP` defaults to `true`.
5. **JWT, WAF, and Audit signing keys are required in production** — `config.Load()` and `auth.New()` call `log.Fatal` if missing.
6. **OIDC client secrets are correctly masked** — `listOIDCProviders` intentionally omits `client_secret` from JSON responses.
7. **Session cookies use `HttpOnly`, `Secure` (in production), and `SameSite=Lax`**; CSRF cookies use `SameSite=Strict`.
8. **Database file permissions set to `0600`** on initialization.
9. **No hardcoded secrets, API keys, or passwords** in production source code.
10. **`.gitignore` properly excludes** `.env`, `*.db`, `*.pem`, `*.key`, `admin_token`, `.kroxy-encryption-key`, and other sensitive artifacts.

---

## SECRETS MANAGEMENT RECOMMENDATIONS

1. **Create a separate API DTO for webhooks** that excludes the `Secret` field. Return the secret only once during creation (similar to API key generation at `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/api/api.go:1086-1090`).
2. **Remove or restrict `HexSecret()`** — either delete it, restrict it to test builds with `//go:build debug`, or gate it behind an explicit unsafe flag.
3. **Add `.env.example`** documenting all required and optional secrets with generation commands (e.g., `openssl rand -base64 32`).
4. **Clean working tree** — delete `kroxy`, `kroxy-fixed`, `kroxy.db`, and `data/audit.log` from disk. Consider adding a `.dockerignore` to exclude them from build contexts.
5. **Fix K8s manifest** — change `KROXY_ADMIN` to `127.0.0.1:8080` or document that `KROXY_TLS_ENABLED=true` is mandatory when using `0.0.0.0`.
6. **Add validation warnings** in `getEnvBool`/`getEnvInt64` when parsing fails, so misconfigurations are visible in logs.
7. **Rename `KROXY_INSECURE_COOKIES`** to `KROXY_SECURE_COOKIES` with inverted logic for clarity.
8. **Increase bot detection dev secret** from 16 bytes to 32 bytes.
9. **Ensure `data/` directory is excluded** from Docker build contexts and backup scripts.
