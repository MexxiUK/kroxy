# Kroxy Web/API Layer Security Audit Report

**Scope:** HTTP handlers, web UI, middleware, routing, and browser-facing security

---

## Critical Issues

*No critical exploitable vulnerabilities were identified in the current codebase. The recently-merged security fixes (commits `8823725`, `879b512`, `c5d4e9c`) addressed the prior critical findings.*

---

## High Priority Issues

### 1. Stored XSS via Unescaped `innerHTML` in Admin Templates
Multiple admin panel templates insert API response data directly into `innerHTML` without escaping, enabling stored XSS. An authenticated admin can inject JavaScript payloads that execute in other admins' browsers.

- **`web/templates/pages/users.html:163-178`**
  `user.name`, `user.email`, `displayName`, and `avatarInitial` are interpolated into `innerHTML` without `escapeHtml()`. The `createUser` handler (`internal/api/api.go:2647`) does **not** validate the `name` field for HTML content.
  **Impact**: Admin session compromise when viewing the Users page.

- **`web/templates/pages/api-keys.html:141-163`**
  `key.name` is rendered unescaped in `innerHTML` (`api-keys.html:155`). The `generateAPIKey` handler (`internal/api/api.go:1017`) only validates length and newline characters.
  **Impact**: Admin session compromise when viewing the API Keys page.

- **`web/templates/pages/dashboard.html:212-214`**
  `cert.domain` and `cert.daysLeft` are inserted into `innerHTML` without escaping. While `cert.domain` is validated via regex server-side, `cert.daysLeft` is a raw string interpolation. This is a code-quality vulnerability that could become exploitable if validation is relaxed.

- **`web/templates/pages/ssl.html:215`**
  `cert.domain` rendered unescaped in `innerHTML`.

- **`web/templates/layouts/base.html:708`**
  The `showToast(message, type)` function sets `toast.innerHTML = message`. It is called with `result.error` from API responses at `base.html:781`. If any API endpoint returns a user-influenced string in the JSON `error` field, it becomes an XSS vector.

**Recommended fix**: Apply the existing `escapeHtml()` utility (already defined in `base.html:791`) to all dynamic values before `innerHTML` assignment, or switch to `textContent` where HTML is not required.

### 2. Improper Webhook Signature (Not True HMAC)
**File**: `internal/alerts/alerts.go:144-150`

```go
func (m *Manager) sign(payload []byte, secret string) string {
	importHash := sha256.New()
	importHash.Write([]byte(secret))
	importHash.Write(payload)
	return hex.EncodeToString(importHash.Sum(nil))
}
```

The function is documented as a "Simple HMAC placeholder" but it implements `SHA256(secret || payload)`, not `HMAC-SHA256`. This is vulnerable to **length extension attacks** and lacks HMAC's key-iteration and padding protections.

**Recommended fix**: Replace with `crypto/hmac`:
```go
mac := hmac.New(sha256.New, []byte(secret))
mac.Write(payload)
return hex.EncodeToString(mac.Sum(nil))
```

### 3. Inconsistent Secure Cookie Flag for CSRF Token
The `csrf_token` cookie is set by two different handlers with inconsistent `Secure` flag logic:

- **`internal/api/api.go:585-592`** (`getCsrfToken`): Uses `secureCookies := os.Getenv("KROXY_INSECURE_COOKIES") != "true"`
- **`internal/api/templates.go:234`** (`renderTemplate`): Uses `Secure: os.Getenv("KROXY_PRODUCTION") == "true"`

If `KROXY_INSECURE_COOKIES=true` (dev mode) but `KROXY_PRODUCTION` is unset, the API endpoint sets `Secure=false` while page rendering sets `Secure=true`. Browsers treat these as two separate cookies, causing CSRF token mismatches and potential bypass windows.

**Recommended fix**: Use a single helper function or constant for determining the `Secure` flag across all cookie-setting code paths.

---

## Medium Priority Issues

### 4. HSTS Header Sent Over HTTP Connections
**File**: `internal/api/api.go:284`

`Strict-Transport-Security: max-age=31536000; includeSubDomains` is unconditionally set in `securityHeadersMiddleware` for every response, including HTTP (non-TLS) connections. RFC 6797 explicitly states that HSTS headers should **only** be sent over secure transports.

**Recommended fix**: Only set HSTS when `r.TLS != nil` or when a configurable `TLSEnabled` flag is true.

### 5. Logout Endpoint Lacks CSRF Protection
**File**: `internal/api/api.go:387`

```go
a.router.Post("/api/auth/logout", a.oauthLogout)
```

The logout route is registered **outside** the protected route group (`a.router.Group` at line 406) and does not have `csrfMiddleware` applied. A malicious site can forge a cross-origin POST request to log the admin out.

**Recommended fix**: Move the logout endpoint inside the protected group, or apply `csrfMiddleware` directly to it.

### 6. Session Deletion Cookie `Secure` Flag Mismatch
**File**: `internal/api/api.go:1570-1578`

The logout handler unconditionally deletes the `kroxy_session` cookie with `Secure: true`. However, `CreateSessionCookie` in `internal/auth/auth.go` uses `Secure: a.productionMode`. In non-TLS development mode, the browser considers the deletion cookie (Secure) and the original cookie (non-Secure) as different cookies, so the session **is not cleared**.

**Recommended fix**: Match the `Secure` flag of the deletion cookie to the flag used when the session was originally created.

### 7. Access Log Write Errors Silently Ignored
**File**: `internal/proxy/accesslog.go:72-74`

```go
line, _ := json.Marshal(entry)
ls.logFile.Write(line)
ls.logFile.Write([]byte("\n"))
```

All three error return values are discarded. In a production environment, this masks disk-full conditions, log corruption, or permission issues. Security events could be lost without notice.

**Recommended fix**: Handle or at least log write errors.

### 8. Webhook URLs Lack SSRF Validation
**File**: `internal/alerts/alerts.go:92`

```go
req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(payload))
```

Webhook URLs are stored in the database and sent without validation. An attacker with admin access could configure a webhook pointing to `http://169.254.169.254/latest/meta-data/` (AWS IMDS), `http://localhost:8080/internal`, or other internal endpoints.

**Recommended fix**: Validate webhook URLs against an allowlist or block private IP ranges, loopback, and link-local addresses before dispatch.

### 9. Deprecated `X-XSS-Protection` Header
**File**: `internal/api/api.go:282`

```go
w.Header().Set("X-XSS-Protection", "1; mode=block")
```

This header is deprecated and has been removed from Chromium-based browsers. Historically, it introduced XSS vulnerabilities in Safari via filter bypasses. It provides no security benefit to modern browsers and may confuse security scanners.

**Recommended fix**: Remove this header entirely.

---

## Missing Security Headers / Protections

### 10. Missing `Clear-Site-Data` on Logout
The logout handler clears cookies but does not send a `Clear-Site-Data` header. This leaves cached responses, local storage, and execution contexts intact in the browser.

**Recommended fix**: Add `Clear-Site-Data: "cache", "cookies", "storage"` to the logout response.

### 11. Missing `Cache-Control` on Authenticated Responses
Authenticated API endpoints and HTML pages do not set `Cache-Control: no-store, no-cache, must-revalidate, private`. Sensitive admin data (routes, certificates, users) could be cached by browsers or intermediate proxies.

### 12. Missing CSP `font-src` and `form-action` Directives
The current CSP at `internal/api/api.go:288-291`:
```go
"default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'nonce-%s'"
```
- **`font-src`** is missing, meaning `default-src 'self'` blocks external fonts. If the UI ever needs CDN fonts, they will fail.
- **`form-action`** is missing, allowing forms to submit to arbitrary origins.

---

## Positive Findings

1. **SQL Injection Prevention** — All SQL queries in `internal/store/store.go` use parameterized placeholders (`?`). No string concatenation in SQL statements was found.
2. **CSRF Protection** — The API uses a double-submit cookie pattern. `csrfMiddleware` (`internal/api/api.go:332`) validates the `X-CSRF-Token` header against the `csrf_token` cookie using constant-time comparison.
3. **Content Security Policy with Nonces** — `securityHeadersMiddleware` (`internal/api/api.go:272`) generates a per-request CSP nonce and injects it into request context. Templates correctly apply `nonce="{{ nonce }}"` to `&lt;script&gt;` and `&lt;style&gt;` tags.
4. **X-Frame-Options: DENY** — Set on all responses, preventing clickjacking of the admin panel.
5. **Secure Session Cookies** — Session cookies (`kroxy_session`) and OAuth binding cookies (`kroxy_oauth_binding`) use `HttpOnly`, `SameSite=Strict`, and conditional `Secure` in production mode (`internal/auth/auth.go`).
6. **Open Redirect Prevention** — `isValidRedirect` (`internal/api/api.go:548-574`) strictly allows only relative URLs starting with `/`, blocking protocol-relative URLs (`//`), backslashes (`\`), and URL-encoded slashes (`%2f`, `%2F`).
7. **Backend SSRF Prevention** — `ValidateBackendURL` (`internal/validation/validation.go`) performs DNS revalidation, blocks private/reserved IPs, and rejects dangerous URL patterns.
8. **Certificate Path Traversal Defense** — Certificate filenames are derived from validated domain names with additional `..` and `/` replacement (`internal/api/api.go:2093-2095`).
9. **Rate Limiting** — Admin login and API key generation endpoints implement in-memory rate limiting (`internal/auth/auth.go`).
10. **TOTP-based 2FA** — Time-based one-time passwords with encrypted secrets stored in the database.
