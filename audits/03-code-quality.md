# Kroxy Production-Readiness Code Quality Audit Report

**Scope:** Go idioms, error handling, concurrency safety, and runtime stability
**Key areas:** All `.go` files in `internal/`, `cmd/`, and `pkg/`

---

## Critical Issues

### 1. SQLite Connection Pool Misconfiguration — "database is locked" Under Concurrency
**File:** `internal/store/store.go:20-44`
`store.New()` opens a SQLite database via `sql.Open()` but never calls `db.SetMaxOpenConns(1)`. With the default unlimited pool, concurrent writes from multiple goroutines (API requests, health checks, WAF event logging, session updates) will reliably produce `database is locked` errors because SQLite file locking does not tolerate multiple writers. This is the single biggest reliability risk in production.

**Fix:** Add `db.SetMaxOpenConns(1)` immediately after `sql.Open`. Also consider `db.SetConnMaxLifetime(...)` and enabling WAL mode in the migrator.

### 2. Silent Data Loss — Missing `rows.Err()` After Iteration Loops
**File:** `internal/store/store.go` (multiple methods)
Almost every query method (`GetRoutes`, `GetOIDCProviders`, `GetWhitelists`, `GetBlacklists`, `GetRateLimits`, `GetUsers`, `GetWAFRules`, `GetGlobalWAFRules`, `GetWAFRulesForRoute`, `GetSecurityEvents`, `GetSecurityEventsForRoute`, `GetSessionsByUser`, `GetWebhooks`, `GetRedirectDomains`) checks `rows.Err()` *inside* the `for rows.Next()` loop (where it is always nil) but **omits the required post-loop `rows.Err()` check**. If the database connection fails during iteration, `rows.Next()` returns false, the error is silently swallowed, and a **partial result set is returned to callers** as if it were complete. This is a data integrity and potential security bug.

**Fix:** Add `if err := rows.Err(); err != nil { return nil, err }` after every `for rows.Next() { ... }` block.

### 3. Alert Webhook Signature Is Not HMAC — Length Extension Vulnerable
**File:** `internal/alerts/alerts.go:144-150`
The `sign()` function claims to produce an HMAC but actually computes a plain SHA-256 hash of `secret || payload`:
```go
importHash := sha256.New()
importHash.Write([]byte(secret))
importHash.Write(payload)
```
This is vulnerable to length extension attacks and does not provide the cryptographic integrity guarantees of HMAC.

**Fix:** Replace with `hmac.New(sha256.New, []byte(secret))`.

### 4. OIDC Provider Secret Wiped on Partial Update
**File:** `internal/api/api.go:1719-1770` (`updateOIDCProvider`)
When updating an OIDC provider, the handler unconditionally sets `provider.ClientSecret = req.ClientSecret`. If the client omits `client_secret` from the JSON payload (e.g., to update only the redirect URL), the stored secret is **overwritten with an empty string**. This breaks authentication for that provider immediately.

**Fix:** Make `client_secret` optional in updates; only overwrite if non-empty.

### 5. OIDC Manager In-Memory Cache Never Updated/Deleted
**File:** `internal/api/api.go:1719-1770` (update), `1772-1794` (delete)
`updateOIDCProvider` persists changes to the database but never reinitializes the provider in the OIDC manager's in-memory map. `deleteOIDCProvider` removes the row from the database but never deletes it from the manager's map. **Old configurations remain active until process restart.**

**Fix:** Call `m.oidcManager.InitializeProvider(...)` after update and add a `RemoveProvider(id)` method to the OIDC manager for deletes.

### 6. Access Log Store Ignores Write Errors and Never Syncs
**File:** `internal/proxy/accesslog.go:71-75`
```go
line, _ := json.Marshal(entry)
ls.logFile.Write(line)
ls.logFile.Write([]byte("\n"))
```
All three operations ignore errors. If the disk is full or the log file descriptor becomes stale, access logs are silently lost with no signal. There is also no `Sync()` call, so buffered data can be lost on crash.

**Fix:** Check errors from `json.Marshal`, `Write`, and optionally call `Sync()` after writes or use a buffered writer with periodic flushes.

### 7. Shutdown Ignores All Critical Errors
**File:** `cmd/kroxy/main.go:219-224`
```go
px.Stop()
server.Shutdown(ctx)
if logStore != nil {
    logStore.Close()
}
```
Errors from proxy shutdown, HTTP server shutdown, and log store close are all discarded. If shutdown fails, the process may exit while connections are still active or files are unflushed.

**Fix:** Capture and log (or return) each error.

### 8. Abrupt Process Termination on `crypto/rand` Failure
**Files:** `internal/auth/auth.go:1692-1693`, `internal/api/api.go:221,601,1458`, `internal/crypto/hmac.go:57`, `internal/crypto/encryption.go:51`, `internal/audit/audit.go:100`, `internal/bot/globals.go:32`
Multiple functions call `log.Fatalf` if `crypto/rand.Read` fails. `log.Fatalf` calls `os.Exit(1)` immediately without running deferred functions (e.g., database close, log flushes). In a production HTTP server, this is an inappropriate panic substitute.

**Fix:** Return errors to callers and let the HTTP framework handle the failure gracefully (e.g., return HTTP 500).

### 9. Static File Handler Panic Risk
**File:** `internal/api/api.go:371`
```go
staticFS, _ := fs.Sub(web.StaticFS, "static")
```
The error from `fs.Sub` is discarded. If the embedded filesystem is missing the `static` directory (build issue, corruption), `staticFS` is nil and the `http.FileServer` will panic on the first `/static/*` request.

**Fix:** Handle the error; return from `New()` or serve a safe fallback.

### 10. WAF Fail-Open on Body Processing Error
**File:** `internal/waf/waf.go:710-718`
```go
if intervention, _ := tx.ProcessRequestBody(); intervention != nil {
```
The error from `ProcessRequestBody` is ignored with `_`. If Coraza encounters an error processing the request body (e.g., malformed multipart, memory pressure), `intervention` may be nil and the request **silently passes through** without WAF inspection. This is a security regression.

**Fix:** Do not ignore the error; fail-closed (return blocked) if body processing errors occur.

### 11. Unbounded Fire-and-Forget Goroutines
**Files:** `internal/auth/auth.go:553`, `596`, `728`
The auth system spawns background goroutines for database writes (`UpdateSessionExpiry`, `UpdateAPIKeyLastUsed`) with no limit on concurrency:
```go
go a.store.UpdateSessionExpiry(sessionID, newExpiry)
go a.store.UpdateAPIKeyLastUsed(keyID)
```
Under high request volume, these can accumulate rapidly and overwhelm both the Go scheduler and the SQLite connection pool.

**Fix:** Use a bounded worker pool or at minimum a buffered channel with a fixed number of goroutines.

### 12. IPv6 Address Parsing Broken in IP Extraction
**Files:** `internal/auth/auth.go:871-879` (`getIPFromRequest`), `internal/security/security.go:14-18` (`GetClientIP` fallback), `internal/bot/challenge.go:244-249` (`NormalizeIP`)
All three functions strip ports using `strings.LastIndex(ip, ":")`, which breaks IPv6 addresses:
- `[::1]:8080` becomes `[::1` (missing bracket)
- `::1` becomes `:` or `::` depending on the last colon position

This corrupts client IPs used for rate limiting, audit logging, and bot detection. It also means IPv6-based rate limiting and IP block decisions are incorrect.

**Fix:** Use `net.SplitHostPort` for the RemoteAddr fallback in `security.go`. Update `getIPFromRequest` and `NormalizeIP` to handle IPv6 properly.

### 13. Admin Route Self-Reference Bypass
**File:** `internal/api/api.go:1250-1302` (`createRoute`)
`createRoute` decodes user-provided JSON directly into a `store.Route`. The `IsAdminRoute` field is not filtered out. An admin can set `"is_admin_route": true` in the JSON, which causes `ValidateNoSelfReference()` to skip the check, allowing a proxy loop to the admin API.

**Fix:** Explicitly set `route.IsAdminRoute = false` before validation for all user-created routes.

---

## High Issues

### 1. Request Body Silently Truncated by Admin WAF
**File:** `internal/api/api.go:252-259` (`adminInputValidation`)
```go
body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
r.Body = io.NopCloser(bytes.NewReader(body))
```
`io.LimitReader` silently truncates bodies larger than 1MB. The downstream handler receives the truncated body without any indication that data was lost. This corrupts large legitimate requests (e.g., bulk imports, large WAF rules).

**Fix:** Check if the read length equals the limit and return HTTP 413 if truncated.

### 2. Inefficient Route Lookup — O(n) Linear Scan
**File:** `internal/api/api.go:1320-1341` (`getRoute`)
The handler fetches **all** routes from the database and iterates linearly to find the one matching the ID. This is O(n) and scales poorly with route count. There is already a `GetAdminRoute()` method that uses `WHERE`; `getRoute` should have an equivalent.

**Fix:** Add `store.GetRouteByID(id)` and use it.

### 3. Health Check Misclassifies HTTP 400 as Healthy
**File:** `internal/proxy/health.go:166`
```go
if resp.StatusCode >= 200 && resp.StatusCode < 500 && resp.StatusCode != 404 {
    status.Healthy = true
```
HTTP 400 (Bad Request) and 499 (client closed) are considered "healthy". A backend that returns 400 on every request will be reported as up.

**Fix:** Narrow the healthy range to `200-399` plus `401/403` if explicitly desired.

### 4. WAF Instance Memory Leak on Reload
**File:** `internal/proxy/proxy.go:208-209` (`buildConfig` -> `ClearRouteWAFs`)
`ClearRouteWAFs()` deletes entries from the map but never calls any cleanup method on the old `*waf.WAF` instances. Coraza engines hold embedded rule sets and may retain memory/file descriptors. Frequent reloads (e.g., route changes, DNS revalidation) will accumulate unreachable WAF instances until GC runs, and even then underlying resources may not be freed promptly.

**Fix:** Add a `Close()` or cleanup method to the WAF type and call it before deleting from the map.

### 5. Cascading Config Reload in DNS Revalidation
**File:** `internal/proxy/proxy.go:660-669` (`revalidateAllRoutes`)
If multiple routes fail DNS revalidation in the same iteration, `p.Reload()` is called once **per failed route** inside the loop. Each reload clears and rebuilds all per-route WAF instances, causing redundant work and potential race conditions.

**Fix:** Collect all disabled route IDs, update them, and call `Reload()` once after the loop.

### 6. Session Cookie Secure Flag Mismatch on Logout
**File:** `internal/api/api.go:1555-1584` (`oauthLogout`)
The logout handler clears the session cookie with `Secure: true` unconditionally. However, `auth.go:1733` creates session cookies with `Secure: a.productionMode`. In non-production mode, the login cookie is `Secure: false`, but the logout cookie is `Secure: true`. Some browsers will not delete the original cookie because the flags don't match, leaving a "zombie" session cookie.

**Fix:** Use the same Secure flag logic as the login cookie.

### 7. `enable2FA` / `disable2FA` Ignore Session Invalidation Errors
**Files:** `internal/api/api.go:935`, `998`
Both endpoints call `a.auth.InvalidateUserSessions(dbUser.ID)` but ignore the error. If session invalidation fails, the user's existing sessions remain active even though their 2FA status changed.

**Fix:** Return the error to the caller or retry.

---

## Medium Issues

### 1. Bubble Sort Used for Session Limiting
**File:** `internal/auth/auth.go:1109-1170` (`enforceSessionLimitLocked`)
Uses a nested loop (bubble sort) to sort user sessions by creation time. For the default `maxConcurrentSessions = 5` this is harmless, but it is non-idiomatic and O(n^2).

**Fix:** Use `sort.Slice`.

### 2. Redundant Double Rate Limiting on Login
**File:** `internal/api/api.go:390`
The login endpoint is wrapped with `a.rateLimitMiddleware` individually, but the router already applies the same middleware globally via `r.Use(api.rateLimitMiddleware)`. The login check runs twice against the same limiter.

**Fix:** Remove the redundant per-route middleware.

### 3. Incorrect GitHub OIDC Discovery URL
**File:** `internal/oidc/oidc.go:68`
The hardcoded GitHub discovery URL is `https://token.actions.githubusercontent.com`, which is the **GitHub Actions** OIDC issuer, not GitHub OAuth/OIDC for user authentication. This will fail for anyone trying to use GitHub as an identity provider.

**Fix:** GitHub does not support standard OIDC discovery for OAuth apps. Remove the misleading fallback or implement GitHub's OAuth flow directly.

### 4. Ignored Write Errors in JSON Responses
**File:** `internal/api/api.go:529-543` (`respondJSON`)
`w.Write(body)` at line 538 ignores the error. While HTTP response write errors are often unrecoverable, they should still be logged or handled to detect client disconnects.

**Fix:** Check and optionally log the error.

### 5. Backup Import Swallows Errors
**File:** `internal/api/api.go:96-126` (`importBackup`)
Individual route creation errors during import are logged but not returned. The caller receives HTTP 200 "imported" even if no routes were actually imported.

**Fix:** Collect errors and return a partial-success response or fail the import.

---

## Positive Findings

- **Bcrypt with cost 12** is used for both passwords and API key secrets.
- **AES-GCM encryption** protects OIDC client secrets and TOTP secrets at rest.
- **HMAC-signed WAF verification headers** (`X-Kroxy-WAF-Verified`) prevent downstream bypass.
- **Session security** includes absolute lifetime limits, sliding window expiry, per-user mutexes for atomic creation, and invalidation on password/2FA changes.
- **DNS rebinding protection** with cached resolutions and periodic revalidation is well-implemented.
- **SSRF prevention** blocks private IPs, encoded IPs (hex/octal/decimal), and dangerous URL schemes.
- **Audit logging** includes HMAC signatures for tamper detection and optional webhook forwarding.
- **Context propagation** is used for database pings, health checks, and DNS resolution timeouts.
- **Structured rate limiting** with sliding windows protects login, API keys, admin tokens, and 2FA verification.
- **`defer rows.Close()`** and **`defer resp.Body.Close()`** are consistently used.
- **WAF fail-closed behavior** is correct: if the WAF engine is missing for a route, requests return 503 rather than passing through.
- **Secure HTTP headers** (CSP with nonces, HSTS, X-Frame-Options, Referrer-Policy) are set on all admin responses.
- **`sync.Once`** is used correctly for singleton initialization (encryption keys, WAF handler resolution).

---

## Summary

Kroxy is a security-conscious codebase with solid architecture around authentication, WAF, and audit logging. The critical issues center on **SQLite concurrency configuration**, **silent data loss from unhandled `rows.Err()`**, **cryptographic correctness in alert signatures**, **OIDC provider lifecycle management**, and **IPv6 address parsing correctness**. Addressing the SQLite pool and rows-error checks should be the immediate priority, as they directly impact production reliability and data integrity.
