# Wave 3: Structural Hardening — Remaining Fixes

**Branch:** `security-hardening-wave3`  
**Date:** 2026-05-20  
**Status:** Fixes 1–3 complete and committed. Fixes 4–6 pending.

## Completed

1. **Fix 1: sync.Map cleanup in auth** (`internal/auth/auth.go`, `internal/api/api.go`, `internal/bot/challenge.go`)
   - Extended `cleanupExpired()` to clean 7 previously leaking sync.Maps.
   - Added `cleanupStaleRateLimits()` to API rate limiter.
   - Triggered `nonceCleanup` goroutine in bot challenge manager.

2. **Fix 2: Session data race** (`internal/auth/auth.go`)
   - Replaced in-place mutation of `session.ExpiresAt` with a struct copy before `sync.Map.Store`.

3. **Fix 3: Bounded worker pools** (`internal/audit/audit.go`, `internal/alerts/alerts.go`, `internal/auth/auth.go`)
   - Audit: buffered channel (100) + single worker for webhook forwarding.
   - Alerts: semaphore (max 10 concurrent) for webhook sends.
   - Auth: buffered channel (100) + single worker for async DB updates.

## Remaining

### Fix 4: Admin IP Allowlist (Defense in Depth)
**Goal:** Restrict admin API access by source IP.

- Add `KROXY_ADMIN_ALLOWED_IPS` env var (comma-separated CIDRs, e.g. `192.168.0.0/24,10.0.0.1,127.0.0.1`).
- Create `adminIPAllowlistMiddleware` in `internal/api/api.go`:
  - Only applies to routes under `/api/` that require admin role.
  - Parses `security.GetClientIP(r)`.
  - Checks against configured allowlist.
  - If no allowlist configured, allow all (backward compatible).
  - If IP not in allowlist, return 403.
- Load the allowlist at startup from env, parse into `[]*net.IPNet`.

**Files:** `internal/api/api.go`, `cmd/kroxy/main.go`

---

### Fix 5: Bind Sessions to IP and User-Agent (Session Hijacking Mitigation)
**Goal:** Prevent stolen session cookies from working across browsers/networks.

1. Add fields to `store.Session` (`internal/store/models.go`):
   ```go
   ClientIP  string
   UserAgent string
   ```
   Update `CREATE TABLE sessions` migration if needed (add nullable columns).

2. Store IP/UA on session creation (`internal/auth/auth.go`):
   - Capture `ip` and `userAgent` when creating sessions.
   - Persist to database via `CreateSession`.

3. Validate IP/UA on session check (`internal/auth/auth.go:validateSession`):
   - Compare current request IP with stored IP (exact match or same /24).
   - Compare current User-Agent with stored UA (exact match — UA can be spoofed but adds friction).
   - On mismatch: invalidate session, return "session invalid".
   - Add env var `KROXY_STRICT_SESSION_BINDING=true` to opt-in (default false for backward compatibility).

4. Update store methods to read/write new columns.

**Files:** `internal/store/models.go`, `internal/store/store.go`, `internal/auth/auth.go`

---

### Fix 6: API DTOs for Sensitive Models (Information Disclosure)
**Goal:** Prevent API handlers from returning internal fields (backend URLs, cert paths, PII).

Create `internal/api/dto/*.go` with response types for:
- `RouteResponse` — omit `Backend`, `OIDCProviderID`, `IsAdminRoute`
- `CertificateResponse` — omit `CertPath`, `KeyPath`
- `WAFRuleResponse`
- `SecurityEventResponse` — mask `ClientIP`, `UserAgent` (PII)
- `UserResponse` — already hides `TOTPSecret`, but raw struct is leaky

Update handlers to build and return DTOs instead of raw `store.*` structs.

**Priority order:**
1. `listRoutes`, `getRoute`, `createRoute`, `updateRoute` (Backend URLs)
2. `listCertificates`, `createCertificate` (KeyPath)
3. `listSecurityEvents` (PII)
4. `listUsers`, `createUser`
5. Lower priority: `listBlacklists`, `listWhitelists`, `listRateLimits`, `listWAFRules`

**Files:** `internal/api/api.go`, new `internal/api/dto/*.go`

---

## Verification Gate (after all fixes)

```bash
# Build passes
go build ./...

# Tests pass (unit)
go test ./...

# Race detector clean
go test -race ./internal/auth/...

# gosec passes
gosec -exclude=G104,G307,G115 ./...

# No unbounded goroutines remain
grep -rn "go func()" internal/ | grep -v "_test.go"
```
