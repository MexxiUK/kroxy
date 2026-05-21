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

## Completed (All Fixes)

### Fix 4: Admin IP Allowlist (Defense in Depth)
- Added `KROXY_ADMIN_ALLOWED_IPS` env var support (comma-separated CIDRs and plain IPs).
- Created `adminIPAllowlistMiddleware` in `internal/api/api.go` applied to all admin routes.
- Parses `security.GetClientIP(r)`, returns 403 for non-allowed IPs.
- Backward compatible: no allowlist configured = allow all.

**Commit:** `16f4a15`

---

### Fix 5: Bind Sessions to IP and User-Agent (Session Hijacking Mitigation)
- Added `client_ip` and `user_agent` columns to `sessions` table via migration `012_session_ip_ua.up.sql`.
- Updated `store.Session` model and all store methods (`CreateSession`, `GetSession`, `GetSessionsByUser`).
- `auth.Login` and `auth.Verify2FA` now persist IP/UA when creating sessions.
- Added `KROXY_STRICT_SESSION_BINDING` opt-in check in `validateSession`:
  - Compares current IP with stored IP (exact match or same /24).
  - Compares User-Agent (exact match).
  - On mismatch: invalidates session and returns "session invalid".

**Commit:** `5c340b0`

---

### Fix 6: API DTOs for Sensitive Models (Information Disclosure)
- Created `internal/api/dto/dto.go` with safe response types:
  - `RouteResponse` — omits `Backend`, `OIDCProviderID`, `IsAdminRoute`
  - `CertificateResponse` — omits `CertPath`, `KeyPath`
  - `WAFRuleResponse`
  - `SecurityEventResponse` — masks `ClientIP` (last octet hidden), strips `UserAgent`
  - `UserResponse`, `BlacklistResponse`, `WhitelistResponse`, `RateLimitResponse`
- Updated all API handlers to return DTOs instead of raw `store.*` structs.
- Fixed dashboard stats to use masked IPs.
- All gosec G706 warnings resolved with sanitization.

**Commit:** `bd03bd3`

---

## Verification Gate (all passing)

```bash
# Build passes
go build ./...
# PASS

# Tests pass (unit)
go test ./...
# PASS (all packages)

# Race detector clean
go test -race ./internal/auth/...
# PASS

# gosec passes
gosec -exclude=G104,G307,G115 ./...
# PASS (0 issues)

# No unbounded goroutines remain
grep -rn "go func()" internal/ | grep -v "_test.go"
# Only expected background workers (cleanup, dbUpdateWorker, alertManager)
```
