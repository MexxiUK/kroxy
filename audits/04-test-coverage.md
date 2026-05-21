# Kroxy Production-Readiness Test Audit Report

**Scope:** Test quality, coverage gaps, and test reliability

---

## Test Execution Results

| Command | Result | Notes |
|---|---|---|
| `go test ./...` | **PASS** | Unit tests pass (6 packages) |
| `go test -race ./...` | **PASS** | No race conditions detected |
| `go test -tags=integration ./internal/api/...` | **FAIL** | `TestSetup_FirstUser` fails |

**Integration test failure:** `TestSetup_FirstUser` expects HTTP 403 on a second `/api/setup` call, but the endpoint returns HTTP 429 (Too Many Requests) because rate limiting is applied before the "already set up" check. This is a genuine test/code bug.

---

## Test Coverage Summary by Package

| Package | Coverage | Test File(s) | Notes |
|---|---|---|---|
| `internal/security` | **78.9%** | `security_test.go` | Best coverage; IP extraction tested |
| `internal/auth` | **42.1%** | `auth_test.go` | Login, sessions, API keys, 2FA |
| `internal/store` | **35.1%** | `store_test.go` | CRUD for routes, users, sessions, keys |
| `internal/validation` | **36.5%** | `validation_test.go` | URL, domain, password, blacklist |
| `internal/crypto` | **33.8%** | `hmac_test.go` | *Only HMAC is tested; encryption.go has 0%* |
| `internal/waf` | **27.7%** | `waf_test.go` | CRS loading, SQLi/XSS blocking, PL2/PL3 |
| `internal/bot` | **27.2%** | `challenge_test.go` | Proof-of-work challenge |
| `internal/api` | **0.0%*** | `api_integration_test.go` | Integration tests only (build-tagged) |
| `cmd/kroxy` | **0.0%** | none | Main entry point (225 LOC) |
| `internal/proxy` | **0.0%** | none | **Entire proxy engine (1,389 LOC)** |
| `internal/config` | **0.0%** | none | Config loading and validation |
| `internal/alerts` | **0.0%** | none | Webhook alert manager (221 LOC) |
| `internal/audit` | **0.0%** | none | Audit logging with rotation (390 LOC) |
| `internal/metrics` | **0.0%** | none | Metrics handler |
| `internal/oidc` | **0.0%** | none | OIDC provider management (292 LOC) |
| `internal/totp` | **0.0%** | none | TOTP generation/validation (64 LOC) |
| `internal/testutil` | **0.0%** | none | Test helpers |
| `internal/version` | **0.0%** | none | Version string |
| `web` | **0.0%** | none | Frontend embed |

*\* `internal/api` coverage is 0% in standard test runs because tests require the `integration` build tag.*

---

## Critical Untested Paths (Security & Reliability)

### 1. Core Proxy Engine (`internal/proxy`) — COMPLETELY UNTESTED
The entire reverse proxy logic (1,389 lines) has zero tests. This includes:
- `buildConfig()` and `buildTLSConfig()` — generates Caddy JSON config
- `buildTLSApp()` — certificate automation, ACME, manual cert loading
- `WAFHandler.ServeHTTP()` — WAF middleware integration with Caddy
- `startDNSRevalidationWorker()` — DNS rebinding attack detection and auto-disable
- `startCertExpiryScanner()` and `parseCertExpiry()` — certificate monitoring
- `parseHeaders()` and `validateHeaders()` — custom header injection protection
- `HealthChecker.checkRoute()` — backend health monitoring
- `AccessLogStore.Log/Query/Stats()` — access logging

**Risk:** The most critical component of an HTTP proxy has no automated verification.

### 2. Encryption (`internal/crypto/encryption.go`) — UNTESTED
AES-GCM encryption/decryption for TOTP secrets and OIDC client secrets:
- `Encrypt()`, `Decrypt()`
- `GetEncryptionKey()`, `loadOrGenerateDevKey()`
- Dev key generation and file permissions (0600)

**Risk:** A regression in encryption could lock out all 2FA users or expose secrets.

### 3. TOTP (`internal/totp`) — UNTESTED
- `GenerateSecret()`, `ValidateCode()`, `ValidateCodeExact()`
- Constant-time comparison wrapper

**Risk:** 2FA is a security-critical path. Zero coverage is unacceptable for production.

### 4. OIDC (`internal/oidc`) — UNTESTED
- `InitializeProvider()`, OAuth2 flow, token verification
- Session management for OIDC users

### 5. Configuration (`internal/config`) — UNTESTED
Production-mode security validations:
- `KROXY_DB` must be absolute path in production
- `KROXY_ALLOW_PRIVATE_BACKENDS` blocked in production
- Admin must bind to localhost if TLS is disabled
- TLS certificate path validations

**Risk:** Misconfiguration could expose the admin API or allow SSRF in production.

### 6. Audit & Alerts (`internal/audit`, `internal/alerts`) — UNTESTED
- Audit log rotation, HMAC signing, webhook forwarding
- Alert cooldowns, threshold detection

---

## Flaky / Fragile Test Patterns Found

### 1. Broken Integration Test (`TestSetup_FirstUser`)
**File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/api/api_integration_test.go:122`

The test asserts `StatusCode == 403` for a duplicate setup call, but the API returns `429` because rate limiting is triggered. This makes the test suite fail consistently.

### 2. Expensive Brute-Force Loops in Bot Tests
**File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/bot/challenge_test.go`

`TestVerifyChallenge_Success`, `TestHandleVerify_NonceReplay`, and `TestHandleVerify_RateLimit` each brute-force a proof-of-work counter up to 5,000,000 iterations. These are computationally expensive and slow the suite.

### 3. Global State Manipulation in Crypto Tests
**File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/crypto/hmac_test.go`

Tests repeatedly set/unset `KROXY_WAF_SIGNING_KEY` and call `ResetSigningKeyForTest()` to reset a `sync.Once`. This pattern is fragile; if tests run in parallel or out of order, they could corrupt each other's state.

### 4. WAF Tests Depend on External Ruleset Behavior
**File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/waf/waf_test.go`

Tests include comments like "not blocked at PL1, expected, needs PL3" and "blocked (bonus)." This indicates tests are coupled to the specific version of the OWASP CRS ruleset. Upgrading Coraza or CRS could cause tests to fail or pass unexpectedly.

### 5. Environment Variable Timing Issue in Auth Helper
**File:** `/run/media/david-lee/SabrentRAID/Projects/kroxy/internal/auth/auth_test.go:37`

```go
func newTestAuth(t *testing.T) (*Auth, *store.Store, func()) {
    ...
    os.Setenv("KROXY_JWT_SECRET", "test-secret-test-secret-test-secret-test")
    defer os.Unsetenv("KROXY_JWT_SECRET")  // Runs when newTestAuth RETURNS, not when test ends
    a := New(s)
    return a, s, cleanupStore
}
```

The `defer` runs immediately upon return from `newTestAuth`, not when the test completes. It works because `New()` reads the env synchronously, but the pattern is misleading and brittle.

---

## Table-Driven Test Usage

| Package | Table-Driven? | Quality |
|---|---|---|
| `internal/validation` | Yes | Excellent; comprehensive cases for URL, domain, password, email |
| `internal/crypto/hmac` | Partial | Good invalid-format table, but most tests are individual |
| `internal/waf` | Partial | Good payload tables for SQLi/XSS/RCE/traversal |
| `internal/security` | No | Individual test functions; would benefit from tables |
| `internal/store` | No | Individual CRUD tests; would benefit from tables |
| `internal/auth` | No | Individual tests; repetitive setup code |
| `internal/bot` | No | Individual tests |

---

## Mocking Strategy

**No mocking framework is used.** All tests use real dependencies:
- SQLite temp-file databases for `store`, `auth`, and integration tests
- Real bcrypt hashing (slow but accurate)
- Real Coraza WAF engine with full CRS ruleset

This provides high integration confidence but makes tests slower. The auth package tests alone take ~1.5s, largely due to bcrypt.

---

## Benchmarks

Only **2 benchmarks** exist, both in `internal/waf`:
- `BenchmarkCreateWAFEngine`
- `BenchmarkWAFMiddleware`

**Missing benchmarks:**
- Auth login (bcrypt cost is 12 — expensive)
- API key validation (also bcrypt)
- WAF payload inspection
- Store queries
- Access log `Query` and `Stats`

---

## Recommendations for Minimum Viable Test Additions

### Priority 1 (Blockers)
1. **Fix `TestSetup_FirstUser`** — Either change expected status to 429 or adjust the API to check "already set up" before rate limiting.
2. **Add unit tests for `internal/proxy/buildConfig`** — Test JSON structure generation, TLS vs HTTP configs, handler ordering.
3. **Add unit tests for `internal/proxy/validateHeaders`** — Verify CRLF injection blocking.
4. **Add unit tests for `internal/crypto/encryption.go`** — Test round-trip encrypt/decrypt, empty input handling, invalid key sizes, dev key generation and file permissions.

### Priority 2 (Security-Critical)
5. **Add unit tests for `internal/totp`** — Test `GenerateSecret`, `ValidateCode` with known-good codes, skew boundaries, and `ValidateCodeExact`.
6. **Add unit tests for `internal/config`** — Test production-mode validation failures (relative DB path, non-localhost admin without TLS, private backends in production).
7. **Add unit tests for `internal/proxy/health.go`** — Test `checkRoute` with mocked HTTP responses (2xx, 404, 500, timeout).
8. **Add unit tests for `internal/proxy/accesslog.go`** — Test `LogStore.Query` filtering and `Stats` aggregation.

### Priority 3 (Reliability)
9. **Add benchmarks for auth Login and API key validation** — Document baseline performance for bcrypt operations.
10. **Reduce bot test brute-force cost** — Pre-compute a valid counter or cap the search space in tests.
11. **Add unit tests for `internal/alerts`** — Test webhook matching, cooldowns, signature generation.
12. **Add unit tests for `internal/audit`** — Test log rotation, HMAC signing, alert threshold triggering.

---

## Verdict: Does the Current Test Suite Give Confidence for Production?

**No.**

The current test suite is **insufficient for production deployment** for these reasons:

- **The core proxy engine (`internal/proxy`) is completely untested.** This is the most critical package in an HTTP proxy application.
- **Encryption and TOTP — both security-critical — have zero tests.** A regression here could disable 2FA for all users or expose stored secrets.
- **Configuration validation is untested.** Production security constraints (localhost binding, TLS requirements, absolute DB paths) are not verified.
- **One integration test is failing**, blocking CI if integration tests are enabled.
- **Only 6 of 19 packages have any coverage.** The overall effective coverage is likely well under 25%.

**What does work:**
- Race detector passes, indicating no obvious concurrency bugs in tested paths.
- The tested packages (`security`, `auth`, `validation`) show good attention to error cases and security edge cases.
- The WAF tests demonstrate the CRS ruleset is functional.

**Bottom line:** Before production, the proxy engine, encryption layer, and TOTP module must have unit tests. The failing integration test must be fixed.
