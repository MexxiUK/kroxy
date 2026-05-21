# Kroxy Robustness Review — Codebase Justification &amp; Hardening Report

**Date:** 2026-05-19
**Auditors:** 4 parallel software architect agents (dead weight, simplicity, dependencies, concurrency)
**Scope:** Every line of code must justify its existence and its processing cost

---

## Executive Summary

Kroxy is a security-conscious Go HTTP proxy with solid fundamentals (bcrypt cost 12, AES-GCM, CSP nonces, parameterized SQL) but significant structural complexity that increases attack surface and maintenance burden. This report identifies dead code, unnecessary abstractions, over-engineered features, concurrency leaks, and dependency bloat — then proposes concrete simplifications that make the codebase more robust.

**Key themes:**
1. **Feature justification:** Several features exist for edge cases that are unlikely in production and add significant attack surface
2. **Concurrency hygiene:** Unbounded goroutine spawning, missing stop mechanisms, and resource leaks are pervasive
3. **Abstraction complexity:** Single-implementation interfaces, 10 `sync.Map` fields, and copy-paste CRUD boilerplate
4. **Dependency bloat:** 170+ transitive deps from Caddy, CGO from SQLite, dead-weight QR/barcode libraries
5. **Error handling:** Silent failures and ignored errors are systemic patterns, not isolated bugs

---

## Part 1: Dead Weight &amp; Unjustified Code

### Functions, Types, and Files That Should Be Removed

| # | File | What | Why Unjustified | Action |
|---|------|------|---------------|--------|
| 1 | `internal/bot/globals.go:82-86` | `HexSecret()` | Exported function that leaks the active bot HMAC key with no access control. No legitimate production use. | **Delete** or gate behind `//go:build debug` |
| 2 | `internal/bot/globals.go:29-35` | Auto-generated 16-byte bot secret fallback | Too short for HMAC (should be 32 bytes). Invalidates bypass cookies on every restart if env var is unset. | **Fail startup** if `KROXY_BOT_SECRET` is unset in production |
| 3 | `internal/api/backup.go` | `exportBackup` and `importBackup` | Exports sensitive data (custom headers with auth tokens, cert key paths) with no HMAC verification. Import is partial and skips validation. High attack surface for data exfiltration. | **Gate behind `KROXY_ENABLE_BACKUP_RESTORE=true`** or **delete** |
| 4 | `internal/api/api.go:282` | `X-XSS-Protection` header | Deprecated, removed from Chromium, historically introduced Safari vulnerabilities. Zero security benefit. | **Delete one line** |
| 5 | `internal/auth/auth.go:147,236-259` | `jwtSecret` field and `LoadJWTSecret()` | Field is set but never referenced anywhere in the codebase. Dead code since inception. | **Delete** |
| 6 | `internal/oidc/oidc.go:68` | GitHub OIDC discovery fallback | Hardcodes `https://token.actions.githubusercontent.com`, which is the GitHub Actions issuer, not user OIDC. Will always fail. | **Delete** the misleading fallback |
| 7 | `internal/api/api.go:56-143` | Custom sliding-window `RateLimiter` | 87 lines of floating-point window arithmetic when `golang.org/x/time/rate` (already in transitive deps via Caddy) provides a battle-tested token bucket in 10 lines. | **Replace** with `x/time/rate` |
| 8 | `internal/store/store.go` | 16 nearly identical query methods | Each repeats `Query` → `rows.Next()` → `Scan` → `Append`. No generic helper exists. | **Replace** with one `queryAll[T]` helper (~200 LOC saved) |
| 9 | `internal/store/store.go` | Single-field updaters: `UpdateCertificateExpiry`, `UpdateCertificateStatus`, `UpdateUserPassword`, `UpdateUserRole`, `UpdateUserEnabled`, `UpdateSessionExpiry`, `UpdateAPIKeyLastUsed` | Ultra-fine-grained updates that could be collapsed into one `UpdateX(id, fields)` or full-struct updates. | **Collapse** into generic updates (~100 LOC saved) |
| 10 | `internal/proxy/proxy.go:31-83` | Global WAF registry (`routeWAFs`, `globalWAF`, `routeWAFsMu` + 6 accessors) | Package-level mutable state that is essentially a manual service locator. Could be fields on `Proxy` struct. | **Inline into `Proxy`** (~50 LOC saved) |
| 11 | `internal/waf/waf.go:812-856` | 5 WAF test struct types | `TestResult`, `TestCategory`, `TestSuiteResult`, `TestSummary`, `TestPayloadResult` — excessive granularity for JSON API responses. | **Collapse to 2 types** (~30 LOC saved) |
| 12 | `cmd/kroxy/main.go:87-106` | Manual webhook hydration loop | Copies every field from `store.Webhook` to `alerts.Webhook` because types are identical but redefined. | **Use type alias** or shared DTO (~15 LOC saved) |
| 13 | `internal/validation/validation.go:44-51` | 6-regex `wafDisablePatterns` | Simple literal substring checks (`strings.Contains`) suffice for detecting `SecRuleEngine off`. Regex compilation is expensive and unnecessary. | **Replace with `strings.Contains`** (~15 LOC saved) |
| 14 | `internal/auth/auth.go:1109-1170` | Hand-rolled bubble sort | `enforceSessionLimitLocked` implements O(n²) sorting when `sort.Slice` is available. | **Replace with `sort.Slice`** (~8 LOC saved) |
| 15 | `internal/auth/auth.go:553,596,728` | Fire-and-forget goroutines | `go a.store.UpdateSessionExpiry(...)`, `go a.store.UpdateAPIKeyLastUsed(...)`. Spawn unlimited goroutines with no error handling or shutdown. | **Replace with synchronous writes or bounded worker pool** |
| 16 | `internal/audit/audit.go:213` | `go l.forwardToWebhook(data)` | Unbounded goroutine per audit event. | **Use worker pool** |
| 17 | `internal/alerts/alerts.go:80` | `go m.sendWebhook(wh, event)` | Unbounded goroutine per webhook per alert event. | **Use worker pool** |

### Total Potential LOC Reduction

| Category | Estimated LOC Saved |
|----------|-------------------|
| Generic query helper (16 methods) | ~200 |
| Single-field updater collapse | ~100 |
| Global WAF registry inline | ~50 |
| WAF test struct collapse | ~30 |
| Webhook hydration loop | ~15 |
| Regex → strings.Contains | ~15 |
| Bubble sort → sort.Slice | ~8 |
| `jwtSecret` dead code | ~25 |
| `HexSecret` removal | ~5 |
| GitHub OIDC fallback | ~3 |
| `X-XSS-Protection` header | ~1 |
| Custom RateLimiter → x/time/rate | ~60 |
| **Total** | **~512 LOC** |

---

## Part 2: Architectural Simplifications

### 1. Collapse auth's 10 `sync.Map` fields into SQLite-backed lookups

**Current:** `Auth` holds 10 `sync.Map` fields (`sessions`, `apiKeys`, `stateStore`, `adminTokens`, `failedAttempts`, `roleCache`, `adminTokenAttempts`, `apiKeyAttempts`, `pending2FA`, `twoFARateLimits`) plus a `*distributedAttackTracker`. Every access requires `LoadOrStore` + type assertion.

**Problem:** Triple-layer locking, cache invalidation bugs, and race-surface expansion. Most of these have durable SQLite backing.

**Solution:** Keep only `sessions` in memory (for hot-path performance). Move `failedAttempts`, `roleCache`, `adminTokenAttempts`, `apiKeyAttempts`, `twoFARateLimits`, and `pending2FA` to SQLite queries or simple in-memory maps with TTL eviction. Replace `sync.Map` with `map[string]any` + `sync.RWMutex` for the remaining in-memory caches.

**Impact:** -250 to -350 lines, fewer race conditions, simpler reasoning.

### 2. Eliminate Fire-and-Forget Goroutines for DB Writes

**Current:** `go a.store.UpdateSessionExpiry(...)`, `go a.store.UpdateAPIKeyLastUsed(...)`, `go l.forwardToWebhook(data)`, `go m.sendWebhook(wh, event)`.

**Problem:** Unbounded goroutine growth under load. Silent failures. Complicates shutdown.

**Solution:** Make DB writes synchronous (SQLite is local, sub-millisecond for single-row updates). For webhooks, use a buffered channel + fixed worker pool (e.g., 4-8 goroutines). Drop events when queue is full rather than spawning new goroutines.

**Impact:** Eliminates entire class of resource exhaustion DoS.

### 3. Replace Per-Route WAF Engine Creation with One Global Engine + Rule Overlays

**Current:** On every config reload, `buildConfig()` calls `waf.New()` for every route, re-parsing the entire OWASP CRS rule set (27 files) via Coraza.

**Problem:** Heavyweight duplication. Memory leak on reload. O(n) with route count.

**Solution:** Create **one global WAF engine** with base CRS rules. Per-route customization should inject only route-specific rules/exclusions into that single engine, or use Coraza's native rule exclusion APIs. Cache and reuse engines keyed by `(paranoiaLevel, mode, customRulesHash)`.

**Impact:** Cuts config reload CPU/memory by orders of magnitude. Eliminates global WAF registry.

### 4. Split `internal/api/api.go` (3489 lines, 78 handlers) into logical files

**Current:** One god-object file containing every CRUD handler.

**Problem:** Merge conflicts, unreadable diffs, no clear ownership.

**Solution:** Split by domain: `routes.go`, `users.go`, `certificates.go`, `waf.go`, `oidc.go`, `settings.go`, `webhooks.go`, `auth_handlers.go`. Extract common patterns (decode JSON → validate → store → audit → respond) into shared helpers.

**Impact:** Zero LOC change, massive maintainability improvement.

### 5. Replace Custom Sliding-Window Rate Limiter with `golang.org/x/time/rate`

**Current:** 87 lines of float arithmetic for weighted sliding windows.

**Problem:** Already in transitive deps via Caddy. Custom implementation is error-prone.

**Solution:** Replace with `rate.NewLimiter(rate.Every(time.Minute/10), 10)` for a simple per-minute limit.

**Impact:** -60 lines, battle-tested correctness.

### 6. Use Typed Structs for Caddy Config Instead of `map[string]interface{}`

**Current:** `buildConfig()` and `buildTLSConfig()` construct Caddy JSON via deeply nested untyped maps.

**Problem:** No compile-time safety. Errors surface only at JSON-parse time inside Caddy.

**Solution:** Define small typed structs (`caddyServer`, `caddyRoute`, `caddyTLSApp`) matching the Caddy subset used. Marshal the root struct.

**Impact:** Net neutral LOC, huge maintainability and type-safety win.

### 7. Consolidate Session Types

**Current:** Three separate `Session` structs (`auth.Session`, `store.Session`, `oidc.Session`) with 80% field overlap and manual conversion code.

**Problem:** Type duplication, conversion bugs.

**Solution:** Define one canonical `store.Session`. `auth` and `oidc` add only domain-specific fields via embedding or wrapper structs.

**Impact:** -60 lines.

### 8. Replace `map[string]interface{}` in Audit/Alert Details with `json.RawMessage` or Typed Structs

**Current:** `audit.Event.Details interface{}` and `alerts.Event.Details map[string]interface{}` allow any shape.

**Problem:** No static analysis possible. Callers construct maps inline.

**Solution:** Use `json.RawMessage` for deferred parsing, or define small typed detail structs for each event type (`AuthFailureDetails`, `WAFBlockDetails`).

**Impact:** Net neutral LOC, type-safety improvement.

---

## Part 3: Dependency Simplification

### Direct Dependency Review

| Dependency | Current Use | Replaceable? | Action |
|-----------|-------------|--------------|--------|
| `github.com/caddyserver/caddy/v2` | Reverse proxy, TLS, ACME | No (core architecture) | **Keep**, but audit if all features (HTTP/3, on-demand TLS) are needed |
| `github.com/corazawaf/coraza/v3` | WAF engine | No (core feature) | **Keep**, monitor `gjson` and `aho-corasick` advisories |
| `github.com/corazawaf/coraza-coreruleset/v4` | WAF rules | No (data-only) | **Keep** |
| `github.com/coreos/go-oidc/v3` | OIDC discovery, JWT verification | No (complex, error-prone) | **Keep**, ensure `go-jose/v4` paths are used |
| `github.com/go-chi/chi/v5` | Admin API router | Partially (Go 1.22 ServeMux) | **Keep or defer** — zero transitive deps, low ROI |
| `github.com/mattn/go-sqlite3` | SQLite driver | **Yes** — `modernc.org/sqlite` (pure Go) | **Replace** — eliminates CGO |
| `github.com/pquerna/otp` | TOTP generation | **Yes** — stdlib `crypto/hmac` + `encoding/base32` | **Replace** — ~80 lines, removes dead `barcode` dep |
| `golang.org/x/crypto` | bcrypt | No | **Keep** |
| `golang.org/x/oauth2` | OAuth2 in OIDC flow | Effectively unavoidable | **Keep** (transitive via `go-oidc`) |

### Supply Chain Risks

- **`go-jose/go-jose/v3`** — CVE-2024-28180. Still present in transitive graph.
- **`github.com/tidwall/gjson`** — Historical panic/DoS on malformed JSON.
- **`github.com/quic-go/quic-go`** — Experimental, frequent breaking changes.
- **`google.golang.org/grpc`** — Periodic CVEs in large surface area.
- **`github.com/mattn/go-sqlite3`** — Sole CGO dependency. Breaks pure-Go cross-compilation.
- **`github.com/boombuler/barcode`** — Dead weight (pulled in by `pquerna/otp` for QR images Kroxy doesn't use).

### Minimum Viable Dependency Set

If aggressively trimmed (replacing `go-sqlite3`, `pquerna/otp`, optionally `go-chi/chi`):

```go
module github.com/kroxy/kroxy

go 1.25.9

require (
    github.com/caddyserver/caddy/v2 v2.11.2
    github.com/corazawaf/coraza-coreruleset/v4 v4.24.1
    github.com/corazawaf/coraza/v3 v3.5.0
    github.com/coreos/go-oidc/v3 v3.17.0
    golang.org/x/crypto v0.49.0
    modernc.org/sqlite v1.36.0 // pure Go, CGO-free
)
```

---

## Part 4: Concurrency &amp; Resource Robustness

### Critical Issues

| # | File | Issue | Impact |
|---|------|-------|--------|
| 1 | `internal/audit/audit.go:213` | `go l.forwardToWebhook(data)` — unbounded goroutine per audit event | Goroutine leak, memory exhaustion |
| 2 | `internal/alerts/alerts.go:80` | `go m.sendWebhook(wh, event)` — unbounded goroutine per webhook per alert | Same as above |
| 3 | `internal/auth/auth.go:271` | `go a.startCleanup()` — no stop mechanism, no `Auth.Close()` | Goroutine leak on every re-init |
| 4 | `internal/auth/auth.go:553,596` | `go a.store.UpdateSessionExpiry(...)` — unbounded per auth request | SQLite lock contention, scheduler overwhelm |
| 5 | `internal/auth/auth.go:728` | `go a.store.UpdateAPIKeyLastUsed(...)` — unbounded per API key request | Same as above |
| 6 | `internal/proxy/proxy.go:170,173` | `go p.startDNSRevalidationWorker()` / `go p.startCertExpiryScanner()` — context cancellation is async, duplicate workers possible during restart | Brief duplicate workers |
| 7 | `internal/proxy/proxy.go:209` | `ClearRouteWAFs()` deletes map entries but doesn't close/destroy WAF engines | Memory leak on every config reload |
| 8 | `cmd/kroxy/main.go:221` | `server.Shutdown(ctx)` uses already-cancelled context from `px.Stop()` | Shutdown may return immediately without draining connections |
| 9 | `internal/api/api.go:74-143` | `RateLimiter` uses `sync.Map` where keys (IPs) are never deleted | Unbounded memory growth |
| 10 | `internal/bot/detector.go:172` | `go c.cleanupLoop()` — no stop mechanism | Goroutine leak on multiple cache instances |
| 11 | `internal/alerts/alerts.go:20` | `cooldowns` map grows forever; expired entries never removed | Unbounded memory growth |
| 12 | `internal/audit/audit.go:280` | `AlertHandler.failedLogins` and `wafBlocks` maps grow forever | Memory leak under sustained attack |

### Goroutine Lifecycle Audit

| Goroutine | Spawned At | Shutdown Guaranteed? | Max Concurrent |
|-----------|-----------|----------------------|----------------|
| API server listener | `cmd/kroxy/main.go:195` | Yes (but ctx pre-cancelled) | 1 |
| DNS revalidation worker | `internal/proxy/proxy.go:170` | Yes, but races with restart | 1 |
| Cert expiry scanner | `internal/proxy/proxy.go:173` | Yes, but races with restart | 1 |
| Health checker ticker | `internal/proxy/health.go:74` | Yes | 1 |
| Health check route workers | `internal/proxy/health.go:129` | Yes | N routes |
| Auth cleanup ticker | `internal/auth/auth.go:271` | **No** | 1 |
| Audit webhook forwarder | `internal/audit/audit.go:213` | **No** | Unbounded |
| Alert webhook sender | `internal/alerts/alerts.go:80` | **No** | Unbounded |
| Session expiry updater | `internal/auth/auth.go:553,596` | **No** | Unbounded |
| API key last-used updater | `internal/auth/auth.go:728` | **No** | Unbounded |
| Bot challenge cache cleanup | `internal/bot/detector.go:198` | **No** | 1 |

### Memory &amp; Allocation Hot Paths

| Location | Issue | Fix |
|----------|-------|-----|
| `internal/audit/audit.go:169-186` | Double `json.Marshal` per log event | Marshal once into `map[string]interface{}`, sign raw bytes, then write |
| `internal/audit/audit.go:201-206` | `strings.ReplaceAll` chain creates 5 intermediate string copies | Use single `strings.NewReplacer` or `bytes.Buffer` |
| `internal/proxy/accesslog.go:65-68` | Slice truncation allocates new backing array on every overflow | Use ring buffer with head/tail indices |
| `internal/auth/auth.go:1155-1160` | Bubble sort O(n²) | Replace with `sort.Slice` |
| `internal/store/store.go` | Result slices not pre-sized | Pre-size with `make([]Type, 0, expectedCount)` |

### Shutdown Robustness

**Does graceful shutdown wait for all goroutines?** Partially.
- `px.Stop()` cancels proxy context and waits for health checker.
- DNS/cert workers, auth cleanup, bot cache cleanup, and fire-and-forget goroutines are **not** waited for.
- `server.Shutdown(ctx)` uses an already-cancelled context.
- `Auth`, `alerts.NewManager()`, and `audit.Init()` have no `Close/Stop` methods.

**Fixes needed:**
1. Add `Stop()` to `Auth` with cancel func for cleanup ticker
2. Replace fire-and-forget goroutines with bounded worker pools that have `Close()` methods
3. Create a fresh timeout context for `server.Shutdown()`
4. Close HTTP clients (`alerts.Manager.client`, `audit.Logger.webhookClient`, `HealthChecker.client`)
5. Add TTL eviction to rate limiter and cooldown maps

---

## Part 5: Defense-in-Depth Layers to Add

| Layer | What It Protects Against | How to Implement |
|-------|------------------------|----------------|
| **SQLite Pool Enforcement** | `database is locked`, data corruption | `db.SetMaxOpenConns(1)`, `SetMaxIdleConns(1)`, `SetConnMaxLifetime(30m)`. Enable WAL mode. |
| **Response Body Truncation Detection** | Silent data corruption | In `adminInputValidation`, after `io.ReadAll(io.LimitReader(..., 1<<20))`, check `len(body) == 1<<20` and return HTTP 413. |
| **Webhook URL SSRF Validation** | SSRF via malicious webhook URLs | Validate `wh.URL` with `validation.ValidateBackendURL` before dispatch. |
| **WAF Fail-Closed** | WAF bypass when Coraza fails | In `internal/waf/waf.go`, do not ignore `ProcessRequestBody` error; return blocked/503 if non-nil. |
| **Session Binding Enforcement** | Session hijacking via stolen cookies | In `validateSession`, compare stored `IP` and `UserAgent` against request. |
| **Shutdown Error Capture** | Data loss on abrupt exit | Capture errors from `px.Stop()`, `server.Shutdown()`, `logStore.Close()`, wait for worker pool drain. |
| **Alert Signature HMAC** | Length-extension attacks | Replace `sha256.New()` with `hmac.New(sha256.New, []byte(secret))` in `internal/alerts/alerts.go:144-150`. |
| **Admin Token Bcrypt Hashing** | Offline brute-force | Replace `sha256Sum` with `bcrypt.GenerateFromPassword` in `internal/auth/auth.go:1414-1416`. |
| **Admin IP Allowlist** | Unauthorized admin access from unexpected networks | Add `KROXY_ADMIN_ALLOWLIST` (CIDR list). Default to `127.0.0.1/32` in production. |
| **Bounded Worker Pools** | Goroutine exhaustion DoS | Replace all `go func()` background work with buffered channel + fixed workers. |

---

## Part 6: Recommended Action Sequence

### Phase 1: Quick Wins (1-2 days)
1. **Add `.dockerignore`** (5 min)
2. **Fix systemd env var** `KROXY_LISTEN` → `KROXY_PROXY` (1 min)
3. **Fix Docker Compose health check** `/api/status` → `/ready` (1 min)
4. **Remove `X-XSS-Protection` header** (delete 1 line)
5. **Delete `HexSecret()`** or gate behind debug build tag
6. **Delete GitHub OIDC discovery fallback** (delete ~3 lines)
7. **Delete `jwtSecret` dead code** (delete ~25 lines)
8. **Replace bubble sort with `sort.Slice`** (swap 8 lines)
9. **Fix `TestSetup_FirstUser`** — change expected status or reorder checks (1 line)

### Phase 2: Critical Reliability (2-3 days)
10. **Add `db.SetMaxOpenConns(1)` and WAL mode** in `store.New()`
11. **Fix all 16 `rows.Err()` checks** — move from inside to after `for rows.Next()` loops
12. **Remove plaintext fallbacks** for TOTP/OIDC secrets — fail closed on decrypt error
13. **Replace webhook signature** with proper HMAC-SHA256
14. **Fix shutdown context** in `main.go` — use fresh timeout context
15. **Add `Stop()` methods** to `Auth`, `alerts.Manager`, `audit.Init`

### Phase 3: Attack Surface Reduction (3-5 days)
16. **Create API DTOs** for webhooks (omit `Secret` field)
17. **Gate or remove backup/restore** behind `KROXY_ENABLE_BACKUP_RESTORE`
18. **Add webhook URL SSRF validation**
19. **Add admin IP allowlist**
20. **Bind sessions to IP/User-Agent**
21. **Replace admin token SHA256 with bcrypt**

### Phase 4: Architectural Simplification (1-2 weeks)
22. **Collapse auth's 10 `sync.Map` fields** into SQLite-backed lookups
23. **Eliminate fire-and-forget goroutines** — synchronous DB writes or bounded worker pools
24. **Replace per-route WAF engines** with one global engine + rule overlays
25. **Split `api.go`** into logical domain files
26. **Replace custom rate limiter** with `golang.org/x/time/rate`
27. **Use typed structs** for Caddy config instead of `map[string]interface{}`
28. **Consolidate session types** (`auth.Session`, `store.Session`, `oidc.Session`)

### Phase 5: Dependency Hardening (1-2 days)
29. **Replace `github.com/mattn/go-sqlite3`** with `modernc.org/sqlite` (pure Go, no CGO)
30. **Replace `github.com/pquerna/otp`** with stdlib TOTP implementation (~80 lines)
31. **Evaluate Caddy necessity** — are HTTP/3 and on-demand TLS strictly required?
32. **Pin CI action versions** to commit SHAs, remove `|| true` from `gosec`

---

## Summary

Kroxy has a solid security foundation but is over-engineered in several areas. The most impactful changes are:

1. **Eliminate unbounded goroutines** — this is a production reliability and DoS prevention imperative
2. **Collapse auth's `sync.Map` explosion** — simplifies reasoning and removes cache invalidation bugs
3. **Replace per-route WAF engines** — massive performance and memory win on config reload
4. **Remove dead code** (`jwtSecret`, `HexSecret`, GitHub OIDC fallback, `X-XSS-Protection`)
5. **Replace CGO SQLite with pure Go** — eliminates C toolchain dependency and cross-compilation pain

Estimated total effort: **2-3 weeks** for all phases. Quick wins alone (Phase 1) can be done in hours and immediately improve security posture.
