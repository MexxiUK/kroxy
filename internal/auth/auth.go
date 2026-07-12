package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kroxy/kroxy/internal/crypto"
	"github.com/kroxy/kroxy/internal/security"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/totp"
	"github.com/kroxy/kroxy/internal/validation"
	"golang.org/x/crypto/bcrypt"
)

const (
	// bcryptCost is the cost parameter for bcrypt hashing.
	// 12 is recommended for modern systems (higher than DefaultCost of 10)
	bcryptCost = 12

	// apiKeyHMACPrefix marks API key HMAC values that use the domain-separated
	// derivation instead of the raw encryption key (legacy).
	apiKeyHMACPrefix = "v2:"

	// maxFailedAttempts is the number of failed login attempts before account lockout
	maxFailedAttempts = 3

	// lockoutDuration is how long an account is locked after too many failed attempts
	lockoutDuration = 15 * time.Minute

	// maxConcurrentSessions is the maximum number of concurrent sessions per user
	maxConcurrentSessions = 5

	// roleCacheTTL is how long cached roles are valid before refresh
	// Kept short (30s) to minimize the window where a demoted user retains access
	roleCacheTTL = 30 * time.Second

	// maxSessionAbsoluteLifetime is the maximum time a session can exist
	// regardless of activity. This prevents session hijacking from lasting indefinitely.
	// 7 days is a reasonable balance between security and user convenience.
	maxSessionAbsoluteLifetime = 7 * 24 * time.Hour
)

// dummyPasswordHash is a pre-computed bcrypt hash used for timing-safe
// comparison when a user does not exist. Running bcrypt.CompareHashAndPassword
// against this dummy hash ensures the login function takes roughly the same
// time regardless of whether the email exists, preventing timing-based
// account enumeration.
var dummyPasswordHash = func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy-password-hash-for-timing"), bcryptCost)
	return h
}()

// failedAttempt tracks failed login attempts for account lockout
type failedAttempt struct {
	mu          sync.Mutex
	count       int
	firstFail   time.Time
	lockedUntil *time.Time
}

// roleCacheEntry caches a user's role with expiration
type roleCacheEntry struct {
	role     string
	cachedAt time.Time
}

// apiKeyAttempt tracks API key validation failures per IP to prevent bcrypt DoS (CRIT-004)
type apiKeyAttempt struct {
	mu        sync.Mutex
	count     int
	firstFail time.Time
}

// distributedAttackTracker tracks credential stuffing attacks (same IP, multiple accounts)
type distributedAttackTracker struct {
	mu          sync.Mutex
	ipAttempts  map[string]*ipAttackStats // IP -> attack stats
	windowStart time.Time
}

// ipAttackStats tracks account enumeration from a single IP
type ipAttackStats struct {
	uniqueAccounts map[string]time.Time // email -> first attempt time
	firstAttempt   time.Time
	lastAttempt    time.Time
	blocked        bool
	blockedUntil   time.Time
}

const (
	// distributedAttackThreshold is the number of unique accounts attempted from same IP
	// before triggering a distributed attack alert
	distributedAttackThreshold = 5
	// distributedAttackWindow is the time window for counting unique account attempts
	distributedAttackWindow = 15 * time.Minute
	// distributedAttackBanDuration is how long to block an IP after detected attack
	distributedAttackBanDuration = 1 * time.Hour
)

// pending2FASession tracks a session awaiting 2FA verification
type pending2FASession struct {
	mu        sync.Mutex
	userID    int
	email     string
	name      string
	role      string
	ip        string
	userAgent string
	createdAt time.Time
	expiresAt time.Time
	attempts  int
}

// Auth provides authentication middleware for the Admin API
type Auth struct {
	store             *store.Store
	sessions          sync.Map                  // sessionID -> *Session
	apiKeys           sync.Map                  // keyID -> *APIKey
	stateStore        sync.Map                  // state -> *StateInfo
	failedAttempts    sync.Map                  // email -> *failedAttempt
	roleCache         sync.Map                  // userID (int) -> *roleCacheEntry
	sessionMu         sync.Map                  // userID (int) -> *sync.Mutex (for atomic session operations)
	apiKeyAttempts    sync.Map                  // IP -> *apiKeyAttempt     // Track failed API key attempts (bcrypt DoS protection)
	distributedAttack *distributedAttackTracker // Credential stuffing detection
	pending2FA        sync.Map                  // pendingID -> *pending2FASession
	twoFARateLimits   sync.Map                  // userID (int) -> *twoFARateLimit
	jwtSecret         []byte
	sessionExpiry     time.Duration
	productionMode    bool        // When false, cookies don't require HTTPS
	dbUpdateCh        chan func() // Background worker for async DB writes
	dbUpdateOnce      sync.Once   // Ensures worker starts once
}

// twoFARateLimit tracks 2FA verification attempts per user to prevent brute-forcing
// across multiple pending sessions.
type twoFARateLimit struct {
	mu           sync.Mutex
	attempts     int
	firstFail    time.Time
	locked       bool
	lockedUntil  *time.Time
	lockoutCount int // number of consecutive lockouts (escalates penalties)
}

// Session represents an authenticated admin session
type Session struct {
	ID             string
	UserID         int
	Email          string
	Name           string
	Role           string
	ProviderName   string // "local", "local_totp", "google", "github", etc.
	CreatedAt      time.Time
	ExpiresAt      time.Time // Sliding window expiration
	AbsoluteExpiry time.Time // Hard maximum lifetime
	IP             string
	UserAgent      string
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID            int
	KeyID         string
	KeySecretHash string // bcrypt hashed secret
	KeySecretHMAC string // fast HMAC pre-check before bcrypt
	UserID        int
	Role          string // User's role at time of key creation
	Name          string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	LastUsed      *time.Time
}

// StateInfo stores OAuth state parameters for CSRF protection
type StateInfo struct {
	State          string
	ProviderID     int
	RedirectURL    string
	SessionBinding string // Hash of session cookie to prevent state token theft
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	SessionID        string `json:"session_id"`
	ExpiresAt        int64  `json:"expires_at"`
	User             User   `json:"user,omitempty"`
	Requires2FA      bool   `json:"requires_2fa,omitempty"`
	Setup2FARequired bool   `json:"setup_2fa_required,omitempty"`
	PendingID        string `json:"pending_id,omitempty"`
}

// User represents a user in API responses (without sensitive data)
type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// New creates a new Auth instance
func New(s *store.Store) *Auth {
	// Check if running in production mode
	productionMode := os.Getenv("KROXY_PRODUCTION") == "true"

	// Allow JWT secret to be configured via environment variable for multi-instance deployments
	jwtSecret := os.Getenv("KROXY_JWT_SECRET")
	if jwtSecret == "" {
		if productionMode {
			// In production mode, JWT secret is required
			log.Fatal("KROXY_JWT_SECRET must be set in production mode. Generate a secret with: openssl rand -base64 32")
		}
		jwtSecret = generateSecret(32)
		// Warn about auto-generated JWT secret (not suitable for multi-instance deployments)
		log.Println("WARNING: KROXY_JWT_SECRET not set. Using auto-generated secret.")
		log.Println("WARNING: Sessions will be invalidated on restart. Set KROXY_JWT_SECRET for multi-instance deployments.")
	}

	// Validate JWT secret length (minimum 32 bytes for security)
	if len(jwtSecret) < 32 {
		if productionMode {
			log.Fatal("KROXY_JWT_SECRET must be at least 32 characters. Generate a secret with: openssl rand -base64 32")
		}
		log.Printf("WARNING: KROXY_JWT_SECRET is only %d characters. Recommended minimum is 32 characters.", len(jwtSecret)) // #nosec G706 — %d prints an integer length, not user input
	}

	// Load session duration from settings, falling back to 24 hours.
	sessionExpiry := 24 * time.Hour
	if s != nil {
		if d := s.GetSettingDefault("session_duration", ""); d != "" {
			if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
				sessionExpiry = parsed
			} else if err != nil {
				log.Printf("WARNING: invalid session_duration setting %q, using default 24h: %v", d, err)
			}
		}
	}

	a := &Auth{
		store:          s,
		sessionExpiry:  sessionExpiry,
		jwtSecret:      []byte(jwtSecret),
		productionMode: productionMode,
		dbUpdateCh:     make(chan func(), 100),
		distributedAttack: &distributedAttackTracker{
			ipAttempts:  make(map[string]*ipAttackStats),
			windowStart: time.Now(),
		},
	}

	// Restore sessions from database
	a.restoreSessions()

	// Start background cleanup goroutine
	go a.startCleanup()

	return a
}

// startCleanup periodically removes expired entries from memory
func (a *Auth) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		a.cleanupExpired()
	}
}

// enqueueDBUpdate schedules an async database write. Drops if buffer is full.
func (a *Auth) enqueueDBUpdate(fn func()) {
	a.dbUpdateOnce.Do(func() {
		go a.dbUpdateWorker()
	})
	select {
	case a.dbUpdateCh <- fn:
	default:
		log.Println("auth: DB update buffer full, dropping async write")
	}
}

func (a *Auth) dbUpdateWorker() {
	for fn := range a.dbUpdateCh {
		fn()
	}
}

// cleanupExpired removes expired entries from all sync.Maps
func (a *Auth) cleanupExpired() {
	now := time.Now()

	// Cleanup expired sessions
	a.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*Session); ok {
			if now.After(session.ExpiresAt) {
				a.sessions.Delete(key)
			}
		}
		return true
	})

	// Cleanup expired OAuth states (10-minute expiry)
	a.stateStore.Range(func(key, value interface{}) bool {
		if stateInfo, ok := value.(*StateInfo); ok {
			if now.After(stateInfo.ExpiresAt) {
				a.stateStore.Delete(key)
			}
		}
		return true
	})

	// Cleanup expired pending 2FA sessions (5-minute expiry)
	a.pending2FA.Range(func(key, value interface{}) bool {
		if pending, ok := value.(*pending2FASession); ok {
			if now.After(pending.expiresAt) {
				a.pending2FA.Delete(key)
			}
		}
		return true
	})

	// Cleanup expired API keys
	a.apiKeys.Range(func(key, value interface{}) bool {
		if apiKey, ok := value.(*APIKey); ok {
			if apiKey.ExpiresAt != nil && now.After(*apiKey.ExpiresAt) {
				a.apiKeys.Delete(key)
			}
		}
		return true
	})

	// Cleanup old failed login attempts (24h retention)
	a.failedAttempts.Range(func(key, value interface{}) bool {
		if attempt, ok := value.(*failedAttempt); ok {
			if now.Sub(attempt.firstFail) > 24*time.Hour {
				a.failedAttempts.Delete(key)
			}
		}
		return true
	})

	// Cleanup expired role cache entries
	a.roleCache.Range(func(key, value interface{}) bool {
		if entry, ok := value.(*roleCacheEntry); ok {
			if now.Sub(entry.cachedAt) > roleCacheTTL {
				a.roleCache.Delete(key)
			}
		}
		return true
	})

	// Cleanup session mutexes for users with no active sessions
	a.sessionMu.Range(func(key, value interface{}) bool {
		userID := key.(int)
		hasSession := false
		a.sessions.Range(func(sKey, sValue interface{}) bool {
			if session, ok := sValue.(*Session); ok {
				if session.UserID == userID && now.Before(session.ExpiresAt) {
					hasSession = true
					return false // stop iterating
				}
			}
			return true
		})
		if !hasSession {
			a.sessionMu.Delete(userID)
		}
		return true
	})

	// Cleanup old API key rate limit entries (1h retention)
	a.apiKeyAttempts.Range(func(key, value interface{}) bool {
		if attempt, ok := value.(*apiKeyAttempt); ok {
			if now.Sub(attempt.firstFail) > time.Hour {
				a.apiKeyAttempts.Delete(key)
			}
		}
		return true
	})

	// Cleanup old 2FA rate limit entries (10m retention)
	a.twoFARateLimits.Range(func(key, value interface{}) bool {
		if rl, ok := value.(*twoFARateLimit); ok {
			if now.Sub(rl.firstFail) > 10*time.Minute {
				a.twoFARateLimits.Delete(key)
			}
		}
		return true
	})

	// Cleanup distributed attack tracker
	a.cleanupDistributedAttackTracker()
}

// restoreSessions loads active sessions from the database on startup

// getUserRole returns a user's role, using cache when available
// This avoids a database query on every authenticated request
func (a *Auth) getUserRole(userID int) string {
	// Check cache first
	if cached, ok := a.roleCache.Load(userID); ok {
		entry := cached.(*roleCacheEntry)
		// Check if cache entry is still valid
		if time.Since(entry.cachedAt) < roleCacheTTL {
			return entry.role
		}
		// Cache expired, remove it
		a.roleCache.Delete(userID)
	}

	// Fetch from database
	user, err := a.store.GetUserByID(userID)
	if err != nil {
		return "user" // default role on error
	}

	// Cache the result
	a.roleCache.Store(userID, &roleCacheEntry{
		role:     user.Role,
		cachedAt: time.Now(),
	})

	return user.Role
}

// InvalidateRoleCache clears a user's cached role (call when role changes)
func (a *Auth) InvalidateRoleCache(userID int) {
	a.roleCache.Delete(userID)
}

// InvalidateAPIKeyCache removes a specific API key from the cache
func (a *Auth) InvalidateAPIKeyCache(keyID string) {
	a.apiKeys.Delete(keyID)
}

// InvalidateUserAPIKeys removes all API keys for a specific user from the cache
func (a *Auth) InvalidateUserAPIKeys(userID int) {
	a.apiKeys.Range(func(key, value interface{}) bool {
		if apiKey, ok := value.(*APIKey); ok && apiKey.UserID == userID {
			a.apiKeys.Delete(key)
		}
		return true
	})
}

// getSessionMutex returns a mutex for session operations for a specific user
// This ensures atomic session creation and limit enforcement per user
func (a *Auth) getSessionMutex(userID int) *sync.Mutex {
	value, _ := a.sessionMu.LoadOrStore(userID, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func (a *Auth) restoreSessions() {
	// Clean up expired sessions first
	// #nosec G104 — best-effort cleanup of expired sessions during startup.
	a.store.CleanupSessions()

	// Note: We don't restore all sessions to memory since that could be expensive
	// Sessions are loaded on-demand when validated
	log.Println("Session persistence initialized")
}

// RequireAuth is middleware that requires authentication for admin routes
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for public endpoints
		if isPublicEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Try session authentication first
		session, err := a.validateSession(r)
		if err == nil {
			ctx := context.WithValue(r.Context(), "user", session)
			ctx = context.WithValue(ctx, "session", session)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Try API key authentication
		apiKey, err := a.validateAPIKey(r)
		if err == nil {
			ctx := context.WithValue(r.Context(), "api_key", apiKey)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Authentication failed
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		a.respondUnauthorized(w, r)
	})
}

// ValidateSession validates a session from the request and returns the session if valid.
// This is the exported version of validateSession for use by page middleware.
func (a *Auth) ValidateSession(r *http.Request) (*Session, error) {
	return a.validateSession(r)
}

// isPublicEndpoint returns true if the endpoint doesn't require auth
func isPublicEndpoint(path string) bool {
	publicPrefixes := []string{
		"/api/status",
		"/api/oauth/login",
		"/api/oauth/callback",
		"/api/oauth/logout",
		"/api/auth/login",
		"/api/auth/2fa/verify",
		"/api/setup",
		"/api/csrf",
		"/health",
		"/.well-known/",
		"/robots.txt",
		"/security.txt",
	}

	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Public pages (no auth required)
	publicPages := []string{"/", "/login", "/2fa", "/setup"}
	for _, page := range publicPages {
		if path == page {
			return true
		}
	}

	// Frontend static assets (CSS, JS, images, fonts)
	if strings.HasPrefix(path, "/static/") {
		return true
	}

	// Favicon and other common static files
	if path == "/favicon.ico" || path == "/favicon.svg" {
		return true
	}

	return false
}

// validateSession validates a session cookie
func (a *Auth) validateSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie("kroxy_session")
	if err != nil {
		return nil, errors.New("no session cookie")
	}

	sessionID := cookie.Value

	// Validate session ID format with constant-time length check
	// Session IDs are base64url-encoded 32 bytes (43-44 characters)
	// Always do the same work regardless of ID validity to prevent timing leaks
	validLength := len(sessionID) >= 43 && len(sessionID) <= 48
	if !validLength {
		// Do a dummy map lookup to equalize timing with the valid path
		a.sessions.Load("__invalid__")
		return nil, errors.New("invalid session")
	}

	// Check in-memory cache first
	value, ok := a.sessions.Load(sessionID)
	if ok {
		session := value.(*Session)
		// Check expiration (sliding window)
		if time.Now().After(session.ExpiresAt) {
			// #nosec G104 — best-effort cache invalidation of expired session.
			a.sessions.Delete(sessionID)
			// #nosec G104 — best-effort persistence cleanup of expired session.
			a.store.DeleteSession(sessionID)
			return nil, errors.New("session expired")
		}
		// Check absolute lifetime limit (prevents indefinite session hijacking)
		if time.Since(session.CreatedAt) > maxSessionAbsoluteLifetime {
			// #nosec G104 — best-effort cache invalidation of expired session.
			a.sessions.Delete(sessionID)
			// #nosec G104 — best-effort persistence cleanup of expired session.
			a.store.DeleteSession(sessionID)
			log.Printf("AUDIT: session expired (absolute limit) for user_id=%d email=%s", session.UserID, strings.ReplaceAll(session.Email, "\n", " ")) // #nosec G706 — newlines stripped from logged email
			return nil, errors.New("session expired (absolute limit)")
		}
		// Verify user account is still enabled
		if userID := session.UserID; userID > 0 {
			if user, err := a.store.GetUserByID(userID); err == nil && !user.Enabled {
				// #nosec G104 — best-effort cache invalidation of disabled user session.
				a.sessions.Delete(sessionID)
				// #nosec G104 — best-effort persistence cleanup of disabled user session.
				a.store.DeleteSession(sessionID)
				log.Printf("AUDIT: session invalidated for disabled user_id=%d email=%s", userID, strings.ReplaceAll(session.Email, "\n", " ")) // #nosec G706 — newlines stripped from logged email
				return nil, errors.New("user account is disabled")
			}
		}
		// Session binding check (hijacking mitigation)
		if !a.checkSessionBinding(r, session, sessionID) {
			return nil, errors.New("session invalid")
		}

		// Extend sliding window expiration on successful validation
		newExpiry := time.Now().Add(a.sessionExpiry)
		if newExpiry.After(session.ExpiresAt) {
			updated := *session
			updated.ExpiresAt = newExpiry
			a.sessions.Store(sessionID, &updated)
			// #nosec G104 — session expiry update is queued and best-effort.
			a.enqueueDBUpdate(func() { a.store.UpdateSessionExpiry(sessionID, newExpiry) })
		}
		return session, nil
	}

	// Try to load from database (for persistence across restarts)
	dbSession, err := a.store.GetSession(sessionID)
	if err != nil {
		return nil, errors.New("session not found")
	}

	// Check expiration (sliding window)
	if time.Now().After(dbSession.ExpiresAt) {
		// #nosec G104 — best-effort cleanup of expired DB session.
		a.store.DeleteSession(sessionID)
		return nil, errors.New("session expired")
	}

	// Check absolute lifetime limit (prevents indefinite session hijacking)
	if time.Since(dbSession.CreatedAt) > maxSessionAbsoluteLifetime {
		// #nosec G104 — best-effort cleanup of expired DB session.
		a.store.DeleteSession(sessionID)
		log.Printf("AUDIT: session expired (absolute limit) for user_email=%s", strings.ReplaceAll(dbSession.UserEmail, "\n", " ")) // #nosec G706 — newlines stripped from logged email
		return nil, errors.New("session expired (absolute limit)")
	}

	// Convert to in-memory session and cache it
	userID := 0
	if dbSession.UserID != "" {
		// #nosec G104 — UserID is validated to be numeric by the store layer.
		fmt.Sscanf(dbSession.UserID, "%d", &userID)
	}

	// Verify user account is still enabled
	if userID > 0 {
		if user, err := a.store.GetUserByID(userID); err == nil && !user.Enabled {
			// #nosec G104 — best-effort cleanup of disabled user session.
			a.store.DeleteSession(sessionID)
			log.Printf("AUDIT: session invalidated for disabled user_id=%d email=%s", userID, strings.ReplaceAll(dbSession.UserEmail, "\n", " ")) // #nosec G706 — newlines stripped from logged email
			return nil, errors.New("user account is disabled")
		}
	}

	// Extend sliding window expiration on successful validation
	newExpiry := time.Now().Add(a.sessionExpiry)
	if newExpiry.After(dbSession.ExpiresAt) {
		dbSession.ExpiresAt = newExpiry
		// #nosec G104 — session expiry update is queued and best-effort.
		a.enqueueDBUpdate(func() { a.store.UpdateSessionExpiry(sessionID, newExpiry) })
	}

	// Fetch user's actual role from database (with caching)
	userRole := "user" // default role
	if userID > 0 {
		userRole = a.getUserRole(userID)
	}

	session := &Session{
		ID:           dbSession.ID,
		UserID:       userID,
		Email:        dbSession.UserEmail,
		Name:         dbSession.UserName,
		Role:         userRole,
		ProviderName: dbSession.ProviderName,
		CreatedAt:    dbSession.CreatedAt,
		ExpiresAt:    dbSession.ExpiresAt,
		IP:           dbSession.ClientIP,
		UserAgent:    dbSession.UserAgent,
	}

	// Session binding check (hijacking mitigation)
	if !a.checkSessionBinding(r, session, sessionID) {
		return nil, errors.New("session invalid")
	}

	// Cache in memory
	a.sessions.Store(sessionID, session)

	return session, nil
}

// validateAPIKey validates an API key from Authorization header
func (a *Auth) validateAPIKey(r *http.Request) (*APIKey, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("no authorization header")
	}

	// Support Bearer and ApiKey formats
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid authorization format")
	}

	var keyID, keySecret string

	switch strings.ToLower(parts[0]) {
	case "bearer":
		// For bearer tokens, the token IS the key
		// Try to find key by secret hash (slower, but works for bearer tokens)
		// This is not ideal - prefer ApiKey format with keyID:secret
		return nil, errors.New("bearer token not supported, use ApiKey format: keyid:secret")
	case "apikey":
		credentials := strings.SplitN(parts[1], ":", 2)
		if len(credentials) != 2 {
			return nil, errors.New("invalid API key format")
		}
		keyID = credentials[0]
		keySecret = credentials[1]
	default:
		return nil, errors.New("unsupported authorization type")
	}

	// Rate-limit API key validation attempts to prevent bcrypt DoS (CRIT-004)
	ip := security.GetClientIP(r)
	if !a.checkAPIKeyRateLimit(ip) {
		log.Printf("AUDIT: API key validation rate limit exceeded for IP=%s", strings.ReplaceAll(ip, "\n", " ")) // #nosec G706 — IP is from security.GetClientIP
		return nil, errors.New("rate limit exceeded")
	}

	// Look up API key from memory cache first
	var apiKey *APIKey
	if value, ok := a.apiKeys.Load(keyID); ok {
		cached := value.(*APIKey)
		// Always refresh role from cache to ensure it's current
		// getUserRole has its own cache with 30s TTL
		currentRole := a.getUserRole(cached.UserID)
		if cached.Role != currentRole {
			// Role changed — copy before mutating to avoid data race
			updated := *cached
			updated.Role = currentRole
			apiKey = &updated
			a.apiKeys.Store(keyID, apiKey)
		} else {
			apiKey = cached
		}
	} else {
		// Not in cache, check database
		dbKey, err := a.store.GetAPIKey(keyID)
		if err != nil {
			return nil, errors.New("invalid API key")
		}

		// Check expiration
		if dbKey.ExpiresAt != nil && time.Now().After(*dbKey.ExpiresAt) {
			return nil, errors.New("invalid API key")
		}

		// Look up user to get their role (with caching)
		userRole := a.getUserRole(dbKey.UserID)

		apiKey = &APIKey{
			KeyID:         dbKey.KeyID,
			KeySecretHash: dbKey.KeySecretHash,
			KeySecretHMAC: dbKey.KeySecretHMAC,
			UserID:        dbKey.UserID,
			Role:          userRole,
			Name:          dbKey.Name,
			CreatedAt:     dbKey.CreatedAt,
			ExpiresAt:     dbKey.ExpiresAt,
		}

		// Cache in memory for future lookups
		a.apiKeys.Store(keyID, apiKey)
	}

	// Check expiration
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, errors.New("API key expired")
	}

	// Fast HMAC pre-check before bcrypt to mitigate DoS from random secrets (CRIT-004).
	// Legacy keys with no stored HMAC fall through to bcrypt verification.
	// New keys use a domain-separated HMAC subkey; legacy keys use the raw
	// encryption key. The version prefix selects the expected algorithm.
	if apiKey.KeySecretHMAC != "" {
		var expected string
		if strings.HasPrefix(apiKey.KeySecretHMAC, apiKeyHMACPrefix) {
			expected = apiKeyHMAC(keySecret)
		} else {
			expected = legacyAPIKeyHMAC(keySecret)
		}
		if !hmac.Equal([]byte(expected), []byte(apiKey.KeySecretHMAC)) {
			a.recordAPIKeyFailure(ip)
			log.Printf("AUDIT: API key authentication failed for key_id=%s", strings.ReplaceAll(keyID, "\n", " "))
			return nil, errors.New("invalid API key secret")
		}
	}

	// Verify secret using bcrypt (constant-time comparison)
	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeySecretHash), []byte(keySecret)); err != nil {
		a.recordAPIKeyFailure(ip)
		log.Printf("AUDIT: API key authentication failed for key_id=%s", strings.ReplaceAll(keyID, "\n", " "))
		return nil, errors.New("invalid API key secret")
	}

	// Check if user account is enabled
	user, err := a.store.GetUserByID(apiKey.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}
	if !user.Enabled {
		return nil, errors.New("user account is disabled")
	}

	// Update last used timestamp (async)
	// #nosec G104 — last-used update is queued and best-effort.
	a.enqueueDBUpdate(func() { a.store.UpdateAPIKeyLastUsed(keyID) })

	log.Printf("AUDIT: API key authenticated: key_id=%s user_id=%d name=%s", strings.ReplaceAll(keyID, "\n", " "), apiKey.UserID, strings.ReplaceAll(apiKey.Name, "\n", " ")) // #nosec G706 — newlines stripped from logged fields

	return apiKey, nil
}

// checkAPIKeyRateLimit enforces rate limiting for API key validation attempts (CRIT-004)
// Returns false if rate limit exceeded, preventing bcrypt DoS.
func (a *Auth) checkAPIKeyRateLimit(ip string) bool {
	const maxAttempts = 10
	const window = time.Minute

	value, ok := a.apiKeyAttempts.Load(ip)
	if !ok {
		a.apiKeyAttempts.Store(ip, &apiKeyAttempt{
			count:     0,
			firstFail: time.Now(),
		})
		return true
	}

	attempt := value.(*apiKeyAttempt)
	attempt.mu.Lock()
	defer attempt.mu.Unlock()

	// Reset if window expired
	if time.Since(attempt.firstFail) > window {
		attempt.count = 0
		attempt.firstFail = time.Now()
		return true
	}

	// Check if limit exceeded
	if attempt.count >= maxAttempts {
		return false
	}

	return true
}

// recordAPIKeyFailure records a failed API key validation attempt for rate limiting
func (a *Auth) recordAPIKeyFailure(ip string) {
	value, _ := a.apiKeyAttempts.LoadOrStore(ip, &apiKeyAttempt{
		count:     0,
		firstFail: time.Now(),
	})

	attempt := value.(*apiKeyAttempt)
	attempt.mu.Lock()
	defer attempt.mu.Unlock()

	// Reset if window expired
	if time.Since(attempt.firstFail) > time.Minute {
		attempt.count = 0
		attempt.firstFail = time.Now()
	}

	attempt.count++
}

// checkSessionBinding validates that the current request matches the session's
// stored IP and User-Agent. Returns true if binding check passes or is disabled.
// When KROXY_STRICT_SESSION_BINDING is true, mismatches reject the request but
// do NOT delete the session (prevents forced-logout DoS by stolen cookies).
// Legacy sessions with empty stored IP/UA are grandfathered.
func (a *Auth) checkSessionBinding(r *http.Request, session *Session, sessionID string) bool {
	// Session binding is enabled by default; it can only be explicitly disabled.
	if os.Getenv("KROXY_STRICT_SESSION_BINDING") == "false" {
		return true
	}

	// Grandfather legacy sessions created before migration 012
	if session.IP == "" && session.UserAgent == "" {
		return true
	}

	currentIP := security.GetClientIP(r)
	currentUA := r.UserAgent()

	ipMatch := session.IP == currentIP
	uaMatch := session.UserAgent == currentUA

	if !ipMatch || !uaMatch {
		log.Printf("AUDIT: session binding mismatch for user_id=%d session=%s: ip(stored=%s current=%s) ua(stored=%s current=%s)", // #nosec G706 — IPs come from security.GetClientIP; UA newlines stripped below
			session.UserID, maskSessionID(sessionID), session.IP, currentIP, strings.ReplaceAll(session.UserAgent, "\n", " "), strings.ReplaceAll(currentUA, "\n", " "))
		// Do NOT delete the session — that would let a stolen-cookie attacker
		// force the legitimate user to re-authenticate repeatedly.
		return false
	}
	return true
}

// Login authenticates a user and creates a session
func (a *Auth) Login(email, password, ip, userAgent string) (*LoginResponse, error) {
	// Normalize email to lowercase to prevent lockout bypass via case variations
	email = strings.ToLower(email)

	// Check if IP is blocked for distributed attack (credential stuffing)
	if blocked, remaining := a.isIPBlockedForDistributedAttack(ip); blocked {
		log.Printf("AUDIT: login blocked for distributed attack from IP=%s email=%s remaining=%v", ip, email, remaining)
		return nil, fmt.Errorf("your IP is temporarily blocked due to suspicious activity. Please try again in %v", remaining.Round(time.Minute))
	}

	// Check if account is locked due to failed attempts
	if err := a.checkLockout(email); err != nil {
		return nil, err
	}

	// Look up user (database query is case-insensitive for email)
	user, err := a.store.GetUserByEmail(email)
	if err != nil {
		// Timing-safe: run bcrypt on dummy hash so response time matches a real
		// user with wrong password, preventing timing-based account enumeration.
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(password))
		a.recordFailedAttempt(email)
		a.recordDistributedAttackAttempt(ip, email)
		return nil, errors.New("invalid credentials")
	}

	if !user.Enabled {
		// Timing-safe: run bcrypt on dummy hash so response time matches a real
		// user with wrong password, preventing timing-based account enumeration.
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(password))
		a.recordFailedAttempt(email)
		a.recordDistributedAttackAttempt(ip, email)
		return nil, errors.New("invalid credentials")
	}

	// Verify password (bcrypt comparison)
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		a.recordFailedAttempt(email)
		a.recordDistributedAttackAttempt(ip, email)
		return nil, errors.New("invalid credentials")
	}

	// If TOTP is enabled, create a pending session instead
	if user.TOTPEnabled {
		pendingID := generateSecret(32)
		pending := &pending2FASession{
			userID:    user.ID,
			email:     user.Email,
			name:      user.Name,
			role:      user.Role,
			ip:        ip,
			userAgent: userAgent,
			createdAt: time.Now(),
			expiresAt: time.Now().Add(5 * time.Minute),
			attempts:  0,
		}
		a.pending2FA.Store(pendingID, pending)

		return &LoginResponse{
			Requires2FA: true,
			PendingID:   pendingID,
		}, nil
	}

	// TOTP not enabled — flag that setup is required before admin access
	setup2FARequired := true

	// Clear failed attempts on successful login
	a.clearFailedAttempts(email)

	// Lock session operations for this user to prevent race condition where
	// concurrent logins both pass the session count check before either stores
	mu := a.getSessionMutex(user.ID)
	mu.Lock()

	// Enforce session limit - invalidate oldest sessions if over limit
	a.enforceSessionLimitLocked(user.ID)

	// Create session with new ID (prevents session fixation)
	sessionID := generateSessionID()
	session := &Session{
		ID:           sessionID,
		UserID:       user.ID,
		Email:        user.Email,
		Name:         user.Name,
		Role:         user.Role,
		ProviderName: "local",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(a.sessionExpiry),
		IP:           ip,
		UserAgent:    userAgent,
	}

	a.sessions.Store(sessionID, session)
	mu.Unlock()

	log.Printf("AUDIT: session created for user_id=%d email=%s ip=%s session_id=%s",
		user.ID, user.Email, ip, maskSessionID(sessionID))

	// Persist to database for restarts
	dbSession := &store.Session{
		ID:           sessionID,
		UserEmail:    user.Email,
		UserName:     user.Name,
		UserID:       fmt.Sprintf("%d", user.ID),
		ProviderName: "local",
		ClientIP:     ip,
		UserAgent:    userAgent,
		CreatedAt:    session.CreatedAt,
		ExpiresAt:    session.ExpiresAt,
	}
	if err := a.store.CreateSession(dbSession); err != nil {
		// Log but don't fail - in-memory session is still valid
		log.Printf("Warning: failed to persist session to database: %v", err)
	}

	return &LoginResponse{
		SessionID:        sessionID,
		ExpiresAt:        session.ExpiresAt.Unix(),
		Setup2FARequired: setup2FARequired,
		User: User{
			ID:    user.ID,
			Email: user.Email,
			Name:  user.Name,
			Role:  user.Role,
		},
	}, nil
}

// Logout invalidates a session and logs the event
func (a *Auth) Logout(sessionID string) {
	// Get session info for audit logging before deletion
	var sessionInfo *Session
	if value, ok := a.sessions.Load(sessionID); ok {
		sessionInfo = value.(*Session)
	}

	// Remove from memory
	a.sessions.Delete(sessionID)
	// Remove from database
	if err := a.store.DeleteSession(sessionID); err != nil {
		log.Printf("Warning: failed to delete session from database: %v", err)
	}

	// Log audit event
	if sessionInfo != nil {
		log.Printf("AUDIT: user logout user_id=%d email=%s ip=%s", sessionInfo.UserID, sessionInfo.Email, sessionInfo.IP)
	} else {
		log.Printf("AUDIT: session logout session_id=%s", maskSessionID(sessionID))
	}
}

// HashPassword creates a bcrypt hash of the password with increased cost
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// checkLockout checks if an account is currently locked due to failed attempts
// Checks database first (persistent), then memory cache
func (a *Auth) checkLockout(email string) error {
	// Check database first (persistent across restarts)
	locked, lockedUntil, err := a.store.IsLocked(email)
	if err != nil {
		log.Printf("Warning: failed to check lockout in database: %v", err)
		// Fall back to memory check
	} else if locked && lockedUntil != nil {
		return fmt.Errorf("account locked until %s due to too many failed login attempts", lockedUntil.Format(time.RFC3339))
	}

	// Also check memory cache (for recent attempts not yet persisted)
	value, ok := a.failedAttempts.Load(email)
	if ok {
		attempt := value.(*failedAttempt)
		attempt.mu.Lock()
		defer attempt.mu.Unlock()
		if attempt.lockedUntil != nil && time.Now().Before(*attempt.lockedUntil) {
			return fmt.Errorf("account locked until %s due to too many failed login attempts", attempt.lockedUntil.Format(time.RFC3339))
		}
		// Lockout expired — reset the in-memory counter so the next failure
		// starts from zero instead of instantly re-locking.
		if attempt.lockedUntil != nil && time.Now().After(*attempt.lockedUntil) {
			attempt.count = 0
			attempt.firstFail = time.Time{}
			attempt.lockedUntil = nil
		}
	}
	return nil
}

// recordFailedAttempt records a failed login attempt and checks for lockout
// Persists to database for survival across restarts
func (a *Auth) recordFailedAttempt(email string) {
	// Record in database (persistent)
	if err := a.store.RecordFailedAttempt(email, maxFailedAttempts, lockoutDuration); err != nil {
		log.Printf("Warning: failed to record failed attempt in database: %v", err)
	}

	// Also update memory cache (for fast lockout detection)
	value, _ := a.failedAttempts.LoadOrStore(email, &failedAttempt{})
	attempt := value.(*failedAttempt)

	// Lock to prevent race condition with concurrent attempts
	attempt.mu.Lock()
	defer attempt.mu.Unlock()

	attempt.count++
	if attempt.firstFail.IsZero() {
		attempt.firstFail = time.Now()
	}

	if attempt.count >= maxFailedAttempts {
		lockedUntil := time.Now().Add(lockoutDuration)
		attempt.lockedUntil = &lockedUntil
		log.Printf("Account %s locked until %v due to %d failed login attempts", email, lockedUntil, attempt.count)
	}
}

// clearFailedAttempts clears failed attempt counter after successful login
// Clears both database and memory cache
func (a *Auth) clearFailedAttempts(email string) {
	// Clear from database
	if err := a.store.ClearFailedAttempts(email); err != nil {
		log.Printf("Warning: failed to clear failed attempts from database: %v", err)
	}
	// Clear from memory
	a.failedAttempts.Delete(email)
}

// enforceSessionLimitLocked removes oldest sessions if user exceeds maxConcurrentSessions.
// Caller must hold the per-user session mutex.
func (a *Auth) enforceSessionLimitLocked(userID int) {
	// Collect sessions from memory
	var userSessions []*Session

	a.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*Session); ok {
			if session.UserID == userID {
				userSessions = append(userSessions, session)
			}
		}
		return true
	})

	// Also query database sessions (in case sessions exist from previous restart)
	dbSessions, err := a.store.GetSessionsByUser(userID)
	if err == nil {
		// Create a map to deduplicate (memory sessions take precedence)
		sessionMap := make(map[string]*Session)
		for _, s := range userSessions {
			sessionMap[s.ID] = s
		}
		for i := range dbSessions {
			userIDInt, _ := strconv.Atoi(dbSessions[i].UserID)
			if _, exists := sessionMap[dbSessions[i].ID]; !exists {
				// Convert store.Session to auth.Session for consistency
				sessionMap[dbSessions[i].ID] = &Session{
					ID:        dbSessions[i].ID,
					UserID:    userIDInt,
					Email:     dbSessions[i].UserEmail,
					Name:      dbSessions[i].UserName,
					CreatedAt: dbSessions[i].CreatedAt,
					ExpiresAt: dbSessions[i].ExpiresAt,
				}
			}
		}
		// Rebuild userSessions from map
		userSessions = make([]*Session, 0, len(sessionMap))
		for _, s := range sessionMap {
			userSessions = append(userSessions, s)
		}
	}

	// If over limit, remove oldest sessions
	if len(userSessions) >= maxConcurrentSessions {
		// Sort by creation time (oldest first)
		for i := 0; i < len(userSessions)-1; i++ {
			for j := i + 1; j < len(userSessions); j++ {
				if userSessions[i].CreatedAt.After(userSessions[j].CreatedAt) {
					userSessions[i], userSessions[j] = userSessions[j], userSessions[i]
				}
			}
		}

		// Remove oldest sessions to get under limit
		toRemove := len(userSessions) - maxConcurrentSessions + 1
		for i := 0; i < toRemove; i++ {
			// #nosec G104 — best-effort cache invalidation.
			a.sessions.Delete(userSessions[i].ID)
			// #nosec G104 — best-effort persistence cleanup.
			a.store.DeleteSession(userSessions[i].ID)
		}
	}
}

// InvalidateUserSessions invalidates all sessions for a user (on password change, account disable, etc.)
func (a *Auth) InvalidateUserSessions(userID int) error {
	// Remove from memory
	a.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*Session); ok {
			if session.UserID == userID {
				a.sessions.Delete(key)
			}
		}
		return true
	})

	// Remove from database
	return a.store.DeleteUserSessions(userID)
}

// ChangePassword changes a user password after verifying the current password
func (a *Auth) ChangePassword(userID int, currentPassword, newPassword string) error {
	user, err := a.store.GetUserByID(userID)
	if err != nil {
		return errors.New("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
		return errors.New("current password is incorrect")
	}
	hashedPassword, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	if err := a.store.UpdateUserPassword(userID, hashedPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	if err := a.InvalidateUserSessions(userID); err != nil {
		log.Printf("Warning: failed to invalidate sessions after password change: %v", err)
	}
	return nil
}

// Verify2FA validates a TOTP code against a pending 2FA session and creates a full session on success.
func (a *Auth) Verify2FA(pendingID, code, ip, userAgent string) (*LoginResponse, error) {
	value, ok := a.pending2FA.Load(pendingID)
	if !ok {
		return nil, errors.New("invalid or expired 2FA session")
	}
	pending := value.(*pending2FASession)

	// Check expiry
	if time.Now().After(pending.expiresAt) {
		a.pending2FA.Delete(pendingID)
		return nil, errors.New("2FA session expired")
	}

	// Bind the pending 2FA session to the IP and User-Agent used at login.
	// This prevents an attacker who steals the pending cookie from completing
	// 2FA from a different device/network.
	if pending.ip != ip || pending.userAgent != userAgent {
		a.pending2FA.Delete(pendingID)
		log.Printf("SECURITY: 2FA session binding mismatch for user_id=%d pending_id=%s", pending.userID, pendingID)
		return nil, errors.New("2FA session binding mismatch")
	}

	// Check per-user 2FA rate limit (prevents brute-force across multiple pending sessions)
	if err := a.check2FARateLimit(pending.userID, ip); err != nil {
		return nil, err
	}

	pending.mu.Lock()

	// Check max attempts per pending session
	if pending.attempts >= 5 {
		pending.mu.Unlock()
		a.pending2FA.Delete(pendingID)
		return nil, errors.New("too many failed attempts, please log in again")
	}

	pending.attempts++
	pending.mu.Unlock()

	// Get user's TOTP secret
	user, err := a.store.GetUserByID(pending.userID)
	if err != nil {
		a.pending2FA.Delete(pendingID)
		return nil, errors.New("user not found")
	}

	// Decrypt TOTP secret
	secret, err := crypto.Decrypt(user.TOTPSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// Validate TOTP code
	if !totp.ValidateCode(secret, code) {
		if exceeded := a.atomicallyRecord2FAFailure(pending.userID); exceeded {
			return nil, errors.New("too many failed 2FA attempts, please log in again")
		}
		return nil, errors.New("invalid 2FA code")
	}

	// 2FA verified - remove pending session and create full session
	a.pending2FA.Delete(pendingID)
	a.clear2FARateLimit(pending.userID)
	a.clearFailedAttempts(pending.email)

	mu := a.getSessionMutex(user.ID)
	mu.Lock()
	a.enforceSessionLimitLocked(user.ID)

	sessionID := generateSessionID()
	session := &Session{
		ID:           sessionID,
		UserID:       user.ID,
		Email:        user.Email,
		Name:         user.Name,
		Role:         user.Role,
		ProviderName: "local_totp",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(a.sessionExpiry),
		IP:           ip,
		UserAgent:    userAgent,
	}
	a.sessions.Store(sessionID, session)
	mu.Unlock()

	log.Printf("AUDIT: 2FA session created for user_id=%d email=%s ip=%s session_id=%s",
		user.ID, user.Email, ip, maskSessionID(sessionID))

	dbSession := &store.Session{
		ID:           sessionID,
		UserEmail:    user.Email,
		UserName:     user.Name,
		UserID:       fmt.Sprintf("%d", user.ID),
		ProviderName: "local_totp",
		ClientIP:     ip,
		UserAgent:    userAgent,
		CreatedAt:    session.CreatedAt,
		ExpiresAt:    session.ExpiresAt,
	}
	if err := a.store.CreateSession(dbSession); err != nil {
		log.Printf("Warning: failed to persist 2FA session to database: %v", err)
	}

	return &LoginResponse{
		SessionID: sessionID,
		ExpiresAt: session.ExpiresAt.Unix(),
		User: User{
			ID:    user.ID,
			Email: user.Email,
			Name:  user.Name,
			Role:  user.Role,
		},
	}, nil
}

// Create2FAPendingCookie creates the cookie for pending 2FA sessions
func (a *Auth) Create2FAPendingCookie(pendingID string) *http.Cookie {
	c := &http.Cookie{
		Name:     "kroxy_pending_2fa",
		Value:    pendingID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(5 * time.Minute),
	}
	if os.Getenv("KROXY_INSECURE_COOKIES") != "true" {
		c.Secure = true
	}
	return c
}

// RequireTOTP middleware redirects password-only sessions to the 2FA setup page
// if the user has not enabled TOTP. This ensures admin access always requires 2FA.
func (a *Auth) RequireTOTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := getSessionFromContext(r.Context())
		if session == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Allow access to 2FA setup/verify endpoints and login/logout
		path := r.URL.Path
		if path == "/2fa/setup" || path == "/2fa" ||
			strings.HasPrefix(path, "/api/user/2fa/") ||
			strings.HasPrefix(path, "/api/auth/2fa/") ||
			path == "/login" || path == "/api/auth/login" ||
			path == "/logout" || path == "/api/auth/logout" {
			next.ServeHTTP(w, r)
			return
		}

		// OIDC sessions are considered strong auth
		if session.ProviderName != "" && session.ProviderName != "local" && session.ProviderName != "local_totp" {
			next.ServeHTTP(w, r)
			return
		}

		// TOTP-verified sessions are allowed
		if session.ProviderName == "local_totp" {
			next.ServeHTTP(w, r)
			return
		}

		// Password-only session — if the user has TOTP enabled they must have
		// completed the second factor (ProviderName == "local_totp"). A plain
		// "local" session must never be accepted for a TOTP-enabled user.
		if session.ProviderName == "local" {
			user, err := a.store.GetUserByID(session.UserID)
			if err == nil && user.TOTPEnabled {
				http.Error(w, "Two-factor authentication required", http.StatusForbidden)
				return
			}

			// TOTP not enabled — redirect to setup
			if strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r, "/2fa/setup", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			// #nosec G104 — best-effort JSON error response.
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "2fa_setup_required",
				"error_description": "Two-factor authentication must be set up before accessing this resource",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireStrongAuth middleware ensures that non-local connections use strong auth (OIDC or TOTP).
// Local/private network connections are allowed with password-only auth.
func (a *Auth) RequireStrongAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := getSessionFromContext(r.Context())
		if session == nil {
			// No session - let RequireAuth handle it
			next.ServeHTTP(w, r)
			return
		}

		// OIDC sessions are always considered strong auth
		if session.ProviderName != "" && session.ProviderName != "local" && session.ProviderName != "local_totp" {
			next.ServeHTTP(w, r)
			return
		}

		// TOTP sessions are strong auth
		if session.ProviderName == "local_totp" {
			next.ServeHTTP(w, r)
			return
		}

		// Password-only ("local") - check if client IP is private.
		// Use security.GetClientIP to respect trusted proxies and X-Forwarded-For
		// instead of raw RemoteAddr (HIGH-024).
		ip := security.GetClientIP(r)
		parsedIP := net.ParseIP(ip)

		if parsedIP != nil && validation.IsPrivateIP(parsedIP) {
			// Private IP - allow password-only
			next.ServeHTTP(w, r)
			return
		}

		// Public IP with password-only auth - reject
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		// #nosec G104 — best-effort JSON error response.
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "2fa_required",
			"error_description": "Two-factor authentication required for internet-facing access",
		})
	})
}
func (a *Auth) GenerateAPIKey(userID int, name string, expiresAt *time.Time) (keyID, keySecret string, err error) {
	keyID = generateKeyID()
	keySecret = generateSecret(32)

	// Hash the secret for storage using the same cost as passwords
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(keySecret), bcryptCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash secret: %w", err)
	}

	// Fast HMAC pre-check to mitigate bcrypt DoS on random secrets (CRIT-004).
	// In the rare case no encryption key is available, the bcrypt rate limit remains the defense.
	secretHMAC := apiKeyHMAC(keySecret)

	// Create API key record
	apiKey := &store.APIKey{
		KeyID:         keyID,
		KeySecretHash: string(hashedSecret),
		KeySecretHMAC: secretHMAC,
		UserID:        userID,
		Name:          name,
		CreatedAt:     time.Now(),
		ExpiresAt:     expiresAt,
	}

	// Persist to database
	if err := a.store.CreateAPIKey(apiKey); err != nil {
		return "", "", fmt.Errorf("failed to store API key: %w", err)
	}

	// Cache in memory
	cachedKey := &APIKey{
		KeyID:         keyID,
		KeySecretHash: string(hashedSecret),
		KeySecretHMAC: secretHMAC,
		UserID:        userID,
		Name:          name,
		CreatedAt:     time.Now(),
		ExpiresAt:     expiresAt,
	}
	a.apiKeys.Store(keyID, cachedKey)

	return keyID, keySecret, nil
}

// sha256Sum returns SHA256 hash of input as base64 string
func sha256Sum(input string) string {
	hash := sha256.Sum256([]byte(input))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// apiKeyHMAC returns a server-side HMAC of an API key secret using a key
// derived specifically for this purpose (domain separation from AES encryption).
// Guessing random secrets requires both the key ID and a valid HMAC, avoiding
// bcrypt work for invalid secrets. Returns an empty string when no encryption
// key is available (legacy/dev fallback).
func apiKeyHMAC(secret string) string {
	key, err := crypto.GetEncryptionKey()
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, deriveAPIKeyHMACKey(key))
	mac.Write([]byte(secret))
	return apiKeyHMACPrefix + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// legacyAPIKeyHMAC is the original pre-check used for keys created before the
// domain-separated derivation was introduced. It is kept only so existing keys
// continue to work; newly created keys always use apiKeyHMAC.
func legacyAPIKeyHMAC(secret string) string {
	key, err := crypto.GetEncryptionKey()
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(secret))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// deriveAPIKeyHMACKey derives a domain-separated HMAC key from the encryption key
// using HMAC-SHA256 with a fixed context label.
func deriveAPIKeyHMACKey(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("kroxy-api-key-hmac-v1"))
	return mac.Sum(nil)
}

// GenerateState creates a cryptographically secure state parameter
// sessionBinding should be a value from the user's session cookie to bind the state to their browser
func (a *Auth) GenerateState(providerID int, redirectURL, sessionBinding string) string {
	state := generateSecret(32)

	// Hash the session binding for storage (don't store raw session value)
	bindingHash := ""
	if sessionBinding != "" {
		bindingHash = sha256Sum(sessionBinding)
	}

	stateInfo := &StateInfo{
		State:          state,
		ProviderID:     providerID,
		RedirectURL:    redirectURL,
		SessionBinding: bindingHash,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(10 * time.Minute),
	}

	a.stateStore.Store(state, stateInfo)
	return state
}

// ValidateState validates and consumes a state parameter
// sessionBinding should be the same value passed to GenerateState
func (a *Auth) ValidateState(state, sessionBinding string) (*StateInfo, error) {
	value, ok := a.stateStore.Load(state)
	if !ok {
		return nil, errors.New("invalid state")
	}

	stateInfo := value.(*StateInfo)

	// Check expiration
	if time.Now().After(stateInfo.ExpiresAt) {
		a.stateStore.Delete(state)
		return nil, errors.New("state expired")
	}

	// Verify session binding to prevent state token theft
	if stateInfo.SessionBinding != "" {
		if sessionBinding == "" {
			a.stateStore.Delete(state)
			return nil, errors.New("missing session binding")
		}
		expectedBinding := sha256Sum(sessionBinding)
		if subtle.ConstantTimeCompare([]byte(stateInfo.SessionBinding), []byte(expectedBinding)) != 1 {
			a.stateStore.Delete(state)
			return nil, errors.New("invalid session binding")
		}
	}

	// Consume state (single-use)
	a.stateStore.Delete(state)

	return stateInfo, nil
}

// respondUnauthorized sends an unauthorized response
func (a *Auth) respondUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer realm=\"kroxy\"")
	w.WriteHeader(http.StatusUnauthorized)
	// #nosec G104 — best-effort JSON error response.
	json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": "Authentication required",
	})
}

// getSessionFromContext extracts session from request context
func getSessionFromContext(ctx context.Context) *Session {
	if session, ok := ctx.Value("session").(*Session); ok {
		return session
	}
	return nil
}

// check2FARateLimit enforces per-user rate limiting for 2FA verification attempts.
// Prevents brute-forcing TOTP codes by creating new pending sessions.
// Lockouts escalate: 1st=5m, 2nd=1h, 3rd=IP ban.
func (a *Auth) check2FARateLimit(userID int, ip string) error {
	const maxAttempts = 5
	const window = 5 * time.Minute

	value, _ := a.twoFARateLimits.LoadOrStore(userID, &twoFARateLimit{})
	entry := value.(*twoFARateLimit)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()

	// Reset attempts if window expired, but keep lockoutCount for escalation
	if !entry.firstFail.IsZero() && now.Sub(entry.firstFail) > window {
		entry.attempts = 0
		entry.firstFail = time.Time{}
		entry.locked = false
		entry.lockedUntil = nil
	}

	if entry.locked && entry.lockedUntil != nil && now.Before(*entry.lockedUntil) {
		return fmt.Errorf("too many failed 2FA attempts, try again in %v", time.Until(*entry.lockedUntil).Round(time.Second))
	}
	if entry.attempts >= maxAttempts {
		entry.lockoutCount++
		var lockoutDuration time.Duration
		switch entry.lockoutCount {
		case 1:
			lockoutDuration = 5 * time.Minute
		case 2:
			lockoutDuration = 1 * time.Hour
		default:
			// 3rd+ lockout: ban the IP via distributed attack tracker
			a.banIPFor2FA(ip)
			return fmt.Errorf("too many failed 2FA attempts. Your IP has been temporarily banned.")
		}
		lockedUntil := now.Add(lockoutDuration)
		entry.locked = true
		entry.lockedUntil = &lockedUntil
		log.Printf("SECURITY: 2FA lockout #%d for user_id=%d ip=%s duration=%v", entry.lockoutCount, userID, ip, lockoutDuration)
		return fmt.Errorf("too many failed 2FA attempts, try again in %v", lockoutDuration)
	}

	return nil
}

// atomicallyRecord2FAFailure increments the per-user 2FA attempt counter under lock
// and returns whether the limit was exceeded. This avoids the check-then-act race.
func (a *Auth) atomicallyRecord2FAFailure(userID int) bool {
	const maxAttempts = 5
	value, _ := a.twoFARateLimits.LoadOrStore(userID, &twoFARateLimit{})
	entry := value.(*twoFARateLimit)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.firstFail.IsZero() {
		entry.firstFail = time.Now()
	}
	entry.attempts++
	return entry.attempts >= maxAttempts
}

// record2FAFailure increments the per-user 2FA attempt counter.
func (a *Auth) record2FAFailure(userID int) {
	value, _ := a.twoFARateLimits.LoadOrStore(userID, &twoFARateLimit{})
	entry := value.(*twoFARateLimit)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.firstFail.IsZero() {
		entry.firstFail = time.Now()
	}
	entry.attempts++
}

// clear2FARateLimit resets the per-user 2FA attempt counter on successful verification.
func (a *Auth) clear2FARateLimit(userID int) {
	a.twoFARateLimits.Delete(userID)
}

// banIPFor2FA adds an IP to the distributed attack tracker with an immediate block.
func (a *Auth) banIPFor2FA(ip string) {
	if a.distributedAttack == nil {
		return
	}
	a.distributedAttack.mu.Lock()
	defer a.distributedAttack.mu.Unlock()

	now := time.Now()
	stats, exists := a.distributedAttack.ipAttempts[ip]
	if !exists {
		stats = &ipAttackStats{
			uniqueAccounts: make(map[string]time.Time),
			firstAttempt:   now,
		}
		a.distributedAttack.ipAttempts[ip] = stats
	}
	stats.blocked = true
	stats.blockedUntil = now.Add(distributedAttackBanDuration)
	log.Printf("SECURITY ALERT: IP %s banned due to repeated 2FA lockouts", ip)
}

// GetUserFromContext extracts user from request context
func GetUserFromContext(ctx context.Context) *User {
	if session, ok := ctx.Value("session").(*Session); ok {
		return &User{
			ID:    session.UserID,
			Email: session.Email,
			Name:  session.Name,
			Role:  session.Role,
		}
	}
	return nil
}

// getAPIKeyFromContext extracts API key from request context
func getAPIKeyFromContext(ctx context.Context) *APIKey {
	if apiKey, ok := ctx.Value("api_key").(*APIKey); ok {
		return apiKey
	}
	return nil
}

// RequireRole middleware requires a specific role
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check session authentication first
			session := getSessionFromContext(r.Context())
			if session != nil {
				if session.Role == role || session.Role == "admin" {
					next.ServeHTTP(w, r)
					return
				}
				if strings.Contains(r.Header.Get("Accept"), "text/html") {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				http.Error(w, "Forbidden - Insufficient privileges", http.StatusForbidden)
				return
			}

			// Check API key authentication
			apiKey := getAPIKeyFromContext(r.Context())
			if apiKey != nil {
				// API keys inherit the user's role - check it
				if apiKey.Role == role || apiKey.Role == "admin" {
					next.ServeHTTP(w, r)
					return
				}
				if strings.Contains(r.Header.Get("Accept"), "text/html") {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				http.Error(w, "Forbidden - Insufficient privileges", http.StatusForbidden)
				return
			}

			if strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}

// Helper functions

func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("FATAL: crypto/rand failed in generateSessionID: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// maskSessionID masks a session ID for logging (shows first 4 and last 4 chars)
func maskSessionID(sessionID string) string {
	if len(sessionID) <= 8 {
		return "****"
	}
	return sessionID[:4] + "..." + sessionID[len(sessionID)-4:]
}

func generateKeyID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("FATAL: crypto/rand failed in generateKeyID: %v", err)
	}
	return "key_" + base64.URLEncoding.EncodeToString(b)
}

// GenerateSecret creates a cryptographically secure random string
func GenerateSecret(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("FATAL: crypto/rand failed in GenerateSecret: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// generateSecret is an alias for GenerateSecret (internal use)
func generateSecret(length int) string {
	return GenerateSecret(length)
}

// CreateSessionCookie creates an HTTP cookie for a session
func (a *Auth) CreateSessionCookie(sessionID string) *http.Cookie {
	c := &http.Cookie{
		Name:     "kroxy_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax required for OAuth redirects
		Expires:  time.Now().Add(a.sessionExpiry),
	}
	if os.Getenv("KROXY_INSECURE_COOKIES") != "true" {
		c.Secure = true
	}
	return c
}

// isIPBlockedForDistributedAttack checks if an IP is currently blocked for credential stuffing
func (a *Auth) isIPBlockedForDistributedAttack(ip string) (bool, time.Duration) {
	if a.distributedAttack == nil {
		return false, 0
	}
	a.distributedAttack.mu.Lock()
	defer a.distributedAttack.mu.Unlock()

	stats, exists := a.distributedAttack.ipAttempts[ip]
	if !exists || !stats.blocked {
		return false, 0
	}

	remaining := time.Until(stats.blockedUntil)
	if remaining <= 0 {
		// Block expired
		delete(a.distributedAttack.ipAttempts, ip)
		return false, 0
	}

	return true, remaining
}

// recordDistributedAttackAttempt tracks failed login attempts per IP for distributed attack detection
func (a *Auth) recordDistributedAttackAttempt(ip, email string) {
	if a.distributedAttack == nil {
		return
	}
	a.distributedAttack.mu.Lock()
	defer a.distributedAttack.mu.Unlock()

	now := time.Now()
	stats, exists := a.distributedAttack.ipAttempts[ip]
	if !exists {
		stats = &ipAttackStats{
			uniqueAccounts: make(map[string]time.Time),
			firstAttempt:   now,
		}
		a.distributedAttack.ipAttempts[ip] = stats
	}

	// Clean up old entries (older than window)
	if now.Sub(stats.firstAttempt) > distributedAttackWindow {
		// Reset window
		stats.uniqueAccounts = make(map[string]time.Time)
		stats.firstAttempt = now
		stats.blocked = false
	}

	// Track unique accounts
	stats.uniqueAccounts[email] = now
	stats.lastAttempt = now

	// Check if threshold exceeded
	if len(stats.uniqueAccounts) >= distributedAttackThreshold && !stats.blocked {
		stats.blocked = true
		stats.blockedUntil = now.Add(distributedAttackBanDuration)
		log.Printf("SECURITY ALERT: Distributed attack detected from IP %s - %d unique accounts attempted in %v window",
			ip, len(stats.uniqueAccounts), distributedAttackWindow)
	}
}

// cleanupDistributedAttackTracker removes expired entries from the distributed attack tracker
func (a *Auth) cleanupDistributedAttackTracker() {
	if a.distributedAttack == nil {
		return
	}
	a.distributedAttack.mu.Lock()
	defer a.distributedAttack.mu.Unlock()

	now := time.Now()
	for ip, stats := range a.distributedAttack.ipAttempts {
		// Remove if blocked and expired
		if stats.blocked && now.After(stats.blockedUntil) {
			delete(a.distributedAttack.ipAttempts, ip)
			continue
		}
		// Remove if window expired
		if now.Sub(stats.lastAttempt) > distributedAttackWindow {
			delete(a.distributedAttack.ipAttempts, ip)
		}
	}
}

// VerifyPassword checks if the provided password matches the user's current password
func (a *Auth) VerifyPassword(userID int, password string) error {
	user, err := a.store.GetUserByID(userID)
	if err != nil {
		return errors.New("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return errors.New("invalid password")
	}
	return nil
}
