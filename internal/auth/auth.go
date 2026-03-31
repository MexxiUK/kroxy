package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kroxy/kroxy/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// Auth provides authentication middleware for the Admin API
type Auth struct {
	store         *store.Store
	sessions      sync.Map // sessionID -> *Session
	apiKeys       sync.Map // keyID -> *APIKey
	stateStore    sync.Map // state -> *StateInfo
	adminTokens   sync.Map // token -> *adminTokenInfo
	jwtSecret     []byte
	sessionExpiry time.Duration
}

// adminTokenInfo holds admin token with expiration
type adminTokenInfo struct {
	createdAt time.Time
	expiresAt time.Time
}
	jwtSecret     []byte
	sessionExpiry time.Duration
}

// Session represents an authenticated admin session
type Session struct {
	ID        string
	UserID    int
	Email     string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	UserAgent string
}

// APIKey represents an API key for programmatic access
// APIKey represents an API key - use store.APIKey for persistence
type APIKey struct {
	ID            int
	KeyID         string
	KeySecretHash string // bcrypt hashed secret
	UserID        int
	Name          string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	LastUsed      *time.Time
}

// StateInfo stores OAuth state parameters for CSRF protection
type StateInfo struct {
	State       string
	ProviderID  int
	RedirectURL string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// adminTokenInfo stores admin token with expiration
type adminTokenInfo struct {
	CreatedAt time.Time
	ExpiresAt time.Time
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	SessionID string `json:"session_id"`
	ExpiresAt int64  `json:"expires_at"`
	User      User   `json:"user"`
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
	// Allow JWT secret to be configured via environment variable for multi-instance deployments
	jwtSecret := os.Getenv("KROXY_JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = generateSecret(32)
	}

	a := &Auth{
		store:         s,
		sessionExpiry: 24 * time.Hour,
		jwtSecret:     []byte(jwtSecret),
	}

	// Restore sessions from database
	a.restoreSessions()

	return a
}

// restoreSessions loads active sessions from the database on startup
func (a *Auth) restoreSessions() {
	// Clean up expired sessions first
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

		// Try admin token (for initial setup)
		if token := r.Header.Get("X-Admin-Token"); token != "" {
			if a.validateAdminToken(token) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Authentication failed
		a.respondUnauthorized(w, r)
	})
}

// isPublicEndpoint returns true if the endpoint doesn't require auth
func isPublicEndpoint(path string) bool {
	publicPrefixes := []string{
		"/api/status",
		"/api/oauth/login",
		"/api/oauth/callback",
		"/api/oauth/logout",
		// "/api/metrics" - Removed: metrics should require authentication
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

	// Frontend static files
	if !strings.HasPrefix(path, "/api/") {
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

	// Check in-memory cache first
	value, ok := a.sessions.Load(sessionID)
	if ok {
		session := value.(*Session)
		// Check expiration
		if time.Now().After(session.ExpiresAt) {
			a.sessions.Delete(sessionID)
			a.store.DeleteSession(sessionID)
			return nil, errors.New("session expired")
		}
		return session, nil
	}

	// Try to load from database (for persistence across restarts)
	dbSession, err := a.store.GetSession(sessionID)
	if err != nil {
		return nil, errors.New("session not found")
	}

	// Check expiration
	if time.Now().After(dbSession.ExpiresAt) {
		a.store.DeleteSession(sessionID)
		return nil, errors.New("session expired")
	}

	// Convert to in-memory session and cache it
	userID := 0
	if dbSession.UserID != "" {
		fmt.Sscanf(dbSession.UserID, "%d", &userID)
	}
	session := &Session{
		ID:        dbSession.ID,
		UserID:    userID,
		Email:     dbSession.UserEmail,
		Role:      "user",
		CreatedAt: dbSession.CreatedAt,
		ExpiresAt: dbSession.ExpiresAt,
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
		keySecret = parts[1]
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

	// Look up API key from memory cache first
	var apiKey *APIKey
	if value, ok := a.apiKeys.Load(keyID); ok {
		apiKey = value.(*APIKey)
	} else {
		// Not in cache, check database
		dbKey, err := a.store.GetAPIKey(keyID)
		if err != nil {
			return nil, errors.New("invalid API key ID")
		}

		// Check expiration
		if dbKey.ExpiresAt != nil && time.Now().After(*dbKey.ExpiresAt) {
			return nil, errors.New("API key expired")
		}

		apiKey = &APIKey{
			KeyID:         dbKey.KeyID,
			KeySecretHash: dbKey.KeySecretHash,
			UserID:        dbKey.UserID,
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

	// Verify secret using bcrypt (constant-time comparison)
	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeySecretHash), []byte(keySecret)); err != nil {
		return nil, errors.New("invalid API key secret")
	}

	// Update last used timestamp (async)
	go a.store.UpdateAPIKeyLastUsed(keyID)

	return apiKey, nil
}

// validateAdminToken validates a one-time admin token with expiration
func (a *Auth) validateAdminToken(token string) bool {
	value, ok := a.adminTokens.Load(token)
	if !ok {
		return false
	}

	info, ok := value.(*adminTokenInfo)
	if !ok {
		a.adminTokens.Delete(token)
		return false
	}

	// Check expiration
	if time.Now().After(info.ExpiresAt) {
		a.adminTokens.Delete(token)
		return false
	}

	// Single-use: delete after validation
	a.adminTokens.Delete(token)
	return true
}

// Login authenticates a user and creates a session
func (a *Auth) Login(email, password, ip, userAgent string) (*LoginResponse, error) {
	// Look up user
	user, err := a.store.GetUserByEmail(email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if !user.Enabled {
		return nil, errors.New("account disabled")
	}

	// Verify password (bcrypt comparison)
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Create session
	sessionID := generateSessionID()
	session := &Session{
		ID:        sessionID,
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(a.sessionExpiry),
		IP:        ip,
		UserAgent: userAgent,
	}

	a.sessions.Store(sessionID, session)

	// Persist to database for restarts
	dbSession := &store.Session{
		ID:           sessionID,
		UserEmail:    user.Email,
		UserName:     user.Name,
		UserID:       fmt.Sprintf("%d", user.ID),
		ProviderName: "local",
		CreatedAt:    session.CreatedAt,
		ExpiresAt:    session.ExpiresAt,
	}
	if err := a.store.CreateSession(dbSession); err != nil {
		// Log but don't fail - in-memory session is still valid
		log.Printf("Warning: failed to persist session to database: %v", err)
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

// Logout invalidates a session
func (a *Auth) Logout(sessionID string) {
	// Remove from memory
	a.sessions.Delete(sessionID)
	// Remove from database
	if err := a.store.DeleteSession(sessionID); err != nil {
		log.Printf("Warning: failed to delete session from database: %v", err)
	}
}

// HashPassword creates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// GenerateAPIKey creates a new API key
func (a *Auth) GenerateAPIKey(userID int, name string) (keyID, keySecret string, err error) {
	keyID = generateKeyID()
	keySecret = generateSecret(32)

	// Hash the secret for storage
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(keySecret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash secret: %w", err)
	}

	// Create API key record
	apiKey := &store.APIKey{
		KeyID:         keyID,
		KeySecretHash: string(hashedSecret),
		UserID:        userID,
		Name:          name,
		CreatedAt:     time.Now(),
	}

	// Persist to database
	if err := a.store.CreateAPIKey(apiKey); err != nil {
		return "", "", fmt.Errorf("failed to store API key: %w", err)
	}

	// Cache in memory
	a.apiKeys.Store(keyID, &APIKey{
		KeyID:         keyID,
		KeySecretHash: string(hashedSecret),
		UserID:        userID,
		Name:          name,
		CreatedAt:     time.Now(),
	})

	return keyID, keySecret, nil
}

// CreateAdminToken creates a one-time admin token for initial setup
func (a *Auth) CreateAdminToken() string {
	token := generateSecret(32)
	// Admin tokens expire after 24 hours for security
	a.adminTokens.Store(token, &adminTokenInfo{
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	return token
}

// GenerateState creates a cryptographically secure state parameter
func (a *Auth) GenerateState(providerID int, redirectURL string) string {
	state := generateSecret(32)

	stateInfo := &StateInfo{
		State:       state,
		ProviderID:  providerID,
		RedirectURL: redirectURL,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	a.stateStore.Store(state, stateInfo)
	return state
}

// ValidateState validates and consumes a state parameter
func (a *Auth) ValidateState(state string) (*StateInfo, error) {
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

	// Consume state (single-use)
	a.stateStore.Delete(state)

	return stateInfo, nil
}

// respondUnauthorized sends an unauthorized response
func (a *Auth) respondUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer realm=\"kroxy\"")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": "Authentication required",
	})
}

// GetSessionFromContext extracts session from request context
func GetSessionFromContext(ctx context.Context) *Session {
	if session, ok := ctx.Value("session").(*Session); ok {
		return session
	}
	return nil
}

// GetUserFromContext extracts user from request context
func GetUserFromContext(ctx context.Context) *User {
	if session, ok := ctx.Value("session").(*Session); ok {
		return &User{
			ID:    session.UserID,
			Email: session.Email,
			Role:  session.Role,
		}
	}
	return nil
}

// GetAPIKeyFromContext extracts API key from request context
func GetAPIKeyFromContext(ctx context.Context) *APIKey {
	if apiKey, ok := ctx.Value("api_key").(*APIKey); ok {
		return apiKey
	}
	return nil
}

// GetAPIKeyFromContext extracts API key from request context
func GetAPIKeyFromContext(ctx context.Context) *APIKey {
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
			session := GetSessionFromContext(r.Context())
			if session != nil {
				if session.Role == role || session.Role == "admin" {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Forbidden - Insufficient privileges", http.StatusForbidden)
				return
			}

			// Check API key authentication
			apiKey := GetAPIKeyFromContext(r.Context())
			if apiKey != nil {
				// API keys inherit the user's role - need to check it
				// For now, API keys are admin-level access
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}

// Helper functions

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateKeyID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "key_" + base64.URLEncoding.EncodeToString(b)
}

func generateSecret(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
// CreateSessionCookie creates an HTTP cookie for a session
func (a *Auth) CreateSessionCookie(sessionID string) *http.Cookie {
	return &http.Cookie{
		Name:     "kroxy_session",
		Value:   sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(a.sessionExpiry),
	}
}
