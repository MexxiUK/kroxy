package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kroxy/kroxy/internal/crypto"
	"github.com/kroxy/kroxy/internal/store"
	"golang.org/x/oauth2"
)

// Manager handles OIDC authentication for multiple providers
type Manager struct {
	store      *store.Store
	providers  map[int]*oauthProvider
	sessions   map[string]*Session
	mu         sync.RWMutex // Protects providers map
	sessionMu  sync.RWMutex // Protects sessions map
	httpClient *http.Client
}

type oauthProvider struct {
	name        string
	oauthConfig *oauth2.Config
	verifier    *oidc.IDTokenVerifier
}

// Session represents an authenticated user session
type Session struct {
	ID           string
	ProviderName string
	UserEmail    string
	UserName     string
	UserID       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Roles        []string
}

// NewManager creates a new OIDC manager
func NewManager(s *store.Store) *Manager {
	return &Manager{
		store:      s,
		providers:  make(map[int]*oauthProvider),
		sessions:   make(map[string]*Session),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// buildOAuthProvider performs OIDC discovery and constructs the runtime provider
// WITHOUT holding any locks. Network I/O happens here, so callers must not hold mu.
func (m *Manager) buildOAuthProvider(ctx context.Context, p store.OIDCProvider) (*oauthProvider, error) {
	// Discover OIDC configuration
	discoveryURL := p.DiscoveryURL
	if discoveryURL == "" {
		switch p.Name {
		case "google":
			discoveryURL = "https://accounts.google.com"
		case "github":
			discoveryURL = "https://token.actions.githubusercontent.com"
		default:
			return nil, fmt.Errorf("discovery URL required for custom provider")
		}
	}

	provider, err := oidc.NewProvider(ctx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Default scopes
	scopes := []string{oidc.ScopeOpenID, "email", "profile"}

	oauthConfig := &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  p.RedirectURL,
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: p.ClientID})

	return &oauthProvider{
		name:        p.Name,
		oauthConfig: oauthConfig,
		verifier:    verifier,
	}, nil
}

// InitializeProvider sets up an OIDC provider from database configuration
func (m *Manager) InitializeProvider(ctx context.Context, p store.OIDCProvider) error {
	op, err := m.buildOAuthProvider(ctx, p)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[p.ID] = op
	log.Printf("Initialized OIDC provider: %s", p.Name)
	return nil
}

// AddProvider adds a new provider to the in-memory cache
func (m *Manager) AddProvider(ctx context.Context, p store.OIDCProvider) error {
	return m.InitializeProvider(ctx, p)
}

// UpdateProvider updates an existing provider in the cache.
// It performs discovery BEFORE modifying the cache, so a failure leaves the old entry intact.
func (m *Manager) UpdateProvider(ctx context.Context, p store.OIDCProvider) error {
	op, err := m.buildOAuthProvider(ctx, p)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[p.ID] = op
	log.Printf("Updated OIDC provider: %s", p.Name)
	return nil
}

// RemoveProvider removes a provider from the cache
func (m *Manager) RemoveProvider(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.providers, id)
}

// InitializeAllProviders loads all providers from database
func (m *Manager) InitializeAllProviders(ctx context.Context) error {
	providers, err := m.store.GetOIDCProviders()
	if err != nil {
		return fmt.Errorf("failed to get OIDC providers: %w", err)
	}

	for _, p := range providers {
		decryptedSecret, err := crypto.Decrypt(p.ClientSecret)
		if err != nil {
			log.Printf("Warning: failed to decrypt client secret for provider %s: %v", p.Name, err)
			continue
		}
		p.ClientSecret = decryptedSecret
		if err := m.InitializeProvider(ctx, p); err != nil {
			log.Printf("Warning: failed to initialize provider %s: %v", p.Name, err)
			continue
		}
	}

	return nil
}

// GetAuthURL returns the OAuth authorization URL for a provider
func (m *Manager) GetAuthURL(providerID int, state string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.providers[providerID]
	if !ok {
		return "", fmt.Errorf("provider not found: %d", providerID)
	}

	return p.oauthConfig.AuthCodeURL(state), nil
}

// ExchangeCode exchanges an authorization code for tokens.
// The ip and userAgent parameters are persisted in the database session for binding validation.
func (m *Manager) ExchangeCode(ctx context.Context, providerID int, code string, ip string, userAgent string) (*Session, error) {
	m.mu.RLock()
	p, ok := m.providers[providerID]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("provider not found: %d", providerID)
	}

	// Exchange code for token
	token, err := p.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no ID token in response")
	}

	// Verify ID token
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Subject       string `json:"sub"`
		Username      string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	if !claims.EmailVerified {
		return nil, fmt.Errorf("OIDC provider did not verify the email address")
	}

	// Create session
	session := &Session{
		ID:           generateSessionID(),
		ProviderName: p.name,
		UserEmail:    claims.Email,
		UserName:     claims.Name,
		UserID:       claims.Subject,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	// Store in memory (cache)
	m.sessionMu.Lock()
	m.sessions[session.ID] = session
	m.sessionMu.Unlock()

	// Persist to database for multi-instance support
	if err := m.store.CreateSession(&store.Session{
		ID:           session.ID,
		UserEmail:    session.UserEmail,
		UserName:     session.UserName,
		UserID:       session.UserID,
		ProviderName: session.ProviderName,
		ClientIP:     ip,
		UserAgent:    userAgent,
		CreatedAt:    session.CreatedAt,
		ExpiresAt:    session.ExpiresAt,
	}); err != nil {
		log.Printf("Warning: failed to persist OIDC session: %v", err)
		// Continue - in-memory session is still valid
	}

	log.Printf("User authenticated: %s (%s)", claims.Email, p.name)
	return session, nil
}

// ValidateSession checks if a session is valid
func (m *Manager) ValidateSession(sessionID string) (*Session, error) {
	// Check in-memory cache first
	m.sessionMu.RLock()
	session, ok := m.sessions[sessionID]
	m.sessionMu.RUnlock()

	if ok {
		if time.Now().After(session.ExpiresAt) {
			m.sessionMu.Lock()
			delete(m.sessions, sessionID)
			m.sessionMu.Unlock()
			return nil, fmt.Errorf("session expired")
		}
		return session, nil
	}

	// Try to load from database (for persistence across restarts)
	dbSession, err := m.store.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found")
	}

	if time.Now().After(dbSession.ExpiresAt) {
		// #nosec G104 — best-effort cleanup of expired OIDC session.
		m.store.DeleteSession(sessionID)
		return nil, fmt.Errorf("session expired")
	}

	// Convert to OIDC session and cache
	session = &Session{
		ID:           dbSession.ID,
		ProviderName: dbSession.ProviderName,
		UserEmail:    dbSession.UserEmail,
		UserName:     dbSession.UserName,
		UserID:       dbSession.UserID,
		CreatedAt:    dbSession.CreatedAt,
		ExpiresAt:    dbSession.ExpiresAt,
	}

	m.sessionMu.Lock()
	m.sessions[sessionID] = session
	m.sessionMu.Unlock()

	return session, nil
}

// CreateSessionCookie creates a session cookie
func (m *Manager) CreateSessionCookie(sessionID string) *http.Cookie {
	return &http.Cookie{
		Name:     "kroxy_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	}
}

// Logout clears a session from memory and database
func (m *Manager) Logout(sessionID string) {
	m.sessionMu.Lock()
	delete(m.sessions, sessionID)
	m.sessionMu.Unlock()

	// #nosec G104 — best-effort persistence cleanup on logout.
	m.store.DeleteSession(sessionID)
}

// Helper functions

func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("FATAL: crypto/rand failed in generateSessionID: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func generateState(redirectURL string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("FATAL: crypto/rand failed in generateState: %v", err)
	}
	state := base64.URLEncoding.EncodeToString(b)
	// Store redirect URL with state (in production, use Redis)
	// For now, we'll use a simple approach
	return state
}
