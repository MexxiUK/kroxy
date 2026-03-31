package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"github.com/kroxy/kroxy/internal/store"
)

// Provider represents an OIDC provider configuration
type Provider struct {
	Name         string
	ClientID     string
	ClientSecret string
	DiscoveryURL string
	RedirectURL  string
	Scopes       []string
}

// Manager handles OIDC authentication for multiple providers
type Manager struct {
	store      *store.Store
	providers  map[int]*oauthProvider
	sessions   map[string]*Session
	mu         sync.RWMutex
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

// UserInfo represents user information from OIDC provider
type UserInfo struct {
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Subject  string   `json:"sub"`
	Roles    []string `json:"roles,omitempty"`
	Username string   `json:"preferred_username,omitempty"`
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

// InitializeProvider sets up an OIDC provider from database configuration
func (m *Manager) InitializeProvider(ctx context.Context, p store.OIDCProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Discover OIDC configuration
	discoveryURL := p.DiscoveryURL
	if discoveryURL == "" {
		switch p.Name {
		case "google":
			discoveryURL = "https://accounts.google.com"
		case "github":
			discoveryURL = "https://token.actions.githubusercontent.com"
		default:
			return fmt.Errorf("discovery URL required for custom provider")
		}
	}

	provider, err := oidc.NewProvider(ctx, discoveryURL)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %w", err)
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

	m.providers[p.ID] = &oauthProvider{
		name:        p.Name,
		oauthConfig: oauthConfig,
		verifier:    verifier,
	}

	log.Printf("Initialized OIDC provider: %s", p.Name)
	return nil
}

// InitializeAllProviders loads all providers from database
func (m *Manager) InitializeAllProviders(ctx context.Context) error {
	providers, err := m.store.GetOIDCProviders()
	if err != nil {
		return fmt.Errorf("failed to get OIDC providers: %w", err)
	}

	for _, p := range providers {
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

// ExchangeCode exchanges an authorization code for tokens
func (m *Manager) ExchangeCode(ctx context.Context, providerID int, code string) (*Session, error) {
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
		Email    string `json:"email"`
		Name     string `json:"name"`
		Subject  string `json:"sub"`
		Username string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
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

	m.mu.Lock()
	m.sessions[session.ID] = session
	m.mu.Unlock()

	log.Printf("User authenticated: %s (%s)", claims.Email, p.name)
	return session, nil
}

// ValidateSession checks if a session is valid
func (m *Manager) ValidateSession(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

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
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	}
}

// RequireAuth is middleware that requires authentication
func (m *Manager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("kroxy_session")
		if err != nil {
			m.redirectToAuth(w, r)
			return
		}

		session, err := m.ValidateSession(cookie.Value)
		if err != nil {
			m.redirectToAuth(w, r)
			return
		}

		// Add user info to context
		ctx := context.WithValue(r.Context(), "user", session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Manager) redirectToAuth(w http.ResponseWriter, r *http.Request) {
	// Store original URL for post-login redirect
	state := generateState(r.URL.String())

	// For now, redirect to first available provider
	// TODO: Support multiple providers with selection
	m.mu.RLock()
	var providerID int
	for id := range m.providers {
		providerID = id
		break
	}
	m.mu.RUnlock()

	if providerID == 0 {
		http.Error(w, "No OIDC provider configured", http.StatusInternalServerError)
		return
	}

	authURL, err := m.GetAuthURL(providerID, state)
	if err != nil {
		http.Error(w, "Failed to generate auth URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// Logout clears a session
func (m *Manager) Logout(sessionID string) {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}

// GetSessionFromRequest extracts session from HTTP request
func (m *Manager) GetSessionFromRequest(r *http.Request) *Session {
	cookie, err := r.Cookie("kroxy_session")
	if err != nil {
		return nil
	}

	session, err := m.ValidateSession(cookie.Value)
	if err != nil {
		return nil
	}

	return session
}

// CleanupSessions removes expired sessions
func (m *Manager) CleanupSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, id)
		}
	}
}

// MarshalSessionJSON returns session info as JSON
func (s *Session) MarshalSessionJSON() ([]byte, error) {
	return json.Marshal(struct {
		Email    string   `json:"email"`
		Name     string   `json:"name"`
		Provider string   `json:"provider"`
		Roles    []string `json:"roles,omitempty"`
	}{
		Email:    s.UserEmail,
		Name:     s.UserName,
		Provider: s.ProviderName,
		Roles:    s.Roles,
	})
}

// Helper functions

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateState(redirectURL string) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	// Store redirect URL with state (in production, use Redis)
	// For now, we'll use a simple approach
	return state
}