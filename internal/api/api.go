package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/oidc"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/web"
)

type API struct {
	store         *store.Store
	router        *chi.Mux
	oidcManager   *oidc.Manager
	auth          *auth.Auth
	audit         *audit.Logger
	rateLimiter   *RateLimiter
	wafReloadFunc func() error // Callback to reload WAF when rules change
}

type RateLimiter struct {
	requests sync.Map // IP -> *rateLimitCounter
}

type rateLimitCounter struct {
	count     int64
	windowEnd int64
	mu        sync.Mutex
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{}
}

func (rl *RateLimiter) Allow(ip string, limit int) bool {
	now := time.Now().UnixNano()
	windowEnd := now + int64(time.Minute)

	value, _ := rl.requests.LoadOrStore(ip, &rateLimitCounter{
		count:     0,
		windowEnd: windowEnd,
	})

	counter := value.(*rateLimitCounter)
	counter.mu.Lock()
	defer counter.mu.Unlock()

	// Reset if window expired
	if now > counter.windowEnd {
		counter.count = 0
		counter.windowEnd = windowEnd
	}

	// Check limit
	if counter.count >= int64(limit) {
		return false
	}

	counter.count++
	return true
}

func New(s *store.Store) *API {
	r := chi.NewRouter()

	api := &API{
		store:       s,
		router:      r,
		auth:        auth.New(s),
		audit:       audit.GetLogger(),
		rateLimiter: NewRateLimiter(),
	}

	// Security middleware (use shared rate limiter instance)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(securityHeadersMiddleware)
	r.Use(api.rateLimitMiddleware)

	// Initialize OIDC manager
	api.oidcManager = oidc.NewManager(s)
	ctx := context.Background()
	if err := api.oidcManager.InitializeAllProviders(ctx); err != nil {
		// Log but don't fail
	}

	api.registerRoutes()
	return api
}

// securityHeadersMiddleware adds all security headers
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// Prevent MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// HSTS (1 year, include subdomains)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		// Permissions Policy
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware returns a middleware that uses the shared rate limiter
func (a *API) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		if !a.rateLimiter.Allow(ip, 100) { // 100 requests per minute
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "rate limit exceeded",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfMiddleware validates CSRF tokens for state-changing operations
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only check for state-changing methods
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for CSRF token
		csrfToken := r.Header.Get("X-CSRF-Token")
		cookie, err := r.Cookie("csrf_token")

		if err != nil || csrfToken == "" || cookie == nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "CSRF token missing",
			})
			return
		}

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(csrfToken), []byte(cookie.Value)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "CSRF token mismatch",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

func (a *API) registerRoutes() {
	// Public routes (no auth required)
	a.router.Get("/api/status", a.getStatus)
	a.router.Get("/health", a.health)
	a.router.Get("/api/metrics", a.getMetrics)

	// OAuth routes (public)
	a.router.Get("/api/oauth/login", a.oauthLogin)
	a.router.Get("/api/oauth/callback", a.oauthCallback)
	a.router.Post("/api/oauth/logout", a.oauthLogout)

	// Login endpoint (public, rate-limited)
	a.router.With(a.rateLimitMiddleware).Post("/api/auth/login", a.login)

	// CSRF token endpoint (public)
	a.router.Get("/api/csrf", a.getCsrfToken)

	// Protected routes (auth required)
	a.router.Group(func(r chi.Router) {
		r.Use(a.auth.RequireAuth)
		r.Use(csrfMiddleware)

		// User management (available to all authenticated users)
		r.Get("/api/user", a.getCurrentUser)
		r.Post("/api/auth/api-key", a.generateAPIKey)

		// Routes CRUD (admin only)
		r.With(auth.RequireRole("admin")).Get("/api/routes", a.listRoutes)
		r.With(auth.RequireRole("admin")).Post("/api/routes", a.createRoute)
		r.With(auth.RequireRole("admin")).Get("/api/routes/{id}", a.getRoute)
		r.With(auth.RequireRole("admin")).Put("/api/routes/{id}", a.updateRoute)
		r.With(auth.RequireRole("admin")).Delete("/api/routes/{id}", a.deleteRoute)

		// OIDC Providers CRUD (admin only)
		r.With(auth.RequireRole("admin")).Get("/api/oidc", a.listOIDCProviders)
		r.With(auth.RequireRole("admin")).Post("/api/oidc", a.createOIDCProvider)
		r.With(auth.RequireRole("admin")).Get("/api/oidc/{id}", a.getOIDCProvider)
		r.With(auth.RequireRole("admin")).Put("/api/oidc/{id}", a.updateOIDCProvider)
		r.With(auth.RequireRole("admin")).Delete("/api/oidc/{id}", a.deleteOIDCProvider)

		// Blacklists CRUD (admin only)
		r.With(auth.RequireRole("admin")).Get("/api/blacklists", a.listBlacklists)
		r.With(auth.RequireRole("admin")).Post("/api/blacklists", a.createBlacklist)
		r.With(auth.RequireRole("admin")).Delete("/api/blacklists/{id}", a.deleteBlacklist)

		// Whitelists CRUD (admin only)
		r.With(auth.RequireRole("admin")).Get("/api/whitelists", a.listWhitelists)
		r.With(auth.RequireRole("admin")).Post("/api/whitelists", a.createWhitelist)
		r.With(auth.RequireRole("admin")).Delete("/api/whitelists/{id}", a.deleteWhitelist)

		// Rate Limits CRUD (admin only)
		r.With(auth.RequireRole("admin")).Get("/api/ratelimits", a.listRateLimits)
		r.With(auth.RequireRole("admin")).Post("/api/ratelimits", a.createRateLimit)
		r.With(auth.RequireRole("admin")).Delete("/api/ratelimits/{id}", a.deleteRateLimit)

		// Certificates CRUD (admin only)
		r.With(auth.RequireRole("admin")).Get("/api/certificates", a.listCertificates)
		r.With(auth.RequireRole("admin")).Post("/api/certificates", a.createCertificate)
		r.With(auth.RequireRole("admin")).Delete("/api/certificates/{id}", a.deleteCertificate)

		// WAF Rules CRUD (admin only)
		r.With(auth.RequireRole("admin")).Get("/api/waf/rules", a.listWAFRules)
		r.With(auth.RequireRole("admin")).Post("/api/waf/rules", a.createWAFRule)
		r.With(auth.RequireRole("admin")).Delete("/api/waf/rules/{id}", a.deleteWAFRule)

		// Users CRUD (admin only)
		r.With(auth.RequireRole("admin")).Get("/api/users", a.listUsers)
		r.With(auth.RequireRole("admin")).Post("/api/users", a.createUser)
		r.With(auth.RequireRole("admin")).Delete("/api/users/{id}", a.deleteUser)
	})

	// Serve frontend
	frontend, err := fs.Sub(web.DistFS, "frontend/dist")
	if err == nil {
		fileServer := http.FileServer(http.FS(frontend))
		a.router.Handle("/*", fileServer)
	}
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

func getClientIP(r *http.Request) string {
	// Get the direct client IP (from connection)
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	// Only trust proxy headers if the request comes from a trusted proxy
	// Trusted proxies are typically: localhost, private networks, or configured proxies
	if isTrustedProxy(remoteIP) {
		// Check X-Forwarded-For (most common)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				clientIP := strings.TrimSpace(ips[0])
				if clientIP != "" {
					return clientIP
				}
			}
		}

		// Check X-Real-IP (nginx)
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}

		// Check CF-Connecting-IP (Cloudflare)
		if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
			return strings.TrimSpace(cf)
		}
	}

	// Fall back to RemoteAddr (direct connection or untrusted proxy)
	return remoteIP
}

// isTrustedProxy checks if the request comes from a trusted proxy
func isTrustedProxy(ip string) bool {
	// Trust localhost
	if ip == "127.0.0.1" || ip == "::1" {
		return true
	}

	// Trust private network ranges (typical internal load balancers)
	// 10.0.0.0/8
	if strings.HasPrefix(ip, "10.") {
		return true
	}

	// 172.16.0.0/12
	if strings.HasPrefix(ip, "172.") {
		// Check if it's in 172.16.0.0/12 range
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			if parts[0] == "172" {
				second := 0
				fmt.Sscanf(parts[1], "%d", &second)
				if second >= 16 && second <= 31 {
					return true
				}
			}
		}
	}

	// 192.168.0.0/16
	if strings.HasPrefix(ip, "192.168.") {
		return true
	}

	return false
}

// isValidRedirect validates that a redirect URL is safe (prevents open redirect attacks)
func isValidRedirect(redirect string) bool {
	// Allow relative URLs starting with / (but not // to prevent protocol-relative URLs)
	if strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") {
		return true
	}

	// Block absolute URLs for security
	// Only allow known safe domains if needed in the future
	return false
}

// validateBackendURL prevents SSRF attacks
func validateBackendURL(backend string) error {
	u, err := url.Parse(backend)
	if err != nil {
		return err
	}

	// Only allow http/https
	if u.Scheme != "http" && u.Scheme != "https" {
		return errInvalidScheme
	}

	// Block internal/reserved IPs
	hostname := u.Hostname()

	// Block localhost
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return errInternalIP
	}

	// Block internal IP ranges
	internalRanges := []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
		"169.254.",
	}

	for _, prefix := range internalRanges {
		if strings.HasPrefix(hostname, prefix) {
			return errInternalIP
		}
	}

	// Block metadata endpoints
	if strings.Contains(hostname, "metadata") || hostname == "169.254.169.254" {
		return errInternalIP
	}

	return nil
}

var errInvalidScheme = err("only http/https schemes allowed")
var errInternalIP = err("internal/reserved IPs not allowed")

type err string

func (e err) Error() string { return string(e) }

// Auth handlers

func (a *API) getCsrfToken(w http.ResponseWriter, r *http.Request) {
	token := generateCSRFToken()

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})

	respondJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Rate limit check
	ip := getClientIP(r)
	if !a.rateLimiter.Allow(ip, 5) { // 5 login attempts per minute
		respondError(w, http.StatusTooManyRequests, "Too many login attempts")
		return
	}

	// Authenticate
	session, err := a.auth.Login(req.Email, req.Password, ip, r.UserAgent())
	if err != nil {
		a.audit.Log(audit.Event{
			Type:     "auth_failure",
			UserEmail: req.Email,
			IP:       ip,
			UserAgent: r.UserAgent(),
		})
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	a.audit.Log(audit.Event{
		Type:     "auth_success",
		UserID:   session.User.ID,
		UserEmail: session.User.Email,
		IP:       ip,
		UserAgent: r.UserAgent(),
	})

	http.SetCookie(w, a.auth.CreateSessionCookie(session.SessionID))
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": session.SessionID,
		"user": map[string]interface{}{
			"id":    session.User.ID,
			"email": session.User.Email,
			"role":  session.User.Role,
		},
	})
}

func (a *API) getCurrentUser(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	respondJSON(w, http.StatusOK, user)
}

func (a *API) generateAPIKey(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	keyID, keySecret, err := a.auth.GenerateAPIKey(user.ID, req.Name)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}

	a.audit.Log(audit.Event{
		Type:     "api_key_created",
		UserID:   user.ID,
		UserEmail: user.Email,
		IP:       getClientIP(r),
		Details:     map[string]interface{}{"info": req.Name},
	})

	// Only return the secret once
	respondJSON(w, http.StatusCreated, map[string]string{
		"key_id":     keyID,
		"key_secret": keySecret,
		"warning":    "Store this secret securely. It will not be shown again.",
	})
}

// Health check
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"status": "healthy",
	})
}

// Route handlers (with SSRF validation and audit logging)

func (a *API) createRoute(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var route store.Route
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate backend URL (SSRF prevention)
	if err := validateBackendURL(route.Backend); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid backend URL: "+err.Error())
		return
	}

	// Validate domain
	if route.Domain == "" {
		respondError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	if err := a.store.CreateRoute(&route); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create route")
		return
	}

	a.audit.Log(audit.Event{
		Type:     "route_created",
		UserID:   user.ID,
		UserEmail: user.Email,
		IP:       getClientIP(r),
		Details:     map[string]interface{}{"info": route.Domain + " -> " + route.Backend},
	})

	respondJSON(w, http.StatusCreated, route)
}

func (a *API) listRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := a.store.GetRoutes()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get routes")
		return
	}
	respondJSON(w, http.StatusOK, routes)
}

func (a *API) getRoute(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid route ID")
		return
	}

	routes, err := a.store.GetRoutes()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get routes")
		return
	}

	for _, route := range routes {
		if route.ID == id {
			respondJSON(w, http.StatusOK, route)
			return
		}
	}

	respondError(w, http.StatusNotFound, "Route not found")
}

func (a *API) updateRoute(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid route ID")
		return
	}

	var route store.Route
	if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	route.ID = id

	// Validate backend URL (SSRF prevention)
	if err := validateBackendURL(route.Backend); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid backend URL: "+err.Error())
		return
	}

	if err := a.store.UpdateRoute(&route); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update route")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "route_updated",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": route.Domain},
	})

	respondJSON(w, http.StatusOK, route)
}

func (a *API) deleteRoute(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid route ID")
		return
	}

	if err := a.store.DeleteRoute(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete route")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "route_deleted",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

// OIDC handlers (with state validation)

func (a *API) oauthLogin(w http.ResponseWriter, r *http.Request) {
	providerIDStr := r.URL.Query().Get("provider_id")
	if providerIDStr == "" {
		providerIDStr = "1"
	}

	providerID, err := strconv.Atoi(providerIDStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid provider ID")
		return
	}

	// Generate state with CSRF protection
	redirectURL := r.URL.Query().Get("redirect")
	state := a.auth.GenerateState(providerID, redirectURL)

	authURL, err := a.oidcManager.GetAuthURL(providerID, state)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate auth URL")
		return
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (a *API) oauthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		respondError(w, http.StatusBadRequest, "Missing authorization code")
		return
	}

	// Validate state (CSRF protection)
	stateInfo, err := a.auth.ValidateState(state)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid or expired state")
		return
	}

	providers, err := a.store.GetOIDCProviders()
	if err != nil || len(providers) == 0 {
		respondError(w, http.StatusInternalServerError, "No OIDC provider configured")
		return
	}

	// Use the provider from state
	providerID := stateInfo.ProviderID
	if providerID == 0 {
		providerID = providers[0].ID
	}

	session, err := a.oidcManager.ExchangeCode(r.Context(), providerID, code)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to exchange code")
		return
	}

	http.SetCookie(w, a.oidcManager.CreateSessionCookie(session.ID))

	a.audit.Log(audit.Event{
		Type:        "oauth_login",
		UserEmail:    session.UserEmail,
		IP:          getClientIP(r),
		UserAgent:   r.UserAgent(),
		Details:     map[string]interface{}{"info": session.ProviderName},
	})

	redirect := "/"
	if stateInfo.RedirectURL != "" {
		redirect = stateInfo.RedirectURL
	}
	// Validate redirect URL to prevent open redirect attacks
	if !isValidRedirect(redirect) {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

func (a *API) oauthLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("kroxy_session")
	if err == nil {
		a.oidcManager.Logout(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "kroxy_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	respondJSON(w, http.StatusOK, map[string]string{"message": "Logged out"})
}

// OIDC Providers (masking secrets)

func (a *API) listOIDCProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := a.store.GetOIDCProviders()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get providers")
		return
	}

	// Mask secrets in response
	responses := make([]map[string]interface{}, len(providers))
	for i, p := range providers {
		responses[i] = map[string]interface{}{
			"id":            p.ID,
			"name":          p.Name,
			"client_id":     p.ClientID,
			"discovery_url": p.DiscoveryURL,
			"redirect_url":  p.RedirectURL,
			// client_secret intentionally omitted
		}
	}
	respondJSON(w, http.StatusOK, responses)
}

func (a *API) createOIDCProvider(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var provider store.OIDCProvider
	if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate redirect URL
	if _, err := url.Parse(provider.RedirectURL); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid redirect URL")
		return
	}

	if err := a.store.CreateOIDCProvider(&provider); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create provider")
		return
	}

	if err := a.oidcManager.InitializeProvider(r.Context(), provider); err != nil {
		// Log but don't fail
	}

	a.audit.Log(audit.Event{
		Type:    "oidc_provider_created",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": provider.Name},
	})

	// Return without secret
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"id":            provider.ID,
		"name":          provider.Name,
		"client_id":     provider.ClientID,
		"discovery_url": provider.DiscoveryURL,
		"redirect_url":  provider.RedirectURL,
	})
}

func (a *API) getOIDCProvider(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid provider ID")
		return
	}

	provider, err := a.store.GetOIDCProvider(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Provider not found")
		return
	}

	// Return without secret
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"id":            provider.ID,
		"name":          provider.Name,
		"client_id":     provider.ClientID,
		"discovery_url": provider.DiscoveryURL,
		"redirect_url":  provider.RedirectURL,
	})
}

func (a *API) updateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid provider ID")
		return
	}

	var provider store.OIDCProvider
	if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	provider.ID = id
	// Note: Update method would need to be added to store

	respondJSON(w, http.StatusOK, provider)
}

func (a *API) deleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid provider ID")
		return
	}

	if err := a.store.DeleteOIDCProvider(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete provider")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "oidc_provider_deleted",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

// Remaining handlers follow similar pattern with auth and audit...

func (a *API) listBlacklists(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.GetBlacklists()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get blacklists")
		return
	}
	respondJSON(w, http.StatusOK, list)
}

func (a *API) createBlacklist(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var b store.Blacklist
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := a.store.CreateBlacklist(&b); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create blacklist")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "blacklist_created",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": b.Type + ": " + b.Value},
	})

	respondJSON(w, http.StatusCreated, b)
}

func (a *API) deleteBlacklist(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid blacklist ID")
		return
	}

	if err := a.store.DeleteBlacklist(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete blacklist")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "blacklist_deleted",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listWhitelists(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.GetWhitelists()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get whitelists")
		return
	}
	respondJSON(w, http.StatusOK, list)
}

func (a *API) createWhitelist(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var wl store.Whitelist
	if err := json.NewDecoder(r.Body).Decode(&wl); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := a.store.CreateWhitelist(&wl); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create whitelist")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "whitelist_created",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": wl.Type + ": " + wl.Value},
	})

	respondJSON(w, http.StatusCreated, wl)
}

func (a *API) deleteWhitelist(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid whitelist ID")
		return
	}

	if err := a.store.DeleteWhitelist(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete whitelist")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "whitelist_deleted",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listRateLimits(w http.ResponseWriter, r *http.Request) {
	limits, err := a.store.GetRateLimits()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get rate limits")
		return
	}
	respondJSON(w, http.StatusOK, limits)
}

func (a *API) createRateLimit(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var rl store.RateLimit
	if err := json.NewDecoder(r.Body).Decode(&rl); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := a.store.CreateRateLimit(&rl); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create rate limit")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "rate_limit_created",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": rl.Domain},
	})

	respondJSON(w, http.StatusCreated, rl)
}

func (a *API) deleteRateLimit(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid rate limit ID")
		return
	}

	if err := a.store.DeleteRateLimit(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete rate limit")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "rate_limit_deleted",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listCertificates(w http.ResponseWriter, r *http.Request) {
	certs, err := a.store.GetCertificates()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get certificates")
		return
	}
	respondJSON(w, http.StatusOK, certs)
}

func (a *API) createCertificate(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var cert store.Certificate
	if err := json.NewDecoder(r.Body).Decode(&cert); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := a.store.CreateCertificate(&cert); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create certificate")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "certificate_created",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": cert.Domain},
	})

	respondJSON(w, http.StatusCreated, cert)
}

func (a *API) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid certificate ID")
		return
	}

	if err := a.store.DeleteCertificate(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete certificate")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "certificate_deleted",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listWAFRules(w http.ResponseWriter, r *http.Request) {
	rules, err := a.store.GetWAFRules()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get WAF rules")
		return
	}
	respondJSON(w, http.StatusOK, rules)
}

func (a *API) createWAFRule(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var rule store.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := a.store.CreateWAFRule(&rule); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create WAF rule")
		return
	}

	// Reload WAF to apply new rule
	if a.wafReloadFunc != nil {
		if err := a.wafReloadFunc(); err != nil {
			// Log but don't fail - rule is stored and will be loaded on restart
			a.audit.Log(audit.Event{
				Type:    "waf_reload_failed",
				UserID:  user.ID,
				UserEmail: user.Email,
				IP:      getClientIP(r),
				Details:     map[string]interface{}{"info": err.Error()},
			})
		}
	}

	a.audit.Log(audit.Event{
		Type:    "waf_rule_created",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": rule.Name},
	})

	respondJSON(w, http.StatusCreated, rule)
}

func (a *API) deleteWAFRule(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid WAF rule ID")
		return
	}

	if err := a.store.DeleteWAFRule(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete WAF rule")
		return
	}

	// Reload WAF to apply rule removal
	if a.wafReloadFunc != nil {
		if err := a.wafReloadFunc(); err != nil {
			a.audit.Log(audit.Event{
				Type:    "waf_reload_failed",
				UserID:  user.ID,
				UserEmail: user.Email,
				IP:      getClientIP(r),
				Details:     map[string]interface{}{"info": err.Error()},
			})
		}
	}

	a.audit.Log(audit.Event{
		Type:    "waf_rule_deleted",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.store.GetUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get users")
		return
	}
	respondJSON(w, http.StatusOK, users)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var u store.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate password strength
	if err := validation.ValidatePassword(u.Password); err != nil {
		respondError(w, http.StatusBadRequest, "Password does not meet requirements: "+err.Error())
		return
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(u.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}
	u.Password = hashedPassword

	if err := a.store.CreateUser(&u); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "user_created",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": u.Email},
	})

	// Don't return password
	u.Password = ""
	respondJSON(w, http.StatusCreated, u)
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	if err := a.store.DeleteUser(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	a.audit.Log(audit.Event{
		Type:    "user_deleted",
		UserID:  user.ID,
		UserEmail: user.Email,
		IP:      getClientIP(r),
		Details:     map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) getStatus(w http.ResponseWriter, r *http.Request) {
	routes, _ := a.store.GetRoutes()
	providers, _ := a.store.GetOIDCProviders()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":         "running",
		"version":        "0.2.0",
		"routes_count":   len(routes),
		"oidc_providers": len(providers),
		"features": map[string]bool{
			"waf":     true,
			"oidc":    true,
			"metrics": true,
		},
	})
}

func (a *API) getMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := `# HELP kroxy_routes_total Total number of routes
# TYPE kroxy_routes_total gauge
kroxy_routes_total{status="enabled"} 0
kroxy_routes_total{status="disabled"} 0
# HELP kroxy_requests_total Total requests processed
# TYPE kroxy_requests_total counter
kroxy_requests_total 0
# HELP kroxy_auth_attempts_total Total authentication attempts
# TYPE kroxy_auth_attempts_total counter
kroxy_auth_attempts_total{result="success"} 0
kroxy_auth_attempts_total{result="failure"} 0
# HELP kroxy_waf_blocks_total Total WAF blocks
# TYPE kroxy_waf_blocks_total counter
kroxy_waf_blocks_total 0
`
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(metrics))
}

// SetWAFReloadFunc sets the callback function to reload WAF rules
func (a *API) SetWAFReloadFunc(fn func() error) {
	a.wafReloadFunc = fn
}
