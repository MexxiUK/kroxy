package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/bot"
	"github.com/kroxy/kroxy/internal/crypto"
	"github.com/kroxy/kroxy/internal/metrics"
	"github.com/kroxy/kroxy/internal/oidc"
	"github.com/kroxy/kroxy/internal/proxy"
	"github.com/kroxy/kroxy/internal/security"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/totp"
	"github.com/kroxy/kroxy/internal/validation"
	"github.com/kroxy/kroxy/internal/version"
	"github.com/kroxy/kroxy/internal/waf"
	"github.com/kroxy/kroxy/web"
)

type API struct {
	store            *store.Store
	router           *chi.Mux
	oidcManager      *oidc.Manager
	auth             *auth.Auth
	audit            *audit.Logger
	rateLimiter      *RateLimiter
	wafReloadFunc    func() error // Callback to reload WAF when rules change
	proxyReloadFunc  func() error // Callback to reload proxy config when routes change
	templates        *TemplateHandler
	productionMode   bool       // Controls security settings like Secure cookie flag
	setupMu          sync.Mutex // Prevents race condition in initial setup (CRIT-005)
	adminAllowedIPs  []*net.IPNet
}

// RateLimiter implements a sliding window rate limiter to prevent burst attacks
// at window boundaries. It uses two half-windows and weighted counting.
type RateLimiter struct {
	requests sync.Map // IP -> *rateLimitCounter
}

type rateLimitCounter struct {
	prevCount   int64 // count from previous window
	currCount   int64 // count in current window
	windowStart int64 // start of current window (UnixNano)
	mu          sync.Mutex
}

const rateLimitWindow = int64(time.Minute)

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{}
}

// Check returns whether the limit would be exceeded without incrementing the counter
func (rl *RateLimiter) Check(ip string, limit int) bool {
	now := time.Now().UnixNano()

	value, _ := rl.requests.LoadOrStore(ip, &rateLimitCounter{
		windowStart: now,
	})

	counter := value.(*rateLimitCounter)
	counter.mu.Lock()
	defer counter.mu.Unlock()

	elapsed := now - counter.windowStart

	if elapsed >= rateLimitWindow {
		if elapsed >= 2*rateLimitWindow {
			counter.prevCount = 0
		} else {
			counter.prevCount = counter.currCount
		}
		counter.currCount = 0
		counter.windowStart = now - (elapsed % rateLimitWindow)
		elapsed = now - counter.windowStart
	}

	weight := float64(rateLimitWindow-elapsed) / float64(rateLimitWindow)
	estimate := int64(float64(counter.prevCount)*weight) + counter.currCount

	return estimate < int64(limit)
}

func (rl *RateLimiter) Allow(ip string, limit int) bool {
	now := time.Now().UnixNano()

	value, _ := rl.requests.LoadOrStore(ip, &rateLimitCounter{
		windowStart: now,
	})

	counter := value.(*rateLimitCounter)
	counter.mu.Lock()
	defer counter.mu.Unlock()

	elapsed := now - counter.windowStart

	// If we've moved past the current window entirely
	if elapsed >= rateLimitWindow {
		// How many full windows have passed?
		if elapsed >= 2*rateLimitWindow {
			// More than 2 windows: reset everything
			counter.prevCount = 0
		} else {
			// Exactly 1 window passed: rotate
			counter.prevCount = counter.currCount
		}
		counter.currCount = 0
		counter.windowStart = now - (elapsed % rateLimitWindow)
		elapsed = now - counter.windowStart
	}

	// Sliding window estimate: weight previous window by remaining fraction
	weight := float64(rateLimitWindow-elapsed) / float64(rateLimitWindow)
	estimate := int64(float64(counter.prevCount)*weight) + counter.currCount

	if estimate >= int64(limit) {
		return false
	}

	counter.currCount++
	return true
}

// cleanupStaleRateLimits removes rate limit entries with zero counts to prevent
// memory leaks when many IPs have touched the API.
func (rl *RateLimiter) cleanupStaleRateLimits() {
	now := time.Now().UnixNano()
	rl.requests.Range(func(key, value interface{}) bool {
		counter := value.(*rateLimitCounter)
		counter.mu.Lock()
		elapsed := now - counter.windowStart
		if elapsed >= 2*rateLimitWindow {
			// More than 2 windows have passed, both counts are effectively zero
			counter.mu.Unlock()
			rl.requests.Delete(key)
		} else {
			counter.mu.Unlock()
		}
		return true
	})
}

func New(s *store.Store) *API {
	r := chi.NewRouter()

	productionMode := os.Getenv("KROXY_PRODUCTION") == "true"

	api := &API{
		store:           s,
		router:          r,
		auth:            auth.New(s),
		audit:           audit.GetLogger(),
		rateLimiter:     NewRateLimiter(),
		productionMode:  productionMode,
		adminAllowedIPs: parseAdminAllowedIPs(),
	}

	// Initialize templates
	tmplHandler, err := NewTemplateHandler()
	if err != nil {
		log.Printf("WARNING: Failed to initialize templates: %v", err)
		// Continue without templates - API will still work
	} else {
		api.templates = tmplHandler
	}

	// Security middleware (use shared rate limiter instance)
	r.Use(requestIDMiddleware)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(securityHeadersMiddleware)
	r.Use(api.rateLimitMiddleware)
	r.Use(adminInputValidation)

	// Initialize OIDC manager
	api.oidcManager = oidc.NewManager(s)
	ctx := context.Background()
	if err := api.oidcManager.InitializeAllProviders(ctx); err != nil {
		log.Printf("Warning: failed to initialize OIDC providers: %v", err)
	}

	api.registerRoutes()
	return api
}

// requestIDContextKey is the context key for request IDs
type requestIDContextKey struct{}

var reqIDKey = requestIDContextKey{}

// requestIDMiddleware generates or propagates a unique request ID for correlation
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				// Non-critical: fall back to timestamp-based ID if crypto fails
				requestID = fmt.Sprintf("ts_%d", time.Now().UnixNano())
			} else {
				requestID = base64.URLEncoding.EncodeToString(b)
			}
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), reqIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(r *http.Request) string {
	if id, ok := r.Context().Value(reqIDKey).(string); ok {
		return id
	}
	return ""
}

// generateCSPNonce generates a cryptographically random nonce for CSP.
// Panics if crypto/rand fails because a predictable nonce is worse than none.
func generateCSPNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("FATAL: crypto/rand failed in generateCSPNonce: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// securityHeadersMiddleware adds all security headers
// adminInputValidation inspects request bodies on the admin API for
// common injection patterns (XSS, SQLi). This is a lightweight check
// that supplements the full Coraza WAF on the proxy port.
var adminInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[\s>]`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)on(?:error|load|click|mouseover|focus|blur)\s*=`),
	regexp.MustCompile(`(?i)<img[^>]+onerror`),
	regexp.MustCompile(`(?i)<svg[^>]+onload`),
	regexp.MustCompile(`(?i)<!\s*(?:DOCTYPE|ENTITY)\s`),
	regexp.MustCompile(`(?i)0x[2722]`),
}

func adminInputValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// WAF rule payloads legitimately contain XSS/SQLi patterns for detection;
		// skip injection scanning on the rules management endpoint.
		if strings.HasPrefix(r.URL.Path, "/api/waf/rules") {
			next.ServeHTTP(w, r)
			return
		}
		// Inspect requests with a body (including chunked transfers where ContentLength == -1)
		if r.Body != nil && r.ContentLength != 0 {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
			if err != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			bodyStr := string(body)
			for _, pattern := range adminInjectionPatterns {
				if pattern.MatchString(bodyStr) {
					log.Printf("ADMIN WAF: blocked injection pattern in %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr) // #nosec G706 — request fields are logged for security audit of blocked requests
					http.Error(w, "Forbidden: request contains disallowed pattern", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate per-request CSP nonce
		nonce := generateCSPNonce()

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
		// Content Security Policy with nonce (no unsafe-inline)
		w.Header().Set("Content-Security-Policy", fmt.Sprintf(
			"default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'nonce-%s'",
			nonce, nonce,
		))
		// Permissions Policy
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Store nonce in request context for use by templates
		ctx := context.WithValue(r.Context(), cspNonceKey, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// cspNonceContextKey is the context key for CSP nonces
type cspNonceContextKey struct{}

var cspNonceKey = cspNonceContextKey{}

// GetCSPNonce retrieves the CSP nonce from the request context
func GetCSPNonce(r *http.Request) string {
	if nonce, ok := r.Context().Value(cspNonceKey).(string); ok {
		return nonce
	}
	return ""
}

// parseAdminAllowedIPs parses KROXY_ADMIN_ALLOWED_IPS into a slice of IP networks.
// Supports comma-separated CIDRs and plain IPs (treated as /32).
func parseAdminAllowedIPs() []*net.IPNet {
	env := os.Getenv("KROXY_ADMIN_ALLOWED_IPS")
	if env == "" {
		return nil
	}

	var networks []*net.IPNet
	for _, raw := range strings.Split(env, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Plain IP: convert to CIDR
		if !strings.Contains(raw, "/") {
			ip := net.ParseIP(raw)
			if ip == nil {
				log.Printf("WARNING: invalid admin allowed IP %q, skipping", raw)
				continue
			}
			if ip.To4() != nil {
				raw = raw + "/32"
			} else {
				raw = raw + "/128"
			}
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			log.Printf("WARNING: invalid admin allowed CIDR %q, skipping", raw)
			continue
		}
		networks = append(networks, network)
	}
	return networks
}

// adminIPAllowlistMiddleware restricts admin routes to configured source IPs.
// If no allowlist is configured, all IPs are permitted (backward compatible).
func (a *API) adminIPAllowlistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No allowlist configured = allow all (backward compatible)
		if len(a.adminAllowedIPs) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		ip := security.GetClientIP(r)
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			log.Printf("ADMIN: blocked request from unparseable IP %q to %s", ip, r.URL.Path)
			respondError(w, http.StatusForbidden, "Access denied")
			return
		}

		for _, network := range a.adminAllowedIPs {
			if network.Contains(parsedIP) {
				next.ServeHTTP(w, r)
				return
			}
		}

		log.Printf("ADMIN: blocked request from IP %s to %s (not in allowlist)", ip, r.URL.Path)
		respondError(w, http.StatusForbidden, "Access denied")
	})
}

// rateLimitMiddleware returns a middleware that uses the shared rate limiter
func (a *API) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := security.GetClientIP(r)
		if !a.rateLimiter.Allow(ip, 100) { // 100 requests per minute
			// Log rate limit trigger
			a.audit.LogRateLimitTrigger(ip, r.Host, 100)
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
	// Static files (no auth required)
	staticFS, _ := fs.Sub(web.StaticFS, "static")
	a.router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Public routes (no auth required)
	a.router.Get("/api/status", a.getStatus)
	a.router.Get("/api/version", a.getVersion)
	a.router.Get("/health", a.health)   // Liveness probe
	a.router.Get("/ready", a.ready)     // Readiness probe
	a.router.Get("/healthz", a.healthz) // Comprehensive health

	// OAuth routes (public)
	a.router.Get("/api/oauth/login", a.oauthLogin)
	a.router.Get("/api/oauth/callback", a.oauthCallback)
	a.router.Post("/api/oauth/logout", a.oauthLogout)

	// Logout endpoint (public — clears cookie regardless)
	a.router.Post("/api/auth/logout", a.oauthLogout)

	// Login endpoint (public, rate-limited)
	a.router.With(a.rateLimitMiddleware).Post("/api/auth/login", a.login)

	// 2FA verification endpoint (public, requires pending 2FA cookie)
	a.router.Post("/api/auth/2fa/verify", a.verify2FA)

	// Certificate permission endpoint (public — called by Caddy internally for on-demand TLS)
	a.router.Get("/api/cert-allowed", a.certAllowed)

	// Setup endpoint (public, only when no users exist)
	a.router.Post("/api/setup", a.setup)

	// CSRF token endpoint (public)
	a.router.Get("/api/csrf", a.getCsrfToken)
	a.router.Post("/.kroxy/challenge/verify", botChallengeVerify)

	// Protected routes (auth required)
	a.router.Group(func(r chi.Router) {
		r.Use(a.auth.RequireAuth)
		r.Use(a.auth.RequireStrongAuth)
		r.Use(csrfMiddleware)

		// User management (available to all authenticated users)
		r.Get("/api/user", a.getCurrentUser)
		r.Put("/api/user/password", a.changePassword)
		r.Delete("/api/user", a.deleteOwnAccount)
		r.Post("/api/user/2fa/setup", a.setup2FA)
		r.Post("/api/user/2fa/enable", a.enable2FA)
		r.Post("/api/user/2fa/disable", a.disable2FA)
		r.Post("/api/auth/api-key", a.generateAPIKey)
		r.Get("/api/user/api-keys", a.listUserAPIKeys)
		r.Delete("/api/user/api-keys/{keyId}", a.deleteUserAPIKey)

		// Routes CRUD (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/routes", a.listRoutes)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/routes", a.createRoute)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/routes/{id}", a.getRoute)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/routes/{id}", a.updateRoute)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/routes/{id}", a.deleteRoute)

		// OIDC Providers CRUD (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/oidc", a.listOIDCProviders)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/oidc", a.createOIDCProvider)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/oidc/{id}", a.getOIDCProvider)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/oidc/{id}", a.updateOIDCProvider)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/oidc/{id}", a.deleteOIDCProvider)

		// Blacklists CRUD (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/blacklists", a.listBlacklists)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/blacklists", a.createBlacklist)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/blacklists/{id}", a.deleteBlacklist)

		// Whitelists CRUD (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/whitelists", a.listWhitelists)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/whitelists", a.createWhitelist)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/whitelists/{id}", a.deleteWhitelist)

		// Rate Limits CRUD (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/ratelimits", a.listRateLimits)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/ratelimits", a.createRateLimit)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/ratelimits/{id}", a.updateRateLimit)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/ratelimits/{id}", a.deleteRateLimit)

		// Certificates CRUD (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/certificates", a.listCertificates)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/certificates", a.createCertificate)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/certificates/{id}", a.deleteCertificate)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/certificates/{id}/provision", a.provisionCertificate)

		// TLS Settings (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/settings/tls", a.getTLSSettings)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/settings/tls", a.updateTLSSettings)

		// General Settings (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/settings/general", a.getGeneralSettings)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/settings/general", a.updateGeneralSettings)

		// Security Settings (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/settings/security", a.getSecuritySettings)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/settings/security", a.updateSecuritySettings)

		// Network Settings (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/settings/network", a.getNetworkSettings)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/settings/network", a.updateNetworkSettings)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/settings/reset", a.resetSettings)

		// WAF Rules CRUD (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/waf/rules", a.listWAFRules)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/waf/rules", a.createWAFRule)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/waf/rules/{id}", a.updateWAFRule)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/waf/rules/{id}", a.deleteWAFRule)

		// WAF Test (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/waf/test", a.testWAF)

		// WAF Paranoia Level (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/waf/paranoia", a.updateWAFParanoia)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/waf/paranoia", a.getWAFParanoia)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/waf/verify-header", a.verifyWAFHeader)

		// Security Events (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/security/events", a.listSecurityEvents)

		// Metrics (admin only) - exposes sensitive system information
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/metrics", a.getMetrics)

		// Dashboard stats (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/dashboard/stats", a.getDashboardStats)

		// Users CRUD (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/users", a.listUsers)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/users", a.createUser)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/users/{id}/role", a.updateUserRole)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/users/{id}", a.deleteUser)

		// Redirect Domains CRUD (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/redirect-domains", a.listRedirectDomains)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/redirect-domains", a.addRedirectDomain)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/redirect-domains/{domain}", a.removeRedirectDomain)

		// Health checks (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/health/backends", a.getHealthStatus)

		// Access logs (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/logs", a.getAccessLogs)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/logs/stats", a.getLogStats)

		// Backup/restore (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/backup", a.exportBackup)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/backup", a.importBackup)

		// Webhooks (admin only)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Get("/api/webhooks", a.listWebhooks)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Post("/api/webhooks", a.createWebhook)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Put("/api/webhooks/{id}", a.updateWebhook)
		r.With(auth.RequireRole("admin"), a.adminIPAllowlistMiddleware).Delete("/api/webhooks/{id}", a.deleteWebhook)
	})

}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	body, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"failed to encode response"}`))
		return
	}
	w.WriteHeader(status)
	w.Write(body)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

// isValidRedirect validates that a redirect URL is safe (prevents open redirect attacks)
// Uses a strict allowlist approach - only relative URLs starting with / are allowed
// Absolute URLs must match the configured allowed domains
func isValidRedirect(redirect string) bool {
	// Empty redirect defaults to home
	if redirect == "" {
		return true
	}

	// Allow relative URLs starting with / (but not // to prevent protocol-relative URLs)
	if strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") {
		// Additional check: no backslash escaping attempts
		if strings.Contains(redirect, "\\") {
			return false
		}
		// No URL-encoded slashes
		if strings.Contains(redirect, "%2f") || strings.Contains(redirect, "%2F") {
			return false
		}
		return true
	}

	// Block all absolute URLs for security
	// Only allow relative URLs - this prevents:
	// - Redirects to external sites
	// - Protocol-relative URLs (//evil.com)
	// - JavaScript URLs (javascript:...)
	// - Data URLs (data:...)
	return false
}

// validateBackendURL has been replaced by validation.ValidateBackendURL
// which provides proper SSRF protection including DNS rebinding mitigation

// Auth handlers

func (a *API) getCsrfToken(w http.ResponseWriter, r *http.Request) {
	token := generateCSRFToken()

	// Secure cookies by default; opt-out via KROXY_INSECURE_COOKIES for local dev
	c := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	}
	if os.Getenv("KROXY_INSECURE_COOKIES") != "true" {
		c.Secure = true
	}
	http.SetCookie(w, c)

	respondJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("FATAL: crypto/rand failed in generateCSRFToken: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// setup handles initial admin account creation (only when no users exist)
func (a *API) setup(w http.ResponseWriter, r *http.Request) {
	// Strict rate limiting: setup should only ever be called once per installation.
	ip := security.GetClientIP(r)
	if !a.rateLimiter.Allow(ip, 3) {
		respondError(w, http.StatusTooManyRequests, "Rate limit exceeded")
		return
	}

	// Prevent race condition where two concurrent requests both see zero users
	// and create multiple admin accounts (CRIT-005)
	a.setupMu.Lock()
	defer a.setupMu.Unlock()

	// Check if setup is allowed (no users exist)
	users, err := a.store.GetUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check setup status")
		return
	}
	if len(users) > 0 {
		respondError(w, http.StatusForbidden, "Setup already completed")
		return
	}

	// Parse request
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate email
	if err := validation.ValidateEmail(req.Email); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate password
	if err := validation.ValidatePassword(req.Password); err != nil {
		respondError(w, http.StatusBadRequest, "Password does not meet requirements: "+err.Error())
		return
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	// Use provided name, or fall back to email
	name := req.Name
	if name == "" {
		name = req.Email
	}

	// Create admin user
	user := &store.User{
		Email:    req.Email,
		Name:     name,
		Password: hashedPassword,
		Role:     "admin", // First user is admin
		Enabled:  true,
	}

	if err := a.store.CreateUser(user); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// Audit log the setup
	a.audit.Log(audit.Event{
		Type:      audit.EventTypeAdminAction,
		Action:    "initial_setup",
		Success:   true,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"admin_email": user.Email},
	})

	// Return success (don't include password)
	user.Password = ""
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"user":    user,
	})
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

	// Authenticate
	ip := security.GetClientIP(r)
	loginResp, err := a.auth.Login(req.Email, req.Password, ip, r.UserAgent())
	if err != nil {
		metrics.IncAuthFailure()
		a.audit.Log(audit.Event{
			Type:      audit.EventTypeAuthFailure,
			UserEmail: req.Email,
			IP:        ip,
			UserAgent: r.UserAgent(),
			RequestID: GetRequestID(r),
			Action:    "login",
			Success:   false,
			Error:     "invalid credentials",
		})
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	metrics.IncAuthSuccess()

	// Check if 2FA is required
	if loginResp.Requires2FA {
		http.SetCookie(w, a.auth.Create2FAPendingCookie(loginResp.PendingID))
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"requires_2fa": true,
			"pending_id":   loginResp.PendingID,
		})
		return
	}

	a.audit.Log(audit.Event{
		Type:      audit.EventTypeAuthLogin,
		UserID:    loginResp.User.ID,
		UserEmail: loginResp.User.Email,
		IP:        ip,
		UserAgent: r.UserAgent(),
		RequestID: GetRequestID(r),
		SessionID: loginResp.SessionID,
		Action:    "login",
		Success:   true,
	})

	http.SetCookie(w, a.auth.CreateSessionCookie(loginResp.SessionID))
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": loginResp.SessionID,
		"user": map[string]interface{}{
			"id":    loginResp.User.ID,
			"email": loginResp.User.Email,
			"role":  loginResp.User.Role,
		},
	})
}

func (a *API) verify2FA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PendingID string `json:"pending_id"`
		Code      string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Also check cookie for pending ID
	if req.PendingID == "" {
		if cookie, err := r.Cookie("kroxy_pending_2fa"); err == nil {
			req.PendingID = cookie.Value
		}
	}

	if req.PendingID == "" || req.Code == "" {
		respondError(w, http.StatusBadRequest, "pending_id and code are required")
		return
	}

	ip := security.GetClientIP(r)
	loginResp, err := a.auth.Verify2FA(req.PendingID, req.Code, ip, r.UserAgent())
	if err != nil {
		a.audit.Log(audit.Event{
			Type:      audit.EventTypeAuthFailure,
			IP:        ip,
			UserAgent: r.UserAgent(),
			RequestID: GetRequestID(r),
			Action:    "2fa_verify",
			Success:   false,
			Error:     err.Error(),
		})
		respondError(w, http.StatusUnauthorized, "Invalid or expired 2FA code")
		return
	}

	a.audit.Log(audit.Event{
		Type:      audit.EventTypeAuthLogin,
		UserID:    loginResp.User.ID,
		UserEmail: loginResp.User.Email,
		IP:        ip,
		UserAgent: r.UserAgent(),
		RequestID: GetRequestID(r),
		SessionID: loginResp.SessionID,
		Action:    "2fa_verify",
		Success:   true,
	})

	// Clear pending 2FA cookie
	c2fa := &http.Cookie{
		Name:     "kroxy_pending_2fa",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	if os.Getenv("KROXY_INSECURE_COOKIES") != "true" {
		c2fa.Secure = true
	}
	http.SetCookie(w, c2fa)

	http.SetCookie(w, a.auth.CreateSessionCookie(loginResp.SessionID))
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": loginResp.SessionID,
		"user": map[string]interface{}{
			"id":    loginResp.User.ID,
			"email": loginResp.User.Email,
			"name":  loginResp.User.Name,
			"role":  loginResp.User.Role,
		},
	})
}

func (a *API) setup2FA(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	// Check if TOTP is already enabled
	dbUser, err := a.store.GetUserByID(user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get user")
		return
	}
	if dbUser.TOTPEnabled {
		respondError(w, http.StatusConflict, "2FA is already enabled")
		return
	}

	// Generate TOTP secret
	secret, uri, err := totp.GenerateSecret("Kroxy", dbUser.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate TOTP secret")
		return
	}

	// Encrypt and store the secret temporarily (not yet enabled)
	encryptedSecret, err := crypto.Encrypt(secret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to encrypt TOTP secret")
		return
	}

	if err := a.store.UpdateTOTPSecret(dbUser.ID, encryptedSecret); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to store TOTP secret")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"secret":    secret,
		"uri":       uri,
		"totp_type": "totp",
		"issuer":    "Kroxy",
		"account":   dbUser.Email,
	})
}

func (a *API) enable2FA(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Code == "" {
		respondError(w, http.StatusBadRequest, "code is required")
		return
	}

	dbUser, err := a.store.GetUserByID(user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get user")
		return
	}

	if dbUser.TOTPSecret == "" {
		respondError(w, http.StatusBadRequest, "No pending TOTP setup. Call /api/user/2fa/setup first")
		return
	}

	// Decrypt secret
	secret, err := crypto.Decrypt(dbUser.TOTPSecret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to decrypt TOTP secret")
		return
	}

	// Verify the code
	if !totp.ValidateCode(secret, req.Code) {
		respondError(w, http.StatusUnauthorized, "Invalid TOTP code")
		return
	}

	// Enable TOTP
	if err := a.store.EnableTOTP(dbUser.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to enable 2FA")
		return
	}

	// Invalidate all sessions to force re-login with 2FA
	a.auth.InvalidateUserSessions(dbUser.ID)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message":      "2FA enabled successfully",
		"totp_enabled": true,
	})
}

func (a *API) disable2FA(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Password == "" || req.Code == "" {
		respondError(w, http.StatusBadRequest, "password and code are required")
		return
	}

	// Verify password
	if err := a.auth.VerifyPassword(user.ID, req.Password); err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid password")
		return
	}

	dbUser, err := a.store.GetUserByID(user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get user")
		return
	}

	if !dbUser.TOTPEnabled {
		respondError(w, http.StatusBadRequest, "2FA is not enabled")
		return
	}

	// Decrypt secret and verify code
	secret, err := crypto.Decrypt(dbUser.TOTPSecret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to decrypt TOTP secret")
		return
	}

	if !totp.ValidateCode(secret, req.Code) {
		respondError(w, http.StatusUnauthorized, "Invalid TOTP code")
		return
	}

	if err := a.store.DisableTOTP(dbUser.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to disable 2FA")
		return
	}

	// Invalidate all sessions so the user must re-authenticate with the new
	// (lower) security posture.
	if err := a.auth.InvalidateUserSessions(dbUser.ID); err != nil {
		log.Printf("Warning: failed to invalidate sessions after 2FA disable: %v", err)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message":      "2FA disabled successfully",
		"totp_enabled": false,
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
		Name      string `json:"name"`
		Duration  string `json:"duration,omitempty"`   // e.g., "24h", "168h", "720h"
		ExpiresAt string `json:"expires_at,omitempty"` // ISO timestamp
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate API key name
	if len(req.Name) > 255 {
		respondError(w, http.StatusBadRequest, "API key name too long (max 255 characters)")
		return
	}
	if strings.ContainsAny(req.Name, "\n\r\u2028\u2029") {
		respondError(w, http.StatusBadRequest, "API key name contains invalid characters")
		return
	}

	// Calculate expiry time
	var expiresAt *time.Time
	if req.Duration != "" {
		duration, err := time.ParseDuration(req.Duration)
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid duration format (e.g., '24h', '168h')")
			return
		}
		if duration <= 0 {
			respondError(w, http.StatusBadRequest, "Duration must be positive")
			return
		}
		const maxDuration = 365 * 24 * time.Hour
		if duration > maxDuration {
			respondError(w, http.StatusBadRequest, "Duration exceeds maximum of 365 days")
			return
		}
		t := time.Now().Add(duration)
		expiresAt = &t
	} else if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid expires_at format (use ISO 8601)")
			return
		}
		expiresAt = &t
	}

	keyID, keySecret, err := a.auth.GenerateAPIKey(user.ID, req.Name, expiresAt)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "api_key_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": req.Name},
	})

	// Only return the secret once
	respondJSON(w, http.StatusCreated, map[string]string{
		"key_id":     keyID,
		"key_secret": keySecret,
		"warning":    "Store this secret securely. It will not be shown again.",
	})
}

func (a *API) listUserAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	keys, err := a.store.GetAPIKeysByUser(user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get API keys")
		return
	}

	// Return keys without secret hashes
	type safeKey struct {
		ID        int        `json:"id"`
		KeyID     string     `json:"key_id"`
		Name      string     `json:"name"`
		CreatedAt time.Time  `json:"created_at"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
		LastUsed  *time.Time `json:"last_used,omitempty"`
		IsExpired bool       `json:"is_expired"`
	}

	now := time.Now()
	result := make([]safeKey, len(keys))
	for i, k := range keys {
		isExpired := k.ExpiresAt != nil && now.After(*k.ExpiresAt)
		result[i] = safeKey{
			ID:        k.ID,
			KeyID:     k.KeyID,
			Name:      k.Name,
			CreatedAt: k.CreatedAt,
			ExpiresAt: k.ExpiresAt,
			LastUsed:  k.LastUsed,
			IsExpired: isExpired,
		}
	}

	respondJSON(w, http.StatusOK, result)
}

func (a *API) deleteUserAPIKey(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	keyID := chi.URLParam(r, "keyId")
	if keyID == "" {
		respondError(w, http.StatusBadRequest, "Key ID is required")
		return
	}

	// Atomically delete only if the key belongs to this user (prevents TOCTOU)
	deleted, err := a.store.DeleteAPIKeyByUser(keyID, user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete API key")
		return
	}
	if !deleted {
		respondError(w, http.StatusNotFound, "API key not found")
		return
	}

	// Invalidate cache after successful database deletion
	a.auth.InvalidateAPIKeyCache(keyID)

	a.audit.Log(audit.Event{
		Type:      audit.EventTypeAuthAPIKeyDelete,
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Action:    "delete_own_api_key",
		Details:   map[string]interface{}{"key_id": keyID},
		Success:   true,
	})

	w.WriteHeader(http.StatusNoContent)
}

// Health check
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"status": "healthy",
	})
}

// Readiness probe - checks if service is ready to accept traffic
func (a *API) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := make(map[string]string)
	allHealthy := true

	// Check database connectivity
	if err := a.store.Ping(ctx); err != nil {
		log.Printf("Readiness check: database unhealthy: %v", err)
		checks["database"] = "unhealthy"
		allHealthy = false
	} else {
		checks["database"] = "healthy"
	}

	status := "ready"
	code := http.StatusOK
	if !allHealthy {
		status = "not_ready"
		code = http.StatusServiceUnavailable
	}

	respondJSON(w, code, map[string]interface{}{
		"status": status,
		"checks": checks,
	})
}

// Comprehensive health check for monitoring
func (a *API) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	checks := make(map[string]string)
	allHealthy := true

	// Database check
	if err := a.store.Ping(ctx); err != nil {
		log.Printf("Healthz check: database unhealthy: %v", err)
		checks["database"] = "unhealthy"
		allHealthy = false
	} else {
		checks["database"] = "healthy"
	}

	// WAF check
	if waf := proxy.GetGlobalWAF(); waf == nil {
		checks["waf"] = "disabled"
	} else {
		checks["waf"] = "enabled"
	}

	status := "healthy"
	code := http.StatusOK
	if !allHealthy {
		status = "unhealthy"
		code = http.StatusServiceUnavailable
	}

	respondJSON(w, code, map[string]interface{}{
		"status": status,
		"checks": checks,
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
	if err := validation.ValidateBackendURL(route.Backend); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid backend URL: "+err.Error())
		return
	}

	// Prevent proxy loops (backend pointing to admin API)
	if err := validation.ValidateNoSelfReference(route.Backend, route.IsAdminRoute); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid backend URL: "+err.Error())
		return
	}

	// Validate domain
	if route.Domain == "" {
		respondError(w, http.StatusBadRequest, "Domain is required")
		return
	}
	if err := validation.ValidateDomain(route.Domain); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid domain: "+err.Error())
		return
	}

	if err := a.store.CreateRoute(&route); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create route")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "route_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": route.Domain + " -> " + route.Backend},
	})

	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			log.Printf("Warning: failed to reload proxy after route creation: %v", err)
		}
	}
	respondJSON(w, http.StatusCreated, route)
}

func (a *API) listRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := a.store.GetRoutes()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get routes")
		return
	}

	// Return paginated response to match frontend expectations
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"routes":     routes,
		"total":      len(routes),
		"totalPages": 1,
		"page":       1,
	})
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

	// Validate domain
	if route.Domain == "" {
		respondError(w, http.StatusBadRequest, "Domain is required")
		return
	}
	if err := validation.ValidateDomain(route.Domain); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid domain: "+err.Error())
		return
	}

	// Validate backend URL (SSRF prevention)
	if err := validation.ValidateBackendURL(route.Backend); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid backend URL: "+err.Error())
		return
	}

	// Prevent proxy loops (backend pointing to admin API)
	if err := validation.ValidateNoSelfReference(route.Backend, route.IsAdminRoute); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid backend URL: "+err.Error())
		return
	}

	if err := a.store.UpdateRoute(&route); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update route")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "route_updated",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": route.Domain},
	})

	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			log.Printf("Warning: failed to reload proxy after route update: %v", err)
		}
	}
	respondJSON(w, http.StatusOK, route)
}

func (a *API) deleteRoute(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid route ID")
		return
	}

	// Check if this is an admin self-route (cannot be deleted)
	adminRoute, _ := a.store.GetAdminRoute()
	if adminRoute != nil && adminRoute.ID == id {
		respondError(w, http.StatusForbidden, "Cannot delete admin self-route")
		return
	}

	if err := a.store.DeleteRoute(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete route")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "route_deleted",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": strconv.Itoa(id)},
	})

	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			log.Printf("Warning: failed to reload proxy after route deletion: %v", err)
		}
	}
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

	// Generate a binding token for this OAuth flow
	// This prevents state token theft attacks - even if an attacker
	// obtains the state parameter, they can't complete the OAuth flow
	// without this browser-bound cookie
	bindingToken := auth.GenerateSecret(32)

	// Set binding cookie (HttpOnly, Secure, SameSite=Strict)
	c := &http.Cookie{
		Name:     "kroxy_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	if os.Getenv("KROXY_INSECURE_COOKIES") != "true" {
		c.Secure = true
	}
	http.SetCookie(w, c)

	// Generate state with session binding
	redirectURL := r.URL.Query().Get("redirect")
	state := a.auth.GenerateState(providerID, redirectURL, bindingToken)

	authURL, err := a.oidcManager.GetAuthURL(providerID, state)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate auth URL")
		return
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect) // #nosec G710 — authURL is generated by server-side OIDC manager, not user-controlled
}

func (a *API) oauthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		respondError(w, http.StatusBadRequest, "Missing authorization code")
		return
	}

	// Get the binding cookie that was set during oauth login
	var bindingToken string
	if bindingCookie, err := r.Cookie("kroxy_oauth_binding"); err == nil {
		bindingToken = bindingCookie.Value
		// Clear the binding cookie (single-use)
		c := &http.Cookie{
			Name:     "kroxy_oauth_binding",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1, // Delete cookie
		}
		if os.Getenv("KROXY_INSECURE_COOKIES") != "true" {
			c.Secure = true
		}
		http.SetCookie(w, c)
	}

	// Validate state (CSRF protection with session binding)
	stateInfo, err := a.auth.ValidateState(state, bindingToken)
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
		Type:      "oauth_login",
		UserEmail: session.UserEmail,
		IP:        security.GetClientIP(r),
		UserAgent: r.UserAgent(),
		Details:   map[string]interface{}{"info": session.ProviderName},
	})

	redirect := "/"
	if stateInfo.RedirectURL != "" {
		redirect = stateInfo.RedirectURL
	}
	// Validate redirect URL to prevent open redirect attacks
	if !isValidRedirect(redirect) {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect) // #nosec G710 — redirect is validated by isValidRedirect() which blocks absolute URLs, protocol-relative URLs, and backslash escaping
}

func (a *API) oauthLogout(w http.ResponseWriter, r *http.Request) {
	ip := security.GetClientIP(r)
	cookie, err := r.Cookie("kroxy_session")
	if err == nil {
		a.audit.Log(audit.Event{
			Type:      audit.EventTypeAuthLogout,
			IP:        ip,
			SessionID: cookie.Value,
			Action:    "logout",
			RequestID: GetRequestID(r),
			Success:   true,
		})
		a.oidcManager.Logout(cookie.Value)
	}

	c := &http.Cookie{
		Name:     "kroxy_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	if os.Getenv("KROXY_INSECURE_COOKIES") != "true" {
		c.Secure = true
	}
	http.SetCookie(w, c)

	if acceptsHTML(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} else {
		respondJSON(w, http.StatusOK, map[string]string{"message": "Logged out"})
	}
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
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
			"issuer":        p.DiscoveryURL,
			"discovery_url": p.DiscoveryURL,
			"redirect_url":  p.RedirectURL,
			"enabled":       true,
			// client_secret intentionally omitted
		}
	}
	respondJSON(w, http.StatusOK, responses)
}

func (a *API) createOIDCProvider(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var req struct {
		Name         string `json:"name"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		DiscoveryURL string `json:"discovery_url"`
		Issuer       string `json:"issuer"`
		RedirectURL  string `json:"redirect_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate OIDC provider configuration
	if err := validation.ValidateOIDCProvider(req.Name, req.DiscoveryURL, req.RedirectURL); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate name is not empty
	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "Provider name is required")
		return
	}

	// Validate client ID and secret are not empty
	if req.ClientID == "" {
		respondError(w, http.StatusBadRequest, "Client ID is required")
		return
	}
	if req.ClientSecret == "" {
		respondError(w, http.StatusBadRequest, "Client secret is required")
		return
	}

	// Map to store model, using issuer as discovery URL if provided
	discoveryURL := req.DiscoveryURL
	if discoveryURL == "" && req.Issuer != "" {
		discoveryURL = req.Issuer
	}

	provider := &store.OIDCProvider{
		Name:         req.Name,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		DiscoveryURL: discoveryURL,
		RedirectURL:  req.RedirectURL,
	}

	if err := a.store.CreateOIDCProvider(provider); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create provider")
		return
	}

	// Use background context so client disconnect doesn't leave the cache stale.
	if err := a.oidcManager.AddProvider(context.Background(), *provider); err != nil {
		log.Printf("Warning: failed to initialize OIDC provider %s: %v", provider.Name, err)
	}

	a.audit.Log(audit.Event{
		Type:      "oidc_provider_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": provider.Name},
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

	var req struct {
		Name         string `json:"name"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		DiscoveryURL string `json:"discovery_url"`
		Issuer       string `json:"issuer"`
		RedirectURL  string `json:"redirect_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate OIDC provider configuration
	discoveryURL := req.DiscoveryURL
	if discoveryURL == "" && req.Issuer != "" {
		discoveryURL = req.Issuer
	}
	if err := validation.ValidateOIDCProvider(req.Name, discoveryURL, req.RedirectURL); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid provider configuration: "+err.Error())
		return
	}

	provider := &store.OIDCProvider{
		ID:           id,
		Name:         req.Name,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		DiscoveryURL: discoveryURL,
		RedirectURL:  req.RedirectURL,
	}
	// Preserve existing secret if not provided in update (prevents secret wipe)
	if provider.ClientSecret == "" {
		existing, err := a.store.GetOIDCProvider(id)
		if err != nil {
			// If we can't decrypt the existing secret, still allow updating other fields
			log.Printf("Warning: failed to retrieve existing provider %d for secret preservation: %v", id, err)
		} else {
			provider.ClientSecret = existing.ClientSecret
		}
	}
	// Persist the update
	if err := a.store.UpdateOIDCProvider(provider); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update OIDC provider")
		return
	}

	// Use background context so client disconnect doesn't leave the cache stale.
	if err := a.oidcManager.UpdateProvider(context.Background(), *provider); err != nil {
		log.Printf("Warning: failed to update OIDC provider cache for %s: %v", provider.Name, err)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"id":            provider.ID,
		"name":          provider.Name,
		"client_id":     provider.ClientID,
		"discovery_url": provider.DiscoveryURL,
		"redirect_url":  provider.RedirectURL,
	})
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

	a.oidcManager.RemoveProvider(id)

	a.audit.Log(audit.Event{
		Type:      "oidc_provider_deleted",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": strconv.Itoa(id)},
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
	respondJSON(w, http.StatusOK, map[string]interface{}{"blacklists": list})
}

func (a *API) createBlacklist(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var b store.Blacklist
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate blacklist type and value
	if err := validation.ValidateBlacklistType(b.Type); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validation.ValidateBlacklistValue(b.Type, b.Value); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := a.store.CreateBlacklist(&b); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create blacklist")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "blacklist_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": b.Type + ": " + b.Value},
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
		Type:      "blacklist_deleted",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listWhitelists(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.GetWhitelists()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get whitelists")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"whitelists": list})
}

func (a *API) createWhitelist(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var wl store.Whitelist
	if err := json.NewDecoder(r.Body).Decode(&wl); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate whitelist entry
	if err := validation.ValidateWhitelist(wl.Type, wl.Value); err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("Invalid whitelist: %v", err))
		return
	}

	if err := a.store.CreateWhitelist(&wl); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create whitelist")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "whitelist_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": wl.Type + ": " + wl.Value},
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
		Type:      "whitelist_deleted",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listRateLimits(w http.ResponseWriter, r *http.Request) {
	limits, err := a.store.GetRateLimits()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get rate limits")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"rules": limits})
}

func (a *API) createRateLimit(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var rl store.RateLimit
	if err := json.NewDecoder(r.Body).Decode(&rl); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate rate limit configuration
	if err := validation.ValidateRateLimit(rl.Domain, rl.RequestsPerMinute, rl.Burst); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid rate limit: "+err.Error())
		return
	}

	if err := a.store.CreateRateLimit(&rl); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create rate limit")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "rate_limit_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": rl.Domain},
	})

	respondJSON(w, http.StatusCreated, rl)
}

func (a *API) updateRateLimit(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid rate limit ID")
		return
	}

	var rl store.RateLimit
	if err := json.NewDecoder(r.Body).Decode(&rl); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	rl.ID = id

	if err := validation.ValidateRateLimit(rl.Domain, rl.RequestsPerMinute, rl.Burst); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid rate limit: "+err.Error())
		return
	}

	if err := a.store.UpdateRateLimit(&rl); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update rate limit")
		return
	}

	a.audit.Log(audit.Event{
		Type:      audit.EventTypeAdminAction,
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Action:    "update_rate_limit",
		Details:   map[string]interface{}{"domain": rl.Domain},
	})

	respondJSON(w, http.StatusOK, rl)
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
		Type:      "rate_limit_deleted",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": strconv.Itoa(id)},
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

	var req struct {
		Domain      string `json:"domain"`
		Type        string `json:"type"`        // "letsencrypt" or "custom"
		Certificate string `json:"certificate"` // PEM content (custom only)
		PrivateKey  string `json:"private_key"` // PEM content (custom only)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Domain == "" {
		respondError(w, http.StatusBadRequest, "Domain is required")
		return
	}
	if err := validation.ValidateDomain(req.Domain); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid domain: "+err.Error())
		return
	}
	if req.Type != "letsencrypt" && req.Type != "custom" {
		respondError(w, http.StatusBadRequest, "Type must be 'letsencrypt' or 'custom'")
		return
	}

	cert := store.Certificate{
		Domain:    req.Domain,
		Type:      req.Type,
		AutoRenew: req.Type == "letsencrypt",
		Status:    "pending",
	}

	if req.Type == "custom" {
		cert.Status = "active"
		if req.Certificate == "" || req.PrivateKey == "" {
			respondError(w, http.StatusBadRequest, "Certificate and private key PEM content are required for custom certificates")
			return
		}
		// Derive data directory from database path
		dataDir := filepath.Dir(a.store.DatabasePath())
		certsDir := filepath.Join(dataDir, "certs")
		if err := os.MkdirAll(certsDir, 0700); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to create certs directory")
			return
		}

		safeName := strings.ReplaceAll(req.Domain, "/", "_")
		safeName = strings.ReplaceAll(safeName, "..", "_")
		certPath := filepath.Join(certsDir, safeName+".crt")
		keyPath := filepath.Join(certsDir, safeName+".key")

		if err := os.WriteFile(certPath, []byte(req.Certificate), 0600); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to write certificate file")
			return
		}
		if err := os.WriteFile(keyPath, []byte(req.PrivateKey), 0600); err != nil {
			os.Remove(certPath)
			respondError(w, http.StatusInternalServerError, "Failed to write private key file")
			return
		}

		cert.CertPath = certPath
		cert.KeyPath = keyPath
		cert.Issuer = "Custom"
	} else {
		cert.Issuer = "Let's Encrypt"
	}

	if err := a.store.CreateCertificate(&cert); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create certificate")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "certificate_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"domain": cert.Domain, "type": cert.Type},
	})

	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			log.Printf("Warning: failed to reload proxy after certificate creation: %v", err)
		}
	}

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
		Type:      "certificate_deleted",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": strconv.Itoa(id)},
	})

	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			log.Printf("Warning: failed to reload proxy after certificate deletion: %v", err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) provisionCertificate(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid certificate ID")
		return
	}

	cert, err := a.store.GetCertificateByID(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Certificate not found")
		return
	}

	if cert.Type != "letsencrypt" {
		respondError(w, http.StatusBadRequest, "Only Let's Encrypt certificates can be re-provisioned")
		return
	}

	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to trigger provisioning")
			return
		}
	}

	// Poll Caddy's certificate directory for up to 10 seconds to detect if provisioning succeeded
	caddyCertDir := filepath.Join("/home/kroxy", ".local", "share", "caddy", "certificates")
	provisioned := false
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		domainDir := findCertDir(caddyCertDir, cert.Domain)
		if domainDir != "" {
			certFile := filepath.Join(domainDir, cert.Domain+".crt")
			if _, err := os.Stat(certFile); err == nil {
				provisioned = true
				break
			}
		}
	}

	if provisioned {
		a.store.UpdateCertificateStatus(id, "active")
	} else {
		a.store.UpdateCertificateStatus(id, "failed")
	}

	a.audit.Log(audit.Event{
		Type:      "certificate_provision",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"domain": cert.Domain, "success": provisioned},
	})

	if provisioned {
		respondJSON(w, http.StatusOK, map[string]string{"message": "Certificate provisioned successfully for " + cert.Domain})
	} else {
		respondJSON(w, http.StatusOK, map[string]string{"message": "Provisioning initiated for " + cert.Domain + ". Certificate may take a few minutes to be issued. Check back later."})
	}
}

func (a *API) certAllowed(w http.ResponseWriter, r *http.Request) {
	// Rate-limit this public endpoint to prevent domain enumeration (LOW-009).
	ip := security.GetClientIP(r)
	if !a.rateLimiter.Allow(ip, 10) {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Timing equalization: always fetch both routes and certs before deciding,
	// so the response time is similar whether the domain exists or not.
	found := false
	routes, err := a.store.GetRoutes()
	if err == nil {
		for _, route := range routes {
			if route.Domain == domain && route.Enabled {
				found = true
				break
			}
		}
	}
	// Also check certificate records — LE certs may exist before a route
	if !found {
		certs, err := a.store.GetCertificates()
		if err == nil {
			for _, cert := range certs {
				if cert.Domain == domain && cert.Type == "letsencrypt" {
					found = true
					break
				}
			}
		}
	}
	if found {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}

func (a *API) listWAFRules(w http.ResponseWriter, r *http.Request) {
	// Support filtering by route_id or global-only
	query := r.URL.Query()

	if routeIDStr := query.Get("route_id"); routeIDStr != "" {
		routeID, err := strconv.Atoi(routeIDStr)
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid route_id parameter")
			return
		}
		rules, err := a.store.GetWAFRulesForRoute(routeID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to get WAF rules")
			return
		}
		respondJSON(w, http.StatusOK, rules)
		return
	}

	if query.Get("global") == "true" {
		rules, err := a.store.GetGlobalWAFRules()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to get WAF rules")
			return
		}
		respondJSON(w, http.StatusOK, rules)
		return
	}

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

	// Validate WAF rule name
	if err := validation.ValidateWAFRuleName(rule.Name); err != nil {
		log.Printf("WAF rule name validation failed for %q: %v", rule.Name, err)
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Validate WAF rule syntax
	if err := validation.ValidateWAFRule(rule.Rule); err != nil {
		log.Printf("WAF rule validation failed for %q (rule: %.100s): %v", rule.Name, rule.Rule, err)
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Validate WAF exclusions (comma-separated numeric rule IDs only)
	if err := validation.ValidateWAFExclusions(rule.Exclusions); err != nil {
		log.Printf("WAF exclusions validation failed for %q: %v", rule.Name, err)
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate WAF exclusions (comma-separated numeric rule IDs only)
	if err := validation.ValidateWAFExclusions(rule.Exclusions); err != nil {
		log.Printf("WAF exclusions validation failed for %q: %v", rule.Name, err)
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate route_id if specified
	if rule.RouteID != nil {
		routes, err := a.store.GetRoutes()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to validate route")
			return
		}
		found := false
		for _, rt := range routes {
			if rt.ID == *rule.RouteID {
				found = true
				break
			}
		}
		if !found {
			respondError(w, http.StatusBadRequest, "Route not found")
			return
		}
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
				Type:      "waf_reload_failed",
				UserID:    user.ID,
				UserEmail: user.Email,
				IP:        security.GetClientIP(r),
				Details:   map[string]interface{}{"info": err.Error()},
			})
		}
	}

	a.audit.Log(audit.Event{
		Type:      "waf_rule_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": rule.Name},
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
				Type:      "waf_reload_failed",
				UserID:    user.ID,
				UserEmail: user.Email,
				IP:        security.GetClientIP(r),
				Details:   map[string]interface{}{"info": err.Error()},
			})
		}
	}

	a.audit.Log(audit.Event{
		Type:      "waf_rule_deleted",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": strconv.Itoa(id)},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) updateWAFRule(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid WAF rule ID")
		return
	}

	var rule store.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	rule.ID = id

	if rule.Name != "" {
		if err := validation.ValidateWAFRuleName(rule.Name); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if rule.Rule != "" {
		if err := validation.ValidateWAFRule(rule.Rule); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if rule.Exclusions != "" {
		if err := validation.ValidateWAFExclusions(rule.Exclusions); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if rule.RouteID != nil {
		routes, err := a.store.GetRoutes()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to validate route")
			return
		}
		found := false
		for _, rt := range routes {
			if rt.ID == *rule.RouteID {
				found = true
				break
			}
		}
		if !found {
			respondError(w, http.StatusBadRequest, "Route not found")
			return
		}
	}
	if rule.Exclusions != "" {
		if err := validation.ValidateWAFExclusions(rule.Exclusions); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if err := a.store.UpdateWAFRule(&rule); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update WAF rule")
		return
	}

	if a.wafReloadFunc != nil {
		if err := a.wafReloadFunc(); err != nil {
			a.audit.Log(audit.Event{
				Type:      "waf_reload_failed",
				UserID:    user.ID,
				UserEmail: user.Email,
				IP:        security.GetClientIP(r),
				Details:   map[string]interface{}{"info": err.Error()},
			})
		}
	}

	a.audit.Log(audit.Event{
		Type:      "waf_rule_updated",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": rule.Name},
	})

	respondJSON(w, http.StatusOK, rule)
}

func (a *API) testWAF(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RouteID *int `json:"route_id"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}

	var wafInstance *waf.WAF
	if req.RouteID != nil {
		wafInstance = proxy.GetRouteWAF(*req.RouteID)
	} else {
		wafInstance = proxy.GetGlobalWAF()
	}

	if wafInstance == nil {
		respondError(w, http.StatusNotFound, "WAF engine not found")
		return
	}

	result := waf.RunTestSuite(wafInstance)
	if req.RouteID != nil {
		result.Engine = fmt.Sprintf("route:%d", *req.RouteID)
	}

	respondJSON(w, http.StatusOK, result)
}

func (a *API) getWAFParanoia(w http.ResponseWriter, r *http.Request) {
	level := 1
	if a.store != nil {
		val, err := a.store.GetSetting("waf_paranoia_level")
		if err == nil && val != "" {
			if n, err := strconv.Atoi(val); err == nil && n >= 1 && n <= 3 {
				level = n
			}
		}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"level": level})
}

func (a *API) updateWAFParanoia(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Level int `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Level < 1 || req.Level > 3 {
		respondError(w, http.StatusBadRequest, "Paranoia level must be 1, 2, or 3")
		return
	}

	if err := a.store.SetSetting("waf_paranoia_level", strconv.Itoa(req.Level)); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to save paranoia level")
		return
	}

	// Reload WAF with new paranoia level
	if a.wafReloadFunc != nil {
		if err := a.wafReloadFunc(); err != nil {
			log.Printf("Warning: WAF reload after paranoia level change failed: %v", err)
		}
	}

	user := auth.GetUserFromContext(r.Context())
	a.audit.Log(audit.Event{
		Type:      "waf_paranoia_changed",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"level": req.Level},
	})

	respondJSON(w, http.StatusOK, map[string]interface{}{"level": req.Level})
}

func (a *API) listSecurityEvents(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	var events []store.SecurityEvent
	var err error
	routeIDStr := r.URL.Query().Get("route_id")

	if routeIDStr != "" {
		routeID, e := strconv.Atoi(routeIDStr)
		if e != nil {
			respondError(w, http.StatusBadRequest, "Invalid route_id")
			return
		}
		events, err = a.store.GetSecurityEventsForRoute(routeID, limit, offset)
	} else {
		events, err = a.store.GetSecurityEvents(limit, offset)
	}

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to load security events")
		return
	}

	if events == nil {
		events = []store.SecurityEvent{}
	}

	count, _ := a.store.GetSecurityEventCount()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"total":  count,
	})
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.store.GetUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get users")
		return
	}
	for i := range users {
		users[i].Password = ""
	}
	respondJSON(w, http.StatusOK, users)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate email format
	if err := validation.ValidateEmail(req.Email); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Validate password strength
	if err := validation.ValidatePassword(req.Password); err != nil {
		respondError(w, http.StatusBadRequest, "Password does not meet requirements: "+err.Error())
		return
	}

	// Default name to email if not provided
	name := req.Name
	if name == "" {
		name = req.Email
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	u := &store.User{
		Email:    req.Email,
		Name:     name,
		Password: hashedPassword,
		Role:     "user",
		Enabled:  true,
	}

	if err := a.store.CreateUser(u); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "user_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"info": u.Email},
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

	// Prevent self-deletion
	if user.ID == id {
		respondError(w, http.StatusBadRequest, "Cannot delete your own account")
		return
	}

	// Invalidate all sessions for the user being deleted
	if err := a.auth.InvalidateUserSessions(id); err != nil {
		log.Printf("Warning: failed to invalidate sessions for deleted user %d: %v", id, err)
	}

	if err := a.store.DeleteUser(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	// Invalidate role cache for deleted user
	a.auth.InvalidateRoleCache(id)

	a.audit.Log(audit.Event{
		Type:      "user_deleted",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"deleted_user_id": id},
	})

	w.WriteHeader(http.StatusNoContent)
}

type UpdateRoleRequest struct {
	Role string `json:"role"`
}

func (a *API) updateUserRole(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate role
	validRoles := map[string]bool{"admin": true, "user": true}
	if !validRoles[req.Role] {
		respondError(w, http.StatusBadRequest, "Invalid role. Must be 'admin' or 'user'")
		return
	}

	// Prevent self-demotion (admin cannot demote themselves)
	if user.ID == id && req.Role != "admin" {
		respondError(w, http.StatusBadRequest, "Cannot demote yourself from admin role")
		return
	}

	// Update role in database
	if err := a.store.UpdateUserRole(id, req.Role); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update role")
		return
	}

	// Invalidate role cache for this user
	a.auth.InvalidateRoleCache(id)

	// Invalidate all API keys for this user (cached roles must be refreshed)
	a.auth.InvalidateUserAPIKeys(id)

	// Invalidate all sessions for this user (they must re-authenticate)
	if err := a.auth.InvalidateUserSessions(id); err != nil {
		log.Printf("Warning: failed to invalidate sessions after role change: %v", err)
	}

	a.audit.Log(audit.Event{
		Type:      "role_updated",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"target_user_id": id, "new_role": req.Role},
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "role updated"})
}

func (a *API) getStatus(w http.ResponseWriter, r *http.Request) {
	// Only expose minimal info publicly to prevent reconnaissance
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status": "running",
	})
}

func (a *API) getVersion(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"version": version.Version,
	})
}

func (a *API) getMetrics(w http.ResponseWriter, r *http.Request) {
	// Query real counts from the store
	enabledRoutes, disabledRoutes := 0, 0
	if routes, err := a.store.GetRoutes(); err == nil {
		for _, route := range routes {
			if route.Enabled {
				enabledRoutes++
			} else {
				disabledRoutes++
			}
		}
	}

	blockedCount, _ := a.store.GetBlockedSecurityEventCount()

	metricsOut := fmt.Sprintf(`# HELP kroxy_routes_total Total number of routes
# TYPE kroxy_routes_total gauge
kroxy_routes_total{status="enabled"} %d
kroxy_routes_total{status="disabled"} %d
# HELP kroxy_requests_total Total requests processed
# TYPE kroxy_requests_total counter
kroxy_requests_total %d
# HELP kroxy_auth_attempts_total Total authentication attempts
# TYPE kroxy_auth_attempts_total counter
kroxy_auth_attempts_total{result="success"} %d
kroxy_auth_attempts_total{result="failure"} %d
# HELP kroxy_waf_blocks_total Total WAF blocks
# TYPE kroxy_waf_blocks_total counter
kroxy_waf_blocks_total %d
`, enabledRoutes, disabledRoutes, metrics.RequestsTotal(), metrics.AuthSuccessTotal(), metrics.AuthFailureTotal(), blockedCount)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(metricsOut))
}

// SetWAFReloadFunc sets the callback function to reload WAF rules
func (a *API) SetWAFReloadFunc(fn func() error) {
	a.wafReloadFunc = fn
}

// SetProxyReloadFunc sets the callback function to reload proxy config
func (a *API) SetProxyReloadFunc(fn func() error) {
	a.proxyReloadFunc = fn
}

func (a *API) listRedirectDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := a.store.GetRedirectDomains()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get redirect domains")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"domains": domains})
}

func (a *API) addRedirectDomain(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate domain format
	req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
	if req.Domain == "" {
		respondError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	// Basic domain validation
	if strings.Contains(req.Domain, "/") || strings.Contains(req.Domain, ":") {
		respondError(w, http.StatusBadRequest, "Domain should not include scheme or port")
		return
	}

	if err := a.store.AddRedirectDomain(req.Domain); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to add redirect domain")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "redirect_domain_added",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"domain": req.Domain},
	})

	respondJSON(w, http.StatusCreated, map[string]string{"domain": req.Domain})
}

func (a *API) removeRedirectDomain(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	domain := chi.URLParam(r, "domain")
	if domain == "" {
		respondError(w, http.StatusBadRequest, "Domain is required")
		return
	}

	if err := a.store.RemoveRedirectDomain(domain); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to remove redirect domain")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "redirect_domain_removed",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"domain": domain},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) verifyWAFHeader(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HeaderValue string `json:"header_value"`
		Host        string `json:"host"`
		Method      string `json:"method"`
		Path        string `json:"path"`
		RouteID     int    `json:"route_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.HeaderValue == "" {
		respondError(w, http.StatusBadRequest, "header_value is required")
		return
	}

	err := crypto.VerifyWAFHeader(
		req.HeaderValue,
		req.Host,
		req.Method,
		req.Path,
		req.RouteID,
		crypto.WAFHeaderTimestampMaxSkew,
	)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"valid": err == nil,
		"error": func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(),
	})
}

// Settings API handlers

func (a *API) getTLSSettings(w http.ResponseWriter, r *http.Request) {
	settings := map[string]interface{}{
		"tls_enabled":     a.store.GetSettingDefault("tls_enabled", "false"),
		"tls_auto_https":  a.store.GetSettingDefault("tls_auto_https", "false"),
		"tls_acme_email":  a.store.GetSettingDefault("tls_acme_email", ""),
		"tls_min_version": a.store.GetSettingDefault("tls_min_version", "1.2"),
		"hsts_enabled":    a.store.GetSettingDefault("hsts_enabled", "true"),
		"redirect_http":   a.store.GetSettingDefault("redirect_http", "true"),
	}
	respondJSON(w, http.StatusOK, settings)
}

func (a *API) updateTLSSettings(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var req struct {
		TLSMinVersion string `json:"tls_min_version"`
		HSTSEnabled   *bool  `json:"hsts_enabled"`
		RedirectHTTP  *bool  `json:"redirect_http"`
		AutoHTTPS     *bool  `json:"tls_auto_https"`
		ACMEEmail     string `json:"tls_acme_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.TLSMinVersion != "" {
		if req.TLSMinVersion != "1.2" && req.TLSMinVersion != "1.3" {
			respondError(w, http.StatusBadRequest, "tls_min_version must be 1.2 or 1.3")
			return
		}
		if err := a.store.SetSetting("tls_min_version", req.TLSMinVersion); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save TLS min version")
			return
		}
	}
	if req.HSTSEnabled != nil {
		if err := a.store.SetSetting("hsts_enabled", strconv.FormatBool(*req.HSTSEnabled)); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save HSTS setting")
			return
		}
	}
	if req.RedirectHTTP != nil {
		if err := a.store.SetSetting("redirect_http", strconv.FormatBool(*req.RedirectHTTP)); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save redirect setting")
			return
		}
	}
	if req.AutoHTTPS != nil {
		if err := a.store.SetSetting("tls_auto_https", strconv.FormatBool(*req.AutoHTTPS)); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save auto HTTPS setting")
			return
		}
	}
	if req.ACMEEmail != "" {
		if err := a.store.SetSetting("tls_acme_email", req.ACMEEmail); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save ACME email")
			return
		}
	}

	a.audit.Log(audit.Event{
		Type:      "settings_update",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Action:    "update_tls_settings",
		Details:   map[string]interface{}{"tls_min_version": req.TLSMinVersion},
		Success:   true,
	})

	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			log.Printf("Warning: failed to reload proxy after TLS settings update: %v", err)
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) getGeneralSettings(w http.ResponseWriter, r *http.Request) {
	settings := map[string]interface{}{
		"app_name":    a.store.GetSettingDefault("app_name", "Kroxy"),
		"admin_email": a.store.GetSettingDefault("admin_email", ""),
		"log_level":   a.store.GetSettingDefault("log_level", "info"),
	}
	respondJSON(w, http.StatusOK, settings)
}

func (a *API) updateGeneralSettings(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var req struct {
		AppName    string `json:"app_name"`
		AdminEmail string `json:"admin_email"`
		LogLevel   string `json:"log_level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.AppName != "" {
		if err := a.store.SetSetting("app_name", req.AppName); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save app name")
			return
		}
	}
	if req.AdminEmail != "" {
		if err := a.store.SetSetting("admin_email", req.AdminEmail); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save admin email")
			return
		}
	}
	if req.LogLevel != "" {
		validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
		if !validLevels[req.LogLevel] {
			respondError(w, http.StatusBadRequest, "Invalid log level")
			return
		}
		if err := a.store.SetSetting("log_level", req.LogLevel); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save log level")
			return
		}
	}

	a.audit.Log(audit.Event{
		Type:      "settings_update",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Action:    "update_general_settings",
		Success:   true,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) getSecuritySettings(w http.ResponseWriter, r *http.Request) {
	settings := map[string]interface{}{
		"session_duration":   a.store.GetSettingDefault("session_duration", "24h"),
		"two_factor_enabled": a.store.GetSettingDefault("two_factor_enabled", "false"),
		"audit_logging":      a.store.GetSettingDefault("audit_logging", "true"),
	}
	respondJSON(w, http.StatusOK, settings)
}

func (a *API) updateSecuritySettings(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var req struct {
		SessionDuration  string `json:"session_duration"`
		TwoFactorEnabled *bool  `json:"two_factor_enabled"`
		AuditLogging     *bool  `json:"audit_logging"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SessionDuration != "" {
		if err := a.store.SetSetting("session_duration", req.SessionDuration); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save session duration")
			return
		}
	}
	if req.TwoFactorEnabled != nil {
		if err := a.store.SetSetting("two_factor_enabled", strconv.FormatBool(*req.TwoFactorEnabled)); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save 2FA setting")
			return
		}
	}
	if req.AuditLogging != nil {
		if err := a.store.SetSetting("audit_logging", strconv.FormatBool(*req.AuditLogging)); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save audit logging setting")
			return
		}
	}

	a.audit.Log(audit.Event{
		Type:      "settings_update",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Action:    "update_security_settings",
		Success:   true,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) getNetworkSettings(w http.ResponseWriter, r *http.Request) {
	settings := map[string]interface{}{
		"listen_port":     a.store.GetSettingDefault("listen_port", "80"),
		"https_port":      a.store.GetSettingDefault("https_port", "443"),
		"max_connections": a.store.GetSettingDefault("max_connections", "1000"),
		"request_timeout": a.store.GetSettingDefault("request_timeout", "30s"),
	}
	respondJSON(w, http.StatusOK, settings)
}

func (a *API) updateNetworkSettings(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var req struct {
		ListenPort     string `json:"listen_port"`
		HTTPSPort      string `json:"https_port"`
		MaxConnections int    `json:"max_connections"`
		RequestTimeout string `json:"request_timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.ListenPort != "" {
		if err := a.store.SetSetting("listen_port", req.ListenPort); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save listen port")
			return
		}
	}
	if req.HTTPSPort != "" {
		if err := a.store.SetSetting("https_port", req.HTTPSPort); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save HTTPS port")
			return
		}
	}
	if req.MaxConnections > 0 {
		if err := a.store.SetSetting("max_connections", strconv.Itoa(req.MaxConnections)); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save max connections")
			return
		}
	}
	if req.RequestTimeout != "" {
		if err := a.store.SetSetting("request_timeout", req.RequestTimeout); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to save request timeout")
			return
		}
	}

	a.audit.Log(audit.Event{
		Type:      "settings_update",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Action:    "update_network_settings",
		Success:   true,
	})

	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			log.Printf("Warning: failed to reload proxy after network settings update: %v", err)
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Reset all settings to defaults
func (a *API) resetSettings(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	// Delete all settings from database
	if err := a.store.ClearSettings(); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to reset settings")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "settings_update",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Action:    "reset_all_settings",
		Success:   true,
	})

	// Reload proxy to apply default settings
	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			log.Printf("Warning: failed to reload proxy after settings reset: %v", err)
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Dashboard stats endpoint - returns real JSON data for the dashboard
func (a *API) getDashboardStats(w http.ResponseWriter, r *http.Request) {
	routes, err := a.store.GetRoutes()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get routes")
		return
	}

	enabledRoutes := 0
	disabledRoutes := 0
	for _, route := range routes {
		if route.Enabled {
			enabledRoutes++
		} else {
			disabledRoutes++
		}
	}

	// Get security events count
	blockedCount, _ := a.store.GetBlockedSecurityEventCount()

	// Get total security events count
	totalEvents, _ := a.store.GetSecurityEventCount()

	// Get recent security events
	recentEvents, _ := a.store.GetSecurityEvents(5, 0)
	eventsOut := make([]map[string]interface{}, 0, len(recentEvents))
	for _, ev := range recentEvents {
		details := ev.RuleName
		if details == "" {
			details = ev.URI
		}
		evType := ev.EventType
		if evType == "" {
			evType = ev.Action
		}
		eventsOut = append(eventsOut, map[string]interface{}{
			"time":    ev.CreatedAt.Format("2006-01-02 15:04"),
			"type":    evType,
			"details": details,
			"ip":      ev.ClientIP,
		})
	}

	// Check certificate expiry
	certs, _ := a.store.GetCertificates()
	expiringCertsCount := 0
	var expiringCerts []map[string]interface{}
	now := time.Now()
	for _, cert := range certs {
		daysLeft := int(cert.ExpiresAt.Sub(now).Hours() / 24)
		if daysLeft <= 30 {
			expiringCertsCount++
			expiringCerts = append(expiringCerts, map[string]interface{}{
				"domain":   cert.Domain,
				"daysLeft": daysLeft,
			})
		}
	}

	// Build top routes list (enabled first, then alphabetically)
	topRoutes := make([]map[string]interface{}, 0, len(routes))
	for _, route := range routes {
		status := "healthy"
		if !route.Enabled {
			status = "disabled"
		}
		topRoutes = append(topRoutes, map[string]interface{}{
			"domain": route.Domain,
			"status": status,
		})
	}

	stats := map[string]interface{}{
		"total_routes":    len(routes),
		"enabled_routes":  enabledRoutes,
		"disabled_routes": disabledRoutes,
		"requests_total":  metrics.RequestsTotal(),
		"waf_blocks":      blockedCount,
		"security_events": totalEvents,
		"expiring_certs":  expiringCertsCount,
		"recent_events":   eventsOut,
		"expiringCerts":   expiringCerts,
		"topRoutes":       topRoutes,
	}

	respondJSON(w, http.StatusOK, stats)
}

// Change password for the authenticated user
func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		respondError(w, http.StatusBadRequest, "Both current and new passwords are required")
		return
	}

	// Enforce password strength policy
	if err := validation.ValidatePassword(req.NewPassword); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify current password
	if err := a.auth.ChangePassword(user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		log.Printf("AUDIT: password change failed for user_id=%d: %v", user.ID, err)
		respondError(w, http.StatusBadRequest, "Password change failed")
		return
	}

	// Invalidate all sessions for this user (force re-login)
	if err := a.auth.InvalidateUserSessions(user.ID); err != nil {
		log.Printf("Warning: failed to invalidate sessions after password change: %v", err)
	}

	a.audit.Log(audit.Event{
		Type:      "password_change",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Action:    "change_password",
		Success:   true,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}

// Delete own account
func (a *API) deleteOwnAccount(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Password == "" {
		respondError(w, http.StatusBadRequest, "Password confirmation required")
		return
	}

	// Verify password
	if err := a.auth.VerifyPassword(user.ID, req.Password); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid password")
		return
	}

	// Prevent last admin from deleting themselves
	adminCount, err := a.store.GetAdminCount()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to check admin count")
		return
	}
	if user.Role == "admin" && adminCount <= 1 {
		respondError(w, http.StatusBadRequest, "Cannot delete the last admin account")
		return
	}

	// Invalidate sessions
	if err := a.auth.InvalidateUserSessions(user.ID); err != nil {
		log.Printf("Warning: failed to invalidate sessions before account deletion: %v", err)
	}

	// Delete user
	if err := a.store.DeleteUser(user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete account")
		return
	}

	a.audit.Log(audit.Event{
		Type:      "account_deletion",
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Action:    "delete_own_account",
		Success:   true,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "account deleted"})
}

// findCertDir searches Caddy's certificate directory for a domain's certificate folder
func botChallengeVerify(w http.ResponseWriter, r *http.Request) {
	bot.NewVerifyEndpoint().ServeHTTP(w, r)
}

func findCertDir(baseDir, domain string) string {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domainPath := filepath.Join(baseDir, entry.Name(), domain)
		if fi, err := os.Stat(domainPath); err == nil && fi.IsDir() {
			return domainPath
		}
	}
	return ""
}
