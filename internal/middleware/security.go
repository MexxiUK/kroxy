package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// SecurityHeaders adds security headers to all responses
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// HSTS - 1 year, include subdomains
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")

		// Permissions Policy
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")

		// Cache control for API responses
		if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		next.ServeHTTP(w, r)
	})
}

// CSRF provides CSRF protection for state-changing operations
type CSRF struct {
	tokens sync.Map // sessionID -> csrfToken
}

// NewCSRF creates a new CSRF protection middleware
func NewCSRF() *CSRF {
	return &CSRF{}
}

// Middleware returns CSRF middleware
func (c *CSRF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only protect state-changing methods
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		// Get CSRF token from header or form
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.FormValue("csrf_token")
		}

		// Get session ID from cookie
		cookie, err := r.Cookie("kroxy_session")
		if err != nil {
			http.Error(w, "Unauthorized - No session", http.StatusUnauthorized)
			return
		}

		// Validate CSRF token
		storedToken, ok := c.tokens.Load(cookie.Value)
		if !ok {
			http.Error(w, "Unauthorized - Invalid CSRF state", http.StatusUnauthorized)
			return
		}

		// Use constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(token), []byte(storedToken.(string))) != 1 {
			http.Error(w, "Forbidden - CSRF token mismatch", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GenerateToken creates a new CSRF token for a session
func (c *CSRF) GenerateToken(sessionID string) string {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)
	c.tokens.Store(sessionID, token)
	return token
}

// GetToken returns the CSRF token for a session
func (c *CSRF) GetToken(sessionID string) string {
	if token, ok := c.tokens.Load(sessionID); ok {
		return token.(string)
	}
	return ""
}

// RateLimiter provides rate limiting for API endpoints
type RateLimiter struct {
	requests sync.Map // key -> *requestCounter
	limit    int
	window   time.Duration
}

type requestCounter struct {
	count     int64
	windowEnd int64
	mu        sync.Mutex
}

// NewRateLimiter creates a rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:  limit,
		window: window,
	}
}

// Middleware returns rate limiting middleware
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client identifier (IP + User-Agent for better fingerprinting)
		key := getClientIdentifier(r)

		// Check rate limit
		if !rl.allowRequest(key) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("X-RateLimit-Limit", int64ToString(int64(rl.limit)))
			w.Header().Set("X-RateLimit-Remaining", "0")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allowRequest(key string) bool {
	now := time.Now().UnixNano()
	windowEnd := now + int64(rl.window)

	value, _ := rl.requests.LoadOrStore(key, &requestCounter{
		count:     0,
		windowEnd: windowEnd,
	})

	counter := value.(*requestCounter)
	counter.mu.Lock()
	defer counter.mu.Unlock()

	// Reset if window expired
	if now > counter.windowEnd {
		counter.count = 0
		counter.windowEnd = windowEnd
	}

	// Check limit
	if counter.count >= int64(rl.limit) {
		return false
	}

	counter.count++
	return true
}

func getClientIdentifier(r *http.Request) string {
	// Use X-Forwarded-For if available
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff + ":" + r.Header.Get("User-Agent")
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr + ":" + r.Header.Get("User-Agent")
}

func int64ToString(n int64) string {
	return base64.URLEncoding.EncodeToString([]byte{
		byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	})
}

// IPWhitelist creates an IP whitelist middleware
func IPWhitelist(allowedIPs []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool)
	for _, ip := range allowedIPs {
		allowed[ip] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allowed) == 0 {
				// No whitelist = allow all
				next.ServeHTTP(w, r)
				return
			}

			clientIP := getClientIP(r)
			if !allowed[clientIP] {
				http.Error(w, "Forbidden - IP not whitelisted", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take first IP in chain
		for i, c := range xff {
			if c == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Extract from RemoteAddr
	for i := len(r.RemoteAddr) - 1; i >= 0; i-- {
		if r.RemoteAddr[i] == ':' {
			return r.RemoteAddr[:i]
		}
	}
	return r.RemoteAddr
}

// RequireMethod creates middleware that only allows specific methods
func RequireMethod(methods ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool)
	for _, m := range methods {
		allowed[m] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowed[r.Method] {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NoCache prevents caching
func NoCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}