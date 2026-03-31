package network

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CORS handles Cross-Origin Resource Sharing
type CORS struct {
	origins sync.Map // domain -> []allowed origins
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge          int
}

// NewCORS creates a new CORS handler
func NewCORS() *CORS {
	return &CORS{}
}

// Middleware returns middleware for CORS handling
func (c *CORS) Middleware(config map[string]CORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Find CORS config for this host
			cfg, ok := config[r.Host]
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			// Check if origin is allowed
			allowed := false
			for _, o := range cfg.AllowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}

			if !allowed {
				next.ServeHTTP(w, r)
				return
			}

			// Set CORS headers
			w.Header().Set("Access-Control-Allow-Origin", origin)

			if len(cfg.AllowedMethods) > 0 {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(cfg.AllowedMethods, ", "))
			}

			if len(cfg.AllowedHeaders) > 0 {
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(cfg.AllowedHeaders, ", "))
			}

			if len(cfg.ExposedHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(cfg.ExposedHeaders, ", "))
			}

			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if cfg.MaxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", string(cfg.MaxAge))
			}

			// Handle preflight
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (c *CORS) SetConfig(domain string, config CORSConfig) {
	c.origins.Store(domain, config)
}

func (c *CORS) RemoveConfig(domain string) {
	c.origins.Delete(domain)
}

// RateLimiter handles request rate limiting
type RateLimiter struct {
	limiters sync.Map // key -> *limitState
}

type limitState struct {
	requests   int64
	windowStart int64
	mu         sync.Mutex
}

type RateLimitConfig struct {
	RequestsPerMinute int
	Burst             int
	Key               string // "ip", "path", "header:X-User-ID"
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{}
}

// Middleware returns middleware for rate limiting
func (rl *RateLimiter) Middleware(config map[string]RateLimitConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Find rate limit config for this host
			cfg, ok := config[r.Host]
			if !ok || cfg.RequestsPerMinute == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Get rate limit key
			key := rl.getKey(r, cfg.Key)

			// Check rate limit
			if !rl.allowRequest(key, cfg.RequestsPerMinute, cfg.Burst) {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte("Rate limit exceeded\n"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (rl *RateLimiter) getKey(r *http.Request, keyType string) string {
	switch keyType {
	case "ip":
		return GetClientIP(r)
	case "path":
		return r.URL.Path
	default:
		if strings.HasPrefix(keyType, "header:") {
			return r.Header.Get(strings.TrimPrefix(keyType, "header:"))
		}
		return GetClientIP(r)
	}
}

func (rl *RateLimiter) allowRequest(key string, limit, burst int) bool {
	value, _ := rl.limiters.LoadOrStore(key, &limitState{})

	state := value.(*limitState)
	state.mu.Lock()
	defer state.mu.Unlock()

	now := time.Now().Unix()
	windowStart := state.windowStart

	// Reset window if expired
	if now-windowStart >= 60 {
		state.requests = 0
		state.windowStart = now
	}

	// Check burst limit
	if state.requests < int64(burst) {
		state.requests++
		return true
	}

	// Check rate limit
	if state.requests >= int64(limit) {
		return false
	}

	state.requests++
	return true
}

// Reset resets the rate limiter state for testing
func (rl *RateLimiter) Reset() {
	rl.limiters = sync.Map{}
}

// RealIP extracts the real client IP from proxy headers
type RealIP struct {
	trustedProxies []string
}

// NewRealIP creates a new RealIP handler
func NewRealIP(trustedProxies []string) *RealIP {
	return &RealIP{trustedProxies: trustedProxies}
}

// Middleware returns middleware for setting the real IP
func (rip *RealIP) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only trust headers from trusted proxies
			remoteIP := getRemoteIP(r)

			if rip.isTrustedProxy(remoteIP) {
				// Try headers in order of preference
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					// Get first non-trusted IP
					ips := strings.Split(xff, ",")
					for i := len(ips) - 1; i >= 0; i-- {
						ip := strings.TrimSpace(ips[i])
						if !rip.isTrustedProxy(ip) {
							r.RemoteAddr = ip + ":0"
							break
						}
					}
				} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
					r.RemoteAddr = xri + ":0"
				} else if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
					r.RemoteAddr = cf + ":0"
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (rip *RealIP) isTrustedProxy(ip string) bool {
	for _, proxy := range rip.trustedProxies {
		if ip == proxy {
			return true
		}
		// Check CIDR
		if strings.Contains(proxy, "/") {
			_, cidr, err := net.ParseCIDR(proxy)
			if err == nil && cidr.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

func getRemoteIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// GetClientIP extracts the client IP from a request
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Check CF-Connecting-IP
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// RequestID generates and tracks request IDs
type RequestID struct{}

// NewRequestID creates a new request ID handler
func NewRequestID() *RequestID {
	return &RequestID{}
}

// Middleware returns middleware for adding request IDs
func (rid *RequestID) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if request already has an ID
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = generateRequestID()
				r.Header.Set("X-Request-ID", requestID)
			}

			// Add ID to response
			w.Header().Set("X-Request-ID", requestID)

			next.ServeHTTP(w, r)
		})
	}
}

func generateRequestID() string {
	b := make([]byte, 16)
	randRead(b)
	return base64Encode(b)
}

// Simple implementations to avoid dependencies
func randRead(b []byte) {
	for i := range b {
		b[i] = byte(atomic.AddInt64(&randCounter, 1) % 256)
	}
}

var randCounter int64

func base64Encode(b []byte) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = base64Chars[v>>2]
		result[i*2+1] = base64Chars[(v&0x3)<<4|(v>>4)]
	}
	return string(result)
}

// Timeout handles request timeouts
type Timeout struct {
	defaultTimeout time.Duration
}

// NewTimeout creates a new timeout handler
func NewTimeout(defaultTimeout time.Duration) *Timeout {
	return &Timeout{defaultTimeout: defaultTimeout}
}

// Middleware returns middleware for request timeouts
func (t *Timeout) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), t.defaultTimeout)
			defer cancel()

			done := make(chan struct{})
			go func() {
				next.ServeHTTP(w, r.WithContext(ctx))
				close(done)
			}()

			select {
			case <-done:
				return
			case <-ctx.Done():
				w.WriteHeader(http.StatusGatewayTimeout)
				w.Write([]byte("Request timeout\n"))
				return
			}
		})
	}
}