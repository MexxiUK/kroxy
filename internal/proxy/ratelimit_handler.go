package proxy

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/kroxy/kroxy/internal/security"
)

func init() {
	caddy.RegisterModule(&RateLimitHandler{})
}

// RateLimitHandler implements per-IP rate limiting for Caddy routes.
// It uses a simple token-bucket-like counter with a 1-minute window.
type RateLimitHandler struct {
	Rate  int `json:"rate"`
	Burst int `json:"burst"`
}

// ipBucket tracks requests for a single IP in a time window.
type ipBucket struct {
	count  int
	window time.Time
}

var (
	ipBuckets   = make(map[string]*ipBucket)
	ipBucketsMu sync.RWMutex
)

// CaddyModule returns the Caddy module information.
func (h *RateLimitHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.rate_limit",
		New: func() caddy.Module { return new(RateLimitHandler) },
	}
}

// Provision sets up the handler.
func (h *RateLimitHandler) Provision(ctx caddy.Context) error { return nil }

// Validate ensures the handler is properly configured.
func (h *RateLimitHandler) Validate() error {
	if h.Rate <= 0 {
		return fmt.Errorf("rate must be positive, got %d", h.Rate)
	}
	if h.Burst <= 0 {
		return fmt.Errorf("burst must be positive, got %d", h.Burst)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *RateLimitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := security.GetClientIP(r)
	now := time.Now()
	windowStart := now.Truncate(time.Minute)

	ipBucketsMu.Lock()
	bucket, ok := ipBuckets[ip]
	if !ok || bucket.window != windowStart {
		bucket = &ipBucket{count: 0, window: windowStart}
		ipBuckets[ip] = bucket
	}
	bucket.count++
	allowed := bucket.count <= h.Rate || bucket.count <= h.Burst
	ipBucketsMu.Unlock()

	if !allowed {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return nil
	}

	return next.ServeHTTP(w, r)
}

// startRateLimitCleanup periodically purges stale IP buckets to prevent
// unbounded memory growth.
func startRateLimitCleanup() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			ipBucketsMu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, b := range ipBuckets {
				if b.window.Before(cutoff) {
					delete(ipBuckets, ip)
				}
			}
			ipBucketsMu.Unlock()
		}
	}()
}

func init() {
	startRateLimitCleanup()
}

var (
	_ caddy.Module                = (*RateLimitHandler)(nil)
	_ caddy.Provisioner           = (*RateLimitHandler)(nil)
	_ caddy.Validator             = (*RateLimitHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*RateLimitHandler)(nil)
)
