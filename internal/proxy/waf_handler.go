package proxy

import (
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/kroxy/kroxy/internal/waf"
)

func init() {
	caddy.RegisterModule(&WAFHandler{})
}

// WAFHandler implements caddyhttp.MiddlewareHandler for WAF protection
type WAFHandler struct {
	Enabled bool `json:"enabled"`
	RouteID int  `json:"route_id,omitempty"`

	wafInstance *waf.WAF
	once        sync.Once
}

// CaddyModule returns the Caddy module information
func (h *WAFHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(WAFHandler) },
	}
}

// Provision sets up the handler
func (h *WAFHandler) Provision(ctx caddy.Context) error {
	return nil
}

// Validate ensures the handler is properly configured
func (h *WAFHandler) Validate() error {
	if h.RouteID < 0 {
		return fmt.Errorf("route_id must be non-negative, got %d", h.RouteID)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler
func (h *WAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Resolve WAF instance: prefer route-specific, fall back to global
	h.once.Do(func() {
		if h.RouteID > 0 {
			h.wafInstance = GetRouteWAF(h.RouteID)
		}
		if h.wafInstance == nil {
			h.wafInstance = GetGlobalWAF()
		}
	})

	if !h.Enabled {
		return next.ServeHTTP(w, r)
	}

	// Fail closed: if WAF is enabled for this route but no WAF instance
	// is available, return 503 instead of silently passing traffic through.
	if h.wafInstance == nil {
		log.Printf("WAFHandler: WAF enabled for route %d but no instance available - failing closed", h.RouteID)
		http.Error(w, "Service Unavailable: WAF not initialized", http.StatusServiceUnavailable)
		return nil
	}

	// Inspect request against WAF rules
	allowed, reason := h.wafInstance.InspectRequest(w, r)
	if !allowed {
		h.wafInstance.BlockRequest(w, r, reason)
		return nil
	}

	// Request passed WAF inspection — pass to next handler in Caddy chain
	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Module                = (*WAFHandler)(nil)
	_ caddy.Provisioner          = (*WAFHandler)(nil)
	_ caddy.Validator            = (*WAFHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*WAFHandler)(nil)
)