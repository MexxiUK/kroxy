package proxy

import (
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/kroxy/kroxy/internal/waf"
)

func init() {
	caddy.RegisterModule(WAFHandler{})
}

// WAFHandler implements caddyhttp.MiddlewareHandler for WAF protection
type WAFHandler struct {
	// For JSON config
	Enabled bool `json:"enabled"`

	wafInstance *waf.WAF
	once        sync.Once
}

// CaddyModule returns the Caddy module information
func (WAFHandler) CaddyModule() caddy.ModuleInfo {
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
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler
func (h WAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Get WAF from global registry
	wafInstance := GetGlobalWAF()

	if !h.Enabled || wafInstance == nil {
		return next.ServeHTTP(w, r)
	}

	// Create an adapter that wraps caddyhttp.Handler as http.Handler
	caddyAdapter := &caddyHandlerAdapter{next: next}

	// Use WAF middleware to check request
	handler := wafInstance.Middleware(caddyAdapter)
	handler.ServeHTTP(w, r)
	return nil
}

// caddyHandlerAdapter adapts caddyhttp.Handler to http.Handler
type caddyHandlerAdapter struct {
	next caddyhttp.Handler
}

func (a *caddyHandlerAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Module                = (*WAFHandler)(nil)
	_ caddy.Provisioner          = (*WAFHandler)(nil)
	_ caddy.Validator            = (*WAFHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*WAFHandler)(nil)
)
