package proxy

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(&StripInternalHeadersHandler{})
}

// StripInternalHeadersHandler removes any incoming request header whose name
// starts with "X-Kroxy-". These headers are reserved for internal Kroxy use
// (WAF verification, health checks, webhook signing) and must never be accepted
// from clients, since they could be used to spoof internal state.
type StripInternalHeadersHandler struct{}

// CaddyModule returns the Caddy module info.
func (StripInternalHeadersHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.strip_internal_headers",
		New: func() caddy.Module {
			return new(StripInternalHeadersHandler)
		},
	}
}

// Provision does nothing.
func (h *StripInternalHeadersHandler) Provision(ctx caddy.Context) error { return nil }

// Validate does nothing.
func (h *StripInternalHeadersHandler) Validate() error { return nil }

// ServeHTTP strips internal X-Kroxy-* headers before passing to the next handler.
func (h *StripInternalHeadersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	for name := range r.Header {
		if strings.HasPrefix(name, "X-Kroxy-") {
			r.Header.Del(name)
		}
	}
	return next.ServeHTTP(w, r)
}

var _ caddy.Module = (*StripInternalHeadersHandler)(nil)
var _ caddy.Provisioner = (*StripInternalHeadersHandler)(nil)
var _ caddy.Validator = (*StripInternalHeadersHandler)(nil)
var _ caddyhttp.MiddlewareHandler = (*StripInternalHeadersHandler)(nil)
