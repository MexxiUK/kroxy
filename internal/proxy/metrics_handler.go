package proxy

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/kroxy/kroxy/internal/metrics"
)

func init() {
	caddy.RegisterModule(&MetricsHandler{})
}

// MetricsHandler increments request counters for all traffic.
type MetricsHandler struct{}

// CaddyModule returns the Caddy module information.
func (h *MetricsHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.kroxy_metrics",
		New: func() caddy.Module { return new(MetricsHandler) },
	}
}

// Provision sets up the handler.
func (h *MetricsHandler) Provision(ctx caddy.Context) error { return nil }

// Validate ensures the handler is properly configured.
func (h *MetricsHandler) Validate() error { return nil }

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *MetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	metrics.IncRequests()
	return next.ServeHTTP(w, r)
}
