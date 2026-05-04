package proxy

import (
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(&AccessLogHandler{})
}

// AccessLogHandler logs all HTTP requests passing through the proxy.
type AccessLogHandler struct{}

// CaddyModule returns the Caddy module information.
func (h *AccessLogHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.kroxy_access_log",
		New: func() caddy.Module { return new(AccessLogHandler) },
	}
}

// Provision sets up the handler.
func (h *AccessLogHandler) Provision(ctx caddy.Context) error { return nil }

// Validate ensures the handler is properly configured.
func (h *AccessLogHandler) Validate() error { return nil }

// responseRecorder wraps http.ResponseWriter to capture status code and body size.
type responseRecorder struct {
	http.ResponseWriter
	statusCode   int
	responseSize int64
	wroteHeader  bool
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w, statusCode: 200}
}

func (rr *responseRecorder) WriteHeader(code int) {
	if !rr.wroteHeader {
		rr.statusCode = code
		rr.wroteHeader = true
		rr.ResponseWriter.WriteHeader(code)
	}
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	if !rr.wroteHeader {
		rr.WriteHeader(http.StatusOK)
	}
	n, err := rr.ResponseWriter.Write(b)
	rr.responseSize += int64(n)
	return n, err
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *AccessLogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	start := time.Now()
	rr := newResponseRecorder(w)

	err := next.ServeHTTP(rr, r)

	entry := AccessLogEntry{
		Timestamp:    time.Now(),
		Method:       r.Method,
		Host:         r.Host,
		URI:          r.RequestURI,
		RemoteAddr:   r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		StatusCode:   rr.statusCode,
		ResponseSize: rr.responseSize,
		Duration:     time.Since(start).Milliseconds(),
	}

	LogAccess(entry)
	return err
}

var _ caddy.Module = (*AccessLogHandler)(nil)
var _ caddy.Provisioner = (*AccessLogHandler)(nil)
var _ caddy.Validator = (*AccessLogHandler)(nil)
var _ caddyhttp.MiddlewareHandler = (*AccessLogHandler)(nil)
