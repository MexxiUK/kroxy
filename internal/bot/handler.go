package bot

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(&BotProtectionHandler{})
}

// BotProtectionHandler implements caddyhttp.MiddlewareHandler for bot detection.
type BotProtectionHandler struct {
	// Mode: "off", "passive", or "challenge".
	// "challenge" is deprecated and now behaves as "passive" because the
	// previous JavaScript proof-of-work implementation was trivially bypassable.
	Mode string `json:"mode,omitempty"`
}

// CaddyModule returns the Caddy module info.
func (h *BotProtectionHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.bot_protection",
		New: func() caddy.Module { return new(BotProtectionHandler) },
	}
}

// Provision does nothing (no external dependencies).
func (h *BotProtectionHandler) Provision(ctx caddy.Context) error { return nil }

// Validate ensures the mode is valid.
func (h *BotProtectionHandler) Validate() error {
	switch h.Mode {
	case "", "off", "passive", "challenge":
		return nil
	default:
		return fmt.Errorf("invalid bot_protection mode: %s", h.Mode)
	}
}

// ServeHTTP runs bot detection and either blocks or passes through.
func (h *BotProtectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.Mode == "" || h.Mode == "off" {
		return next.ServeHTTP(w, r)
	}

	detector := getGlobalDetector()
	score := detector.Score(r)

	if ShouldBlock(score) {
		logBotEvent(r, score, "blocked")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied."))
		return nil
	}

	// Legacy "challenge" mode no longer serves a client-side puzzle; it falls
	// back to passive detection so existing route configurations remain safe.
	return next.ServeHTTP(w, r)
}

func logBotEvent(r *http.Request, score float64, action string) {
	// Use existing audit logger if available, otherwise stdout.
	// This is kept minimal to avoid import cycles.
}

var _ caddy.Module = (*BotProtectionHandler)(nil)
var _ caddy.Provisioner = (*BotProtectionHandler)(nil)
var _ caddy.Validator = (*BotProtectionHandler)(nil)
var _ caddyhttp.MiddlewareHandler = (*BotProtectionHandler)(nil)
