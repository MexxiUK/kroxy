package bot

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/kroxy/kroxy/internal/security"
)

func init() {
	caddy.RegisterModule(&BotProtectionHandler{})
}

// BotProtectionHandler implements caddyhttp.MiddlewareHandler for bot detection.
type BotProtectionHandler struct {
	// Mode: "off", "passive", "challenge"
	Mode string `json:"mode,omitempty"`
}

// CaddyModule returns the Caddy module info.
func (h *BotProtectionHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.bot_protection",
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

// ServeHTTP runs bot detection and either blocks, challenges, or passes through.
func (h *BotProtectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if h.Mode == "" || h.Mode == "off" {
		return next.ServeHTTP(w, r)
	}

	// Skip challenge verification endpoint itself
	if strings.HasPrefix(r.URL.Path, "/.kroxy/challenge/") {
		return next.ServeHTTP(w, r)
	}

	// Skip static assets (CSS, JS, images, fonts)
	if isStaticAsset(r.URL.Path) {
		return next.ServeHTTP(w, r)
	}

	realIP := security.GetClientIP(r)
	ip := NormalizeIP(realIP)

	// Check bypass cookie
	secret := getGlobalSecret()
	if CheckPassCookie(r, realIP, secret) {
		return next.ServeHTTP(w, r)
	}

	// Run detection
	detector := getGlobalDetector()
	score := detector.Score(r)

	cache := getGlobalCache()

	// Check cache for this IP
	if entry := cache.Get(ip); entry != nil {
		if entry.passed {
			return next.ServeHTTP(w, r)
		}
		score = entry.score
	}

	// Decision
	if ShouldBlock(score) {
		logBotEvent(r, score, "blocked")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied."))
		return nil
	}

	if h.Mode == "challenge" && ShouldChallenge(score) {
		logBotEvent(r, score, "challenged")
		cm := getGlobalChallengeManager()
		cm.ServeChallengePage(w)
		return nil
	}

	// Low-score pass: do NOT cache passed=true so that a single benign request
	// cannot whitelist a bot IP. Only explicit challenge success sets passed=true.
	return next.ServeHTTP(w, r)
}

func isStaticAsset(path string) bool {
	exts := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range exts {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	return false
}

func logBotEvent(r *http.Request, score float64, action string) {
	// Use existing audit logger if available, otherwise stdout
	// This is kept minimal to avoid import cycles
}

var _ caddy.Module = (*BotProtectionHandler)(nil)
var _ caddy.Provisioner = (*BotProtectionHandler)(nil)
var _ caddy.Validator = (*BotProtectionHandler)(nil)
var _ caddyhttp.MiddlewareHandler = (*BotProtectionHandler)(nil)
