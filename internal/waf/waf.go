package waf

import (
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/corazawaf/coraza/v3"
	corazacrs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/kroxy/kroxy/internal/store"
)

// WAF wraps the Coraza Web Application Firewall
type WAF struct {
	secEngine coraza.WAF
	enabled   bool
	store     *store.Store
}

// Config holds WAF configuration
type Config struct {
	Enabled     bool
	Mode        string // "block" or "detect"
	Ruleset     string // "owasp-crs" or "custom"
	CustomRules []string
}

// New creates a new WAF instance with OWASP Core Rule Set
func New(s *store.Store, cfg Config) (*WAF, error) {
	secEngine, err := createWAFEngine(cfg, s)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF engine: %w", err)
	}

	waf := &WAF{
		secEngine: secEngine,
		enabled:   cfg.Enabled,
		store:     s,
	}

	log.Printf("WAF initialized with OWASP Core Rule Set (mode: %s)", cfg.Mode)
	return waf, nil
}

func createWAFEngine(cfg Config, s *store.Store) (coraza.WAF, error) {
	wafConfig := coraza.NewWAFConfig()

	wafConfig = wafConfig.
		WithRequestBodyAccess().
		WithRequestBodyLimit(13107200).
		WithRequestBodyInMemoryLimit(1048576).
		WithResponseBodyAccess().
		WithResponseBodyLimit(524288)

	wafConfig = wafConfig.WithRootFS(corazacrs.FS)

	var directives strings.Builder
	if cfg.Mode == "block" {
		directives.WriteString("SecRuleEngine On\n")
	} else {
		directives.WriteString("SecRuleEngine DetectionOnly\n")
	}
	directives.WriteString("SecAuditEngine RelevantOnly\n")
	directives.WriteString("SecAuditLogParts ABCIJK\n")

	for _, rule := range cfg.CustomRules {
		directives.WriteString(rule)
		directives.WriteString("\n")
	}

	if s != nil {
		rules, err := s.GetWAFRules()
		if err != nil {
			log.Printf("Warning: failed to load WAF rules from database: %v", err)
		} else {
			for _, rule := range rules {
				if rule.Enabled {
					directives.WriteString(rule.Rule)
					directives.WriteString("\n")
					log.Printf("Loaded WAF rule: %s", rule.Name)
				}
			}
		}
	}

	wafConfig = wafConfig.WithDirectives(directives.String())
	return coraza.NewWAF(wafConfig)
}

// Middleware returns HTTP middleware that applies WAF rules
func (w *WAF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !w.enabled {
			next.ServeHTTP(rw, r)
			return
		}

		tx := w.secEngine.NewTransaction()
		defer tx.ProcessLogging()

		tx.ProcessConnection(r.RemoteAddr, 80, r.RemoteAddr, 80)
		tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)

		for name, values := range r.Header {
			for _, value := range values {
				tx.AddRequestHeader(name, value)
			}
		}

		if intervention := tx.ProcessRequestHeaders(); intervention != nil {
			w.blockRequest(rw, intervention, "Request headers blocked")
			return
		}

		// Read and process request body
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err == nil {
				if _, _, err := tx.WriteRequestBody(body); err != nil {
					log.Printf("WAF: Error writing request body: %v", err)
				}
				r.Body = io.NopCloser(strings.NewReader(string(body)))
			}
		}

		if intervention, _ := tx.ProcessRequestBody(); intervention != nil {
			w.blockRequest(rw, intervention, "Request body blocked")
			return
		}

		next.ServeHTTP(rw, r)
	})
}

func (w *WAF) blockRequest(rw http.ResponseWriter, intervention *types.Interruption, reason string) {
	rw.WriteHeader(http.StatusForbidden)
	rw.Header().Set("Content-Type", "text/html")
	// Escape the reason to prevent XSS
	escapedReason := html.EscapeString(reason)
	rw.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>Forbidden</h1>
<p>Your request was blocked by the Web Application Firewall.</p>
<p>Reason: ` + escapedReason + `</p>
</body>
</html>`))
}

// IsEnabled returns whether WAF is enabled
func (w *WAF) IsEnabled() bool {
	return w.enabled
}

// SetEnabled enables or disables the WAF
func (w *WAF) SetEnabled(enabled bool) {
	w.enabled = enabled
}

// AddRule adds a custom WAF rule
func (w *WAF) AddRule(rule string) error {
	if err := w.store.CreateWAFRule(&store.WAFRule{
		Name:    rule,
		Rule:    rule,
		Enabled: true,
	}); err != nil {
		return fmt.Errorf("failed to store WAF rule: %w", err)
	}
	log.Printf("WAF rule added: %s", rule)
	return nil
}

// RemoveRule removes a WAF rule
func (w *WAF) RemoveRule(id int) error {
	return w.store.DeleteWAFRule(id)
}

// ListRules returns all WAF rules
func (w *WAF) ListRules() ([]store.WAFRule, error) {
	return w.store.GetWAFRules()
}

// OWASPCRSRules returns information about the OWASP Core Rule Set
func OWASPCRSRules() []string {
	return []string{
		"OWASP CRS - SQL Injection Protection",
		"OWASP CRS - XSS Protection",
		"OWASP CRS - RCE Protection",
		"OWASP CRS - LFI Protection",
		"OWASP CRS - RFI Protection",
		"OWASP CRS - Session Fixation",
		"OWASP CRS - Scanner Detection",
		"OWASP CRS - Protocol Attacks",
		"OWASP CRS - Application Attacks",
	}
}

// CheckRequest checks if a request would pass WAF rules
func (w *WAF) CheckRequest(r *http.Request) (bool, string) {
	if !w.enabled {
		return true, ""
	}

	tx := w.secEngine.NewTransaction()
	tx.ProcessConnection(r.RemoteAddr, 80, r.RemoteAddr, 80)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)

	for name, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}

	if intervention := tx.Interruption(); intervention != nil {
		return false, "WAF blocked request"
	}

	return true, ""
}

// ParseIP extracts IP address from request (handles X-Forwarded-For)
func ParseIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}
