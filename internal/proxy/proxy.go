package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	caddy "github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/waf"
)

// Global WAF registry for handler access
var (
	globalWAF     *waf.WAF
	globalWAFMu   sync.RWMutex
)

// SetGlobalWAF sets the global WAF instance for handler access
func SetGlobalWAF(wafInstance *waf.WAF) {
	globalWAFMu.Lock()
	defer globalWAFMu.Unlock()
	globalWAF = wafInstance
}

// GetGlobalWAF gets the global WAF instance
func GetGlobalWAF() *waf.WAF {
	globalWAFMu.RLock()
	defer globalWAFMu.RUnlock()
	return globalWAF
}

type Proxy struct {
	store     *store.Store
	ctx       context.Context
	cancel    context.CancelFunc
	proxyAddr string
	waf       *waf.WAF
}

func New(s *store.Store, proxyAddr string) (*Proxy, error) {
	// Initialize WAF with OWASP CRS
	wafInstance, err := waf.New(s, waf.Config{
		Enabled: true,
		Mode:    "block",
		Ruleset: "owasp-crs",
	})
	if err != nil {
		log.Printf("Warning: WAF initialization failed: %v", err)
		// Continue without WAF
	}

	// Set global WAF for handler access
	if wafInstance != nil {
		SetGlobalWAF(wafInstance)
	}

	return &Proxy{
		store:     s,
		proxyAddr: proxyAddr,
		waf:       wafInstance,
	}, nil
}

func (p *Proxy) Start(ctx context.Context) error {
	p.ctx, p.cancel = context.WithCancel(ctx)

	// Set global WAF for handler access
	if p.waf != nil {
		SetGlobalWAF(p.waf)
	}

	// Build Caddy config
	cfg, err := p.buildConfig()
	if err != nil {
		return fmt.Errorf("failed to build config: %w", err)
	}

	// Load config
	if err := caddy.Load(cfg, false); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	log.Printf("Kroxy proxy started on %s (WAF: %s)", p.proxyAddr, p.wafStatus())
	return nil
}

func (p *Proxy) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

func (p *Proxy) wafStatus() string {
	if p.waf != nil && p.waf.IsEnabled() {
		return "enabled"
	}
	return "disabled"
}

func (p *Proxy) buildConfig() ([]byte, error) {
	routes, err := p.store.GetRoutes()
	if err != nil {
		return nil, err
	}

	// Build route handlers
	var httpRoutes []map[string]interface{}

	for _, route := range routes {
		if !route.Enabled {
			continue
		}

		// Build handlers for this route
		var handlers []map[string]interface{}

		// Add WAF handler if enabled
		if route.WAFEnabled && p.waf != nil {
			handlers = append(handlers, map[string]interface{}{
				"handler": "waf",
				"enabled": true,
			})
		}

		// Add rate limiting if configured
		if route.RateLimit > 0 {
			handlers = append(handlers, map[string]interface{}{
				"handler": "rate_limit",
				"rate":    route.RateLimit,
				"burst":   route.RateLimit / 10, // 10% burst
			})
		}

		// Add compression if enabled
		if route.EnableGzip {
			handlers = append(handlers, map[string]interface{}{
				"handler": "encode",
				"encodings": []string{"gzip"},
			})
		}

		if route.EnableBrotli {
			handlers = append(handlers, map[string]interface{}{
				"handler": "encode",
				"encodings": []string{"br"},
			})
		}

		// Add headers if configured
		if route.CustomHeaders != "" && route.CustomHeaders != "{}" {
			handlers = append(handlers, map[string]interface{}{
				"handler": "headers",
				"response": map[string]interface{}{
					"add": parseHeaders(route.CustomHeaders),
				},
			})
		}

		// Add OIDC authentication if enabled
		if route.OIDCEnabled {
			handlers = append(handlers, map[string]interface{}{
				"handler": "authentication",
				"provider_id": route.OIDCProviderID,
			})
		}

		// Add reverse proxy handler (always last)
		handlers = append(handlers, map[string]interface{}{
			"handler":   "reverse_proxy",
			"upstreams": []map[string]interface{}{{"dial": route.Backend}},
		})

		// Build route
		httpRoutes = append(httpRoutes, map[string]interface{}{
			"match": []map[string]interface{}{
				{"host": []string{route.Domain}},
			},
			"handle": handlers,
		})
	}

	// Build Caddy config
	cfg := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"kroxy": map[string]interface{}{
						"listen": []string{p.proxyAddr},
						"routes": httpRoutes,
						"logs": map[string]interface{}{
							"logger_names": map[string]interface{}{
								"kroxy": "kroxy-access",
							},
						},
					},
				},
			},
			"tls": map[string]interface{}{
				"certificates": map[string]interface{}{
					"automate": map[string]interface{}{
						"issuer": "acme",
					},
				},
			},
		},
	}

	return json.Marshal(cfg)
}

func parseHeaders(headersJSON string) map[string][]string {
	// Parse JSON-encoded headers
	var headers map[string]string
	if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		return nil
	}

	result := make(map[string][]string)
	for k, v := range headers {
		result[k] = []string{v}
	}
	return result
}

func (p *Proxy) Reload() error {
	cfg, err := p.buildConfig()
	if err != nil {
		return err
	}
	return caddy.Load(cfg, false)
}

// GetWAF returns the WAF instance
func (p *Proxy) GetWAF() *waf.WAF {
	return p.waf
}

// ReloadWAF recreates the WAF instance to load new rules
func (p *Proxy) ReloadWAF() error {
	wafInstance, err := waf.New(p.store, waf.Config{
		Enabled: true,
		Mode:    "block",
		Ruleset: "owasp-crs",
	})
	if err != nil {
		return fmt.Errorf("failed to reload WAF: %w", err)
	}

	p.waf = wafInstance
	SetGlobalWAF(wafInstance)
	log.Printf("WAF reloaded successfully")
	return nil
}

