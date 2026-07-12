package proxy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/standard"
	_ "github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/config"
	"github.com/kroxy/kroxy/internal/crypto"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/validation"
	"github.com/kroxy/kroxy/internal/waf"
)

// WAF registry for per-route handler access
var (
	routeWAFs   = make(map[int]*waf.WAF) // routeID -> WAF instance
	routeWAFsMu sync.RWMutex
	globalWAF   *waf.WAF // fallback for routes without specific engine
)

// SetRouteWAF sets the WAF instance for a specific route
func SetRouteWAF(routeID int, wafInstance *waf.WAF) {
	routeWAFsMu.Lock()
	defer routeWAFsMu.Unlock()
	routeWAFs[routeID] = wafInstance
}

// GetRouteWAF gets the WAF instance for a specific route
func GetRouteWAF(routeID int) *waf.WAF {
	routeWAFsMu.RLock()
	defer routeWAFsMu.RUnlock()
	return routeWAFs[routeID]
}

// GetAllRouteWAFIDs returns all route IDs that have WAF engines
func GetAllRouteWAFIDs() []int {
	routeWAFsMu.RLock()
	defer routeWAFsMu.RUnlock()
	ids := make([]int, 0, len(routeWAFs))
	for id := range routeWAFs {
		ids = append(ids, id)
	}
	return ids
}

// ClearRouteWAFs removes all per-route WAF instances (used during config reload)
func ClearRouteWAFs() {
	routeWAFsMu.Lock()
	defer routeWAFsMu.Unlock()
	for id := range routeWAFs {
		delete(routeWAFs, id)
	}
}

// SetGlobalWAF sets the global WAF fallback instance
func SetGlobalWAF(wafInstance *waf.WAF) {
	routeWAFsMu.Lock()
	defer routeWAFsMu.Unlock()
	globalWAF = wafInstance
}

// GetGlobalWAF gets the global WAF fallback instance
func GetGlobalWAF() *waf.WAF {
	routeWAFsMu.RLock()
	defer routeWAFsMu.RUnlock()
	return globalWAF
}

type Proxy struct {
	store      *store.Store
	cfg        *config.Config
	ctx        context.Context
	cancel     context.CancelFunc
	waf        *waf.WAF
	signingKey []byte // HMAC signing key for WAF verification headers
}

// dnsRevalidationInterval is the interval at which DNS records are revalidated
const dnsRevalidationInterval = 5 * time.Second

func New(s *store.Store, cfg *config.Config) (*Proxy, error) {
	// Read global paranoia level from settings
	paranoiaLevel := 1
	if s != nil {
		val, err := s.GetSetting("waf_paranoia_level")
		if err == nil && val != "" {
			if n, err := strconv.Atoi(val); err == nil && n >= 1 && n <= 3 {
				paranoiaLevel = n
			}
		}
	}

	// Load WAF signing key
	signingKey, err := crypto.GetWAFSigningKey()
	if err != nil {
		log.Printf("Warning: WAF signing key not available: %v", err)
	}

	// Initialize global WAF with OWASP CRS (global rules only, nil routeID)
	wafInstance, err := waf.New(s, waf.Config{
		Enabled:       true,
		Mode:          "block",
		Ruleset:       "owasp-crs",
		ParanoiaLevel: paranoiaLevel,
		SigningKey:    signingKey,
	}, audit.GetLogger(), nil, "block")
	if err != nil {
		return nil, fmt.Errorf("WAF initialization failed: %w", err)
	}

	// Set global WAF for handler access
	SetGlobalWAF(wafInstance)

	return &Proxy{
		store:      s,
		cfg:        cfg,
		waf:        wafInstance,
		signingKey: signingKey,
	}, nil
}

func (p *Proxy) Start(ctx context.Context) error {
	// Cancel any existing context to prevent goroutine leaks on restart
	if p.cancel != nil {
		p.cancel()
	}
	p.ctx, p.cancel = context.WithCancel(ctx)

	// Start health checker
	hc := NewHealthChecker(p.store)
	hc.Start(p.ctx)
	SetGlobalHealthChecker(hc)

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

	// Start DNS revalidation worker
	go p.startDNSRevalidationWorker()

	// Start certificate expiry scanner
	go p.startCertExpiryScanner()

	log.Printf("Kroxy proxy started on %s (WAF: %s, TLS: %s)", p.cfg.ProxyAddr, p.wafStatus(), p.tlsStatus())
	return nil
}

func (p *Proxy) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	// Stop health checker
	if hc := GetGlobalHealthChecker(); hc != nil {
		hc.Stop()
	}
	return nil
}

func (p *Proxy) wafStatus() string {
	if p.waf != nil && p.waf.IsEnabled() {
		return "enabled"
	}
	return "disabled"
}

func (p *Proxy) tlsStatus() string {
	if p.cfg.TLSEnabled {
		if p.cfg.TLSAutoHTTPS {
			return "auto"
		}
		return "manual"
	}
	return "disabled"
}

func (p *Proxy) buildConfig() ([]byte, error) {
	// Clean up old per-route WAF instances to prevent memory leaks on reload
	ClearRouteWAFs()

	routes, err := p.store.GetRoutes()
	if err != nil {
		return nil, err
	}

	// Build separate route lists for HTTP and HTTPS servers.
	// HTTPS always gets full handlers. HTTP gets redirects for
	// routes that require HTTPS, full handlers otherwise.
	httpsRoutes := make([]map[string]interface{}, 0, len(routes))
	httpRoutes := make([]map[string]interface{}, 0, len(routes))

	for _, route := range routes {
		if !route.Enabled {
			continue
		}

		// Admin/self-routes are internal and should never be exposed on the
		// public proxy listener.
		if route.IsAdminRoute {
			continue
		}

		// Runtime re-validation: a route that passed validation when it was
		// created may have become unsafe due to DNS changes, admin edits, or
		// stale data. Skip any route whose backend fails SSRF/self-reference
		// or private-IP checks so it never becomes an upstream.
		if err := validation.ValidateBackendURL(route.Backend); err != nil {
			log.Printf("Warning: skipping route %s (id=%d): backend %q failed SSRF validation: %v", route.Domain, route.ID, route.Backend, err)
			continue
		}
		if err := validation.ValidateNoSelfReference(route.Backend, false); err != nil {
			log.Printf("Warning: skipping route %s (id=%d): backend %q creates proxy loop: %v", route.Domain, route.ID, route.Backend, err)
			continue
		}

		var handlers []map[string]interface{}

		// Strip internal X-Kroxy-* headers from incoming client requests before
		// any other handler can act on spoofed internal state.
		handlers = append(handlers, map[string]interface{}{
			"handler": "strip_internal_headers",
		})

		// Access log handler: logs all requests with timing and status
		handlers = append(handlers, map[string]interface{}{
			"handler": "kroxy_access_log",
		})

		// Metrics handler: counts all requests passing through this route
		handlers = append(handlers, map[string]interface{}{
			"handler": "kroxy_metrics",
		})

		// Bot protection handler
		if route.BotProtection != "" && route.BotProtection != "off" {
			handlers = append(handlers, map[string]interface{}{
				"handler": "bot_protection",
				"mode":    route.BotProtection,
			})
		}

		// Add WAF handler if enabled
		if route.WAFEnabled {
			routeWAFMode := route.WAFMode
			if routeWAFMode == "" {
				routeWAFMode = "block"
			}
			if p.waf != nil {
				routeWAF, wafErr := waf.New(p.store, waf.Config{
					Enabled:       true,
					Mode:          routeWAFMode,
					Ruleset:       "owasp-crs",
					ParanoiaLevel: route.WAFParanoiaLevel,
					SigningKey:    p.signingKey,
				}, audit.GetLogger(), &route.ID, routeWAFMode)
				if wafErr != nil {
					log.Printf("Warning: failed to create WAF for route %s: %v", route.Domain, wafErr)
				} else {
					SetRouteWAF(route.ID, routeWAF)
				}
			}

			handlers = append(handlers, map[string]interface{}{
				"handler":  "waf",
				"enabled":  true,
				"route_id": route.ID,
			})
		}

		// Add rate limiting if configured
		if route.RateLimit > 0 {
			burst := route.RateLimit
			if burst < 5 {
				burst = 5
			}
			handlers = append(handlers, map[string]interface{}{
				"handler": "rate_limit",
				"rate":    route.RateLimit,
				"burst":   burst,
			})
		}

		// Add compression if enabled
		if route.EnableGzip {
			handlers = append(handlers, map[string]interface{}{
				"handler":   "encode",
				"encodings": []string{"gzip"},
			})
		}

		if route.EnableBrotli {
			handlers = append(handlers, map[string]interface{}{
				"handler":   "encode",
				"encodings": []string{"br"},
			})
		}

		// Add headers if configured
		if route.CustomHeaders != "" && route.CustomHeaders != "{}" {
			headers := parseHeaders(route.CustomHeaders)
			if headers != nil && validateHeaders(headers) {
				handlers = append(handlers, map[string]interface{}{
					"handler": "headers",
					"response": map[string]interface{}{
						"add": headers,
					},
				})
			}
		}

		// Add OIDC authentication if enabled
		if route.OIDCEnabled {
			handlers = append(handlers, map[string]interface{}{
				"handler":     "authentication",
				"provider_id": route.OIDCProviderID,
			})
		}

		// Add reverse proxy handler (always last)
		backendDial := route.Backend
		scheme := "http"
		var backendHost, backendPort string
		parsedURL, err := url.Parse(route.Backend)
		if err == nil {
			backendDial = parsedURL.Host
			scheme = parsedURL.Scheme
			backendHost = parsedURL.Hostname()
			backendPort = parsedURL.Port()
		}

		// Enforce Kroxy's DNS-cache resolution so Caddy cannot perform
		// independent per-request DNS lookups (DNS-rebinding/SSRF guard).
		if backendHost != "" {
			if ips, err := validation.GetDNSCache().Resolve(backendHost); err == nil && len(ips) > 0 {
				if backendPort != "" {
					backendDial = net.JoinHostPort(ips[0].String(), backendPort)
				} else if scheme == "https" {
					backendDial = net.JoinHostPort(ips[0].String(), "443")
				} else {
					backendDial = net.JoinHostPort(ips[0].String(), "80")
				}
			}
		}

		rpHandler := map[string]interface{}{
			"handler":   "reverse_proxy",
			"upstreams": []map[string]interface{}{{"dial": backendDial}},
		}
		if scheme == "https" {
			rpHandler["transport"] = map[string]interface{}{
				"protocol": "http",
				"tls": map[string]interface{}{
					"server_name": backendHost,
				},
			}
		}
		handlers = append(handlers, rpHandler)

		httpsRoutes = append(httpsRoutes, map[string]interface{}{
			"match": []map[string]interface{}{
				{"host": []string{route.Domain}},
			},
			"handle": handlers,
		})

		// HTTP server: redirect to HTTPS if route requires it
		if route.RequireHTTPS {
			httpRoutes = append(httpRoutes, map[string]interface{}{
				"match": []map[string]interface{}{
					{"host": []string{route.Domain}},
				},
				"handle": []map[string]interface{}{
					{
						"handler":     "static_response",
						"status_code": 308,
						"headers": map[string]interface{}{
							"Location": []string{"https://{http.request.host}{http.request.uri}"},
						},
					},
				},
			})
		} else {
			httpRoutes = append(httpRoutes, map[string]interface{}{
				"match": []map[string]interface{}{
					{"host": []string{route.Domain}},
				},
				"handle": handlers,
			})
		}
	}

	// Default route: reject unknown hosts with 444
	defaultRoute := map[string]interface{}{
		"handle": []map[string]interface{}{
			{
				"handler":     "static_response",
				"status_code": 444,
				"body":        "Host not found\n",
			},
		},
	}

	allHTTPSRoutes := append(httpsRoutes, defaultRoute)
	allHTTPRoutes := append(httpRoutes, defaultRoute)

	if p.cfg.TLSEnabled {
		return p.buildTLSConfig(allHTTPRoutes, allHTTPSRoutes)
	}

	// HTTP-only config (no TLS)
	servers := map[string]interface{}{
		"kroxy": map[string]interface{}{
			"listen": []string{p.cfg.ProxyAddr},
			"routes": allHTTPRoutes,
			"logs": map[string]interface{}{
				"logger_names": map[string]interface{}{
					"kroxy": "kroxy-access",
				},
			},
		},
	}

	cfg := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": servers,
			},
		},
	}

	return json.Marshal(cfg)
}

// buildTLSConfig builds the Caddy JSON config with TLS enabled.
// It creates two HTTP servers: one for HTTPS on :443 with all route handlers,
// and one for HTTP on :80 that either redirects to HTTPS or serves routes
// that don't require HTTPS.
func (p *Proxy) buildTLSConfig(httpRoutes, httpsRoutes []map[string]interface{}) ([]byte, error) {
	tlsMinVersion := "tls1.2"
	if p.cfg.TLSMinVersion == "1.3" {
		tlsMinVersion = "tls1.3"
	}

	// HTTPS server with all route handlers
	httpsServer := map[string]interface{}{
		"listen": []string{p.cfg.HTTPSAddr},
		"routes": httpsRoutes,
		"tls_connection_policies": []map[string]interface{}{
			{
				"min_version": tlsMinVersion,
			},
		},
		"logs": map[string]interface{}{
			"logger_names": map[string]interface{}{
				"kroxy": "kroxy-access",
			},
		},
	}

	servers := map[string]interface{}{
		"https": httpsServer,
	}

	// HTTP redirect server (port 80 → HTTPS)
	if p.cfg.RedirectHTTP {
		redirectRoute := map[string]interface{}{
			"handle": []map[string]interface{}{
				{
					"handler":     "static_response",
					"status_code": 308,
					"headers": map[string]interface{}{
						"Location": []string{"https://{http.request.host}{http.request.uri}"},
					},
				},
			},
		}

		servers["redirect"] = map[string]interface{}{
			"listen": []string{p.cfg.ProxyAddr},
			"routes": []map[string]interface{}{redirectRoute},
		}
	} else {
		// No redirect: HTTP server serves non-HTTPS routes and redirects for HTTPS-required routes
		servers["http"] = map[string]interface{}{
			"listen": []string{p.cfg.ProxyAddr},
			"routes": httpRoutes,
			"logs": map[string]interface{}{
				"logger_names": map[string]interface{}{
					"kroxy": "kroxy-access",
				},
			},
		}
	}

	apps := map[string]interface{}{
		"http": map[string]interface{}{
			"servers": servers,
		},
	}

	// Build TLS app config
	tlsApp := p.buildTLSApp()
	if tlsApp != nil {
		apps["tls"] = tlsApp
	}

	cfg := map[string]interface{}{
		"apps": apps,
	}

	return json.Marshal(cfg)
}

// buildTLSApp builds the Caddy TLS app config with automation policies
// for ACME and manual certificate loading.
func (p *Proxy) buildTLSApp() map[string]interface{} {
	tlsApp := map[string]interface{}{}

	// Manual certificates from DB or env vars
	var manualCerts []map[string]interface{}

	// Load from env var paths first
	if p.cfg.TLSCertPath != "" && p.cfg.TLSKeyPath != "" {
		manualCerts = append(manualCerts, map[string]interface{}{
			"certificate": p.cfg.TLSCertPath,
			"key":         p.cfg.TLSKeyPath,
		})
	}

	// Build automate list for Let's Encrypt domains and collect manual certs from DB
	var automateDomains []string
	if p.store != nil {
		dbCerts, err := p.store.GetCertificates()
		if err == nil {
			for _, cert := range dbCerts {
				if cert.Type == "letsencrypt" || (cert.CertPath == "" && cert.KeyPath == "") {
					automateDomains = append(automateDomains, cert.Domain)
				} else if cert.CertPath != "" && cert.KeyPath != "" {
					manualCerts = append(manualCerts, map[string]interface{}{
						"certificate": cert.CertPath,
						"key":         cert.KeyPath,
					})
				}
			}
		}
	}

	// Build certificates section with both automate loader and manual certs
	if len(automateDomains) > 0 || len(manualCerts) > 0 {
		certSection := map[string]interface{}{}
		if len(automateDomains) > 0 {
			certSection["automate"] = automateDomains
		}
		if len(manualCerts) > 0 {
			certSection["load"] = manualCerts
		}
		tlsApp["certificates"] = certSection
	} else if len(manualCerts) > 0 {
		tlsApp["certificates"] = manualCerts
	}

	// ACME automation policy with permission module for on-demand TLS
	if p.cfg.TLSAutoHTTPS && p.cfg.TLSACMEEmail != "" {
		adminAddr := p.cfg.AdminAddr
		if strings.HasPrefix(adminAddr, ":") {
			adminAddr = "localhost" + adminAddr
		}

		tlsApp["automation"] = map[string]interface{}{
			"on_demand": map[string]interface{}{
				"permission": map[string]interface{}{
					"module":   "http",
					"endpoint": "http://" + adminAddr + "/api/cert-allowed",
				},
			},
			"policies": []map[string]interface{}{
				{
					"issuers": []map[string]interface{}{
						{
							"module": "acme",
							"email":  p.cfg.TLSACMEEmail,
						},
					},
				},
			},
		}
	}

	// Return nil if TLS app has no content
	if len(tlsApp) == 0 {
		return nil
	}

	return tlsApp
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

// validateHeaders checks that header names and values don't contain CRLF injection
func validateHeaders(headers map[string][]string) bool {
	for name, values := range headers {
		// Check header name for CRLF
		if strings.ContainsAny(name, "\r\n") {
			return false
		}
		// Check each header value for CRLF
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return false
			}
		}
	}
	return true
}

func (p *Proxy) Reload() error {
	cfg, err := p.buildConfig()
	if err != nil {
		return err
	}
	return caddy.Load(cfg, false)
}

// startDNSRevalidationWorker periodically revalidates DNS for all active routes
// to detect DNS rebinding attacks where an attacker changes DNS records after
// initial route validation.
func (p *Proxy) startDNSRevalidationWorker() {
	ticker := time.NewTicker(dnsRevalidationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.revalidateAllRoutes()
		}
	}
}

// revalidateAllRoutes checks all active routes for DNS rebinding
func (p *Proxy) revalidateAllRoutes() {
	routes, err := p.store.GetRoutes()
	if err != nil {
		log.Printf("DNS revalidation: failed to get routes: %v", err)
		return
	}

	for _, route := range routes {
		if !route.Enabled {
			continue
		}

		// Revalidate DNS for this route's backend
		if err := validation.RevalidateBackendDNS(route.Backend); err != nil {
			// Log security alert for DNS rebinding detection
			audit.GetLogger().Log(audit.Event{
				Type:   audit.EventTypeSecurityAlert,
				Action: "dns_rebind_detected",
				Details: map[string]interface{}{
					"domain":  route.Domain,
					"backend": route.Backend,
					"error":   err.Error(),
				},
				Success: false,
				Error:   err.Error(),
			})

			// Log to stdout for immediate visibility
			log.Printf("SECURITY ALERT: DNS rebinding detected for route %s -> %s: %v",
				route.Domain, route.Backend, err)

			// Disable the route to prevent access to internal IPs
			route.Enabled = false
			r := route
			if err := p.store.UpdateRoute(&r); err != nil {
				log.Printf("DNS revalidation: failed to disable route %d: %v", route.ID, err)
			} else {
				log.Printf("DNS revalidation: disabled route %d (%s) due to DNS rebinding risk",
					route.ID, route.Domain)
				// Reload Caddy config to apply route disabling
				if err := p.Reload(); err != nil {
					log.Printf("DNS revalidation: failed to reload config: %v", err)
				}
			}
		}
	}
}

func (p *Proxy) startCertExpiryScanner() {
	select {
	case <-time.After(30 * time.Second):
	case <-p.ctx.Done():
		return
	}
	p.scanCertExpiry()

	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.scanCertExpiry()
		}
	}
}

func (p *Proxy) scanCertExpiry() {
	if p.store == nil {
		return
	}

	certs, err := p.store.GetCertificates()
	if err != nil {
		return
	}

	caddyCertDir := filepath.Join("/home/kroxy", ".local", "share", "caddy", "certificates")

	for _, cert := range certs {
		if cert.Type != "letsencrypt" {
			continue
		}
		domainDir := findCaddyCertDir(caddyCertDir, cert.Domain)
		if domainDir == "" {
			continue
		}
		certFile := filepath.Join(domainDir, cert.Domain+".crt")
		expiresAt, err := parseCertExpiry(certFile)
		if err != nil {
			continue
		}
		// Update expiry
		if !cert.ExpiresAt.Equal(expiresAt) {
			if err := p.store.UpdateCertificateExpiry(cert.ID, expiresAt); err != nil {
				log.Printf("Cert scanner: failed to update expiry for %s: %v", cert.Domain, err)
			}
		}
		// Mark as active if still pending
		if cert.Status == "pending" || cert.Status == "failed" {
			if err := p.store.UpdateCertificateStatus(cert.ID, "active"); err != nil {
				log.Printf("Cert scanner: failed to update status for %s: %v", cert.Domain, err)
			}
		}
	}
}

func findCaddyCertDir(baseDir, domain string) string {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		domainPath := filepath.Join(baseDir, entry.Name(), domain)
		if fi, err := os.Stat(domainPath); err == nil && fi.IsDir() {
			return domainPath
		}
	}
	return ""
}

func parseCertExpiry(certPath string) (time.Time, error) {
	data, err := os.ReadFile(certPath) // #nosec G304 — certPath is from server-side TLS configuration
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
