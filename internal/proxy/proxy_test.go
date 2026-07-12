package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kroxy/kroxy/internal/config"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/testutil"
	"github.com/kroxy/kroxy/internal/validation"
	"github.com/kroxy/kroxy/internal/waf"
)

func TestWAFRegistry(t *testing.T) {
	// Clean slate
	ClearRouteWAFs()
	SetGlobalWAF(nil)

	if ids := GetAllRouteWAFIDs(); len(ids) != 0 {
		t.Errorf("expected 0 IDs, got %d", len(ids))
	}

	// Create a minimal WAF instance for registry tests
	w1 := &waf.WAF{}
	w2 := &waf.WAF{}

	SetRouteWAF(1, w1)
	SetRouteWAF(2, w2)

	if got := GetRouteWAF(1); got != w1 {
		t.Error("expected route 1 WAF to match w1")
	}
	if got := GetRouteWAF(2); got != w2 {
		t.Error("expected route 2 WAF to match w2")
	}
	if got := GetRouteWAF(999); got != nil {
		t.Error("expected route 999 WAF to be nil")
	}

	ids := GetAllRouteWAFIDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}

	ClearRouteWAFs()
	if ids := GetAllRouteWAFIDs(); len(ids) != 0 {
		t.Errorf("expected 0 IDs after clear, got %d", len(ids))
	}

	SetGlobalWAF(w1)
	if got := GetGlobalWAF(); got != w1 {
		t.Error("expected global WAF to match w1")
	}
	SetGlobalWAF(nil)
	if got := GetGlobalWAF(); got != nil {
		t.Error("expected global WAF to be nil")
	}
}

func TestProxy_wafStatus(t *testing.T) {
	p := &Proxy{waf: nil}
	if p.wafStatus() != "disabled" {
		t.Errorf("expected disabled, got %s", p.wafStatus())
	}
}

func TestProxy_tlsStatus(t *testing.T) {
	p := &Proxy{cfg: &config.Config{TLSEnabled: false}}
	if p.tlsStatus() != "disabled" {
		t.Errorf("expected disabled, got %s", p.tlsStatus())
	}

	p = &Proxy{cfg: &config.Config{TLSEnabled: true, TLSAutoHTTPS: true}}
	if p.tlsStatus() != "auto" {
		t.Errorf("expected auto, got %s", p.tlsStatus())
	}

	p = &Proxy{cfg: &config.Config{TLSEnabled: true, TLSAutoHTTPS: false}}
	if p.tlsStatus() != "manual" {
		t.Errorf("expected manual, got %s", p.tlsStatus())
	}
}

func TestProxy_New(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	cfg := &config.Config{ProxyAddr: ":8080"}
	p, err := New(s, cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil proxy")
	}
	if p.store != s {
		t.Error("expected store to be set")
	}
	if p.cfg != cfg {
		t.Error("expected config to be set")
	}
}

func TestProxy_Stop(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	p, err := New(s, &config.Config{ProxyAddr: ":8080"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Start with a context so cancel is non-nil
	ctx, cancel := context.WithCancel(context.Background())
	p.ctx = ctx
	p.cancel = cancel

	if err := p.Stop(); err != nil {
		t.Errorf("expected no error from Stop, got %v", err)
	}

	// Stop again should not panic
	if err := p.Stop(); err != nil {
		t.Errorf("expected no error from second Stop, got %v", err)
	}
}

func TestProxy_buildConfig_HTTPOnly(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// Seed routes
	routes := []store.Route{
		{Domain: "a.com", Backend: "http://localhost:3001", Enabled: true, WAFMode: "block", WAFEnabled: false, RequireHTTPS: false, RateLimit: 10, EnableGzip: true, EnableBrotli: true, CustomHeaders: `{"X-Custom":"value"}`, BotProtection: "captcha"},
		{Domain: "b.com", Backend: "http://localhost:3002", Enabled: true, WAFMode: "block", WAFEnabled: false, RequireHTTPS: true, OIDCEnabled: true, OIDCProviderID: 1},
		{Domain: "disabled.com", Backend: "http://localhost:3003", Enabled: false, WAFMode: "block"},
	}
	for i := range routes {
		if err := s.CreateRoute(&routes[i]); err != nil {
			t.Fatalf("create route: %v", err)
		}
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}

	apps, ok := cfg["apps"].(map[string]interface{})
	if !ok {
		t.Fatal("expected apps key")
	}
	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		t.Fatal("expected http app")
	}
	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		t.Fatal("expected servers")
	}
	kroxy, ok := servers["kroxy"].(map[string]interface{})
	if !ok {
		t.Fatal("expected kroxy server")
	}
	routesArr, ok := kroxy["routes"].([]interface{})
	if !ok {
		t.Fatal("expected routes array")
	}

	// Should have 3 routes (2 enabled + 1 default)
	if len(routesArr) != 3 {
		t.Errorf("expected 3 routes (2 enabled + default), got %d", len(routesArr))
	}

	// Verify TLS app is absent
	if _, hasTLS := apps["tls"]; hasTLS {
		t.Error("expected no tls app for HTTP-only config")
	}
}

func TestProxy_buildConfig_WithWAF(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// Seed a route with WAF enabled
	r := &store.Route{Domain: "waf.com", Backend: "http://localhost:3001", Enabled: true, WAFMode: "block", WAFEnabled: true, WAFParanoiaLevel: 1}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	// Create a real WAF instance so buildConfig creates per-route WAFs
	wafInst, err := waf.New(s, waf.Config{Enabled: true, Mode: "block", Ruleset: "owasp-crs", ParanoiaLevel: 1}, nil, nil, "block")
	if err != nil {
		t.Fatalf("waf.New: %v", err)
	}
	defer SetGlobalWAF(nil)

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: wafInst}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify route WAF was registered
	if GetRouteWAF(r.ID) == nil {
		t.Error("expected route WAF to be registered")
	}
}

func TestProxy_buildTLSConfig(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// Seed a route
	r := &store.Route{Domain: "tls.com", Backend: "http://localhost:3001", Enabled: true, WAFMode: "block", WAFEnabled: false, RequireHTTPS: true}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":80", HTTPSAddr: ":443", TLSEnabled: true, TLSMinVersion: "1.3", RedirectHTTP: true}, waf: nil}
	data, err := p.buildTLSConfig(nil, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	apps := cfg["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})

	if _, ok := servers["https"]; !ok {
		t.Error("expected https server")
	}
	if _, ok := servers["redirect"]; !ok {
		t.Error("expected redirect server")
	}
	if _, ok := servers["http"]; ok {
		t.Error("expected no http server when redirectHTTP=true")
	}

	// Verify TLS min version
	httpsServer := servers["https"].(map[string]interface{})
	policies := httpsServer["tls_connection_policies"].([]interface{})
	policy := policies[0].(map[string]interface{})
	if policy["min_version"] != "tls1.3" {
		t.Errorf("expected tls1.3, got %v", policy["min_version"])
	}
}

func TestProxy_buildTLSConfig_NoRedirect(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "noredirect.com", Backend: "http://localhost:3001", Enabled: true, WAFMode: "block", WAFEnabled: false, RequireHTTPS: false}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":80", HTTPSAddr: ":443", TLSEnabled: true, RedirectHTTP: false}, waf: nil}
	data, err := p.buildTLSConfig(nil, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	apps := cfg["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})

	if _, ok := servers["redirect"]; ok {
		t.Error("expected no redirect server when redirectHTTP=false")
	}
	if _, ok := servers["http"]; !ok {
		t.Error("expected http server when redirectHTTP=false")
	}
}

func TestProxy_buildTLSApp_Empty(t *testing.T) {
	p := &Proxy{store: nil, cfg: &config.Config{TLSEnabled: true, TLSAutoHTTPS: false}}
	app := p.buildTLSApp()
	if app != nil {
		t.Error("expected nil tlsApp when no certs configured")
	}
}

func TestProxy_buildTLSApp_EnvVarCerts(t *testing.T) {
	p := &Proxy{store: nil, cfg: &config.Config{TLSEnabled: true, TLSCertPath: "/etc/ssl/cert.pem", TLSKeyPath: "/etc/ssl/key.pem"}}
	app := p.buildTLSApp()
	if app == nil {
		t.Fatal("expected non-nil tlsApp")
	}
	certs := app["certificates"].(map[string]interface{})
	load := certs["load"].([]map[string]interface{})
	if len(load) != 1 {
		t.Fatalf("expected 1 manual cert, got %d", len(load))
	}
	first := load[0]
	if first["certificate"] != "/etc/ssl/cert.pem" {
		t.Errorf("expected cert path, got %v", first["certificate"])
	}
}

func TestProxy_buildTLSApp_DBCerts(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// Manual cert from DB
	c1 := &store.Certificate{Domain: "manual.com", Type: "custom", CertPath: "/certs/manual.crt", KeyPath: "/certs/manual.key", Status: "active"}
	if err := s.CreateCertificate(c1); err != nil {
		t.Fatalf("create cert: %v", err)
	}
	// Let's Encrypt cert
	c2 := &store.Certificate{Domain: "auto.com", Type: "letsencrypt", Status: "active"}
	if err := s.CreateCertificate(c2); err != nil {
		t.Fatalf("create cert: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{TLSEnabled: true}}
	app := p.buildTLSApp()
	if app == nil {
		t.Fatal("expected non-nil tlsApp")
	}
	certs := app["certificates"].(map[string]interface{})
	automate := certs["automate"].([]string)
	load := certs["load"].([]map[string]interface{})
	if len(automate) != 1 {
		t.Errorf("expected 1 automate domain, got %d", len(automate))
	}
	if len(load) != 1 {
		t.Errorf("expected 1 load cert, got %d", len(load))
	}
}

func TestProxy_buildTLSApp_AutoHTTPS(t *testing.T) {
	p := &Proxy{store: nil, cfg: &config.Config{TLSEnabled: true, TLSAutoHTTPS: true, TLSACMEEmail: "admin@example.com", AdminAddr: "127.0.0.1:8081"}}
	app := p.buildTLSApp()
	if app == nil {
		t.Fatal("expected non-nil tlsApp")
	}
	automation := app["automation"].(map[string]interface{})
	if _, ok := automation["on_demand"]; !ok {
		t.Error("expected on_demand automation")
	}
	policies := automation["policies"].([]map[string]interface{})
	if len(policies) == 0 {
		t.Error("expected at least one policy")
	}
}

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		input    string
		expected map[string][]string
	}{
		{`{"X-Custom":"value"}`, map[string][]string{"X-Custom": {"value"}}},
		{`{}`, map[string][]string{}},
		{`invalid json`, nil},
		{"", nil},
	}

	for _, tt := range tests {
		got := parseHeaders(tt.input)
		if tt.expected == nil {
			if got != nil {
				t.Errorf("parseHeaders(%q) expected nil, got %v", tt.input, got)
			}
			continue
		}
		if len(got) != len(tt.expected) {
			t.Errorf("parseHeaders(%q) expected %v, got %v", tt.input, tt.expected, got)
			continue
		}
		for k, v := range tt.expected {
			if got[k] == nil || got[k][0] != v[0] {
				t.Errorf("parseHeaders(%q) expected %v, got %v", tt.input, tt.expected, got)
			}
		}
	}
}

func TestValidateHeaders(t *testing.T) {
	if !validateHeaders(map[string][]string{"X-Custom": {"value"}}) {
		t.Error("expected valid headers to pass")
	}
	if validateHeaders(map[string][]string{"X-Bad\r\n": {"value"}}) {
		t.Error("expected CRLF in name to fail")
	}
	if validateHeaders(map[string][]string{"X-Custom": {"val\nue"}}) {
		t.Error("expected CRLF in value to fail")
	}
	if validateHeaders(map[string][]string{"X-Custom": {"val\rue"}}) {
		t.Error("expected CR in value to fail")
	}
	if !validateHeaders(map[string][]string{}) {
		t.Error("expected empty headers to pass")
	}
}

func TestProxy_Reload(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	// Reload calls caddy.Load which requires Caddy to be running.
	// We expect an error here but not a panic.
	err := p.Reload()
	if err == nil {
		t.Log("Reload succeeded unexpectedly (caddy may have accepted empty config)")
	}
}

func TestFindCaddyCertDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "caddy-certs-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create acme-v2.api.letsencrypt.org-directory/example.com/ structure
	issuerDir := filepath.Join(tmpDir, "acme-v2.api.letsencrypt.org-directory")
	if err := os.MkdirAll(filepath.Join(issuerDir, "example.com"), 0750); err != nil {
		t.Fatal(err)
	}

	result := findCaddyCertDir(tmpDir, "example.com")
	if result == "" {
		t.Error("expected to find example.com cert dir")
	}

	// Non-existent domain
	if findCaddyCertDir(tmpDir, "missing.com") != "" {
		t.Error("expected empty result for missing domain")
	}

	// Invalid base dir
	if findCaddyCertDir("/nonexistent/path", "example.com") != "" {
		t.Error("expected empty result for invalid base dir")
	}
}

func TestParseCertExpiry(t *testing.T) {
	// Generate a self-signed cert
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "test-cert-*.crt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if err := pem.Encode(tmpFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatal(err)
	}
	// #nosec G104 — test cleanup.
	tmpFile.Close()

	expiry, err := parseCertExpiry(tmpFile.Name())
	if err != nil {
		t.Fatalf("parseCertExpiry: %v", err)
	}
	// Allow 1 second tolerance
	if diff := expiry.Sub(template.NotAfter); diff < -time.Second || diff > time.Second {
		t.Errorf("expiry mismatch: expected ~%v, got %v", template.NotAfter, expiry)
	}

	// Non-existent file
	if _, err := parseCertExpiry("/nonexistent/cert.pem"); err == nil {
		t.Error("expected error for non-existent file")
	}

	// Invalid PEM
	badFile, _ := os.CreateTemp("", "bad-cert-*.crt")
	// #nosec G104 — test fixture write.
	badFile.WriteString("not a pem block")
	// #nosec G104 — test cleanup.
	badFile.Close()
	defer os.Remove(badFile.Name())
	if _, err := parseCertExpiry(badFile.Name()); err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestProxy_buildConfig_CustomHeadersInvalidJSON(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "badheaders.com", Backend: "http://localhost:3001", Enabled: true, WAFMode: "block", WAFEnabled: false, CustomHeaders: "not-json"}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Should still produce valid config even with invalid headers
	apps := cfg["apps"].(map[string]interface{})
	if _, ok := apps["http"]; !ok {
		t.Error("expected http app")
	}
}

func TestProxy_buildConfig_CustomHeadersCRLF(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "evil.com", Backend: "http://localhost:3001", Enabled: true, WAFMode: "block", WAFEnabled: false, CustomHeaders: `{"X-Bad":"val\r\nue"}`}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// CRLF headers should be dropped; config should still be valid
	apps := cfg["apps"].(map[string]interface{})
	if _, ok := apps["http"]; !ok {
		t.Error("expected http app")
	}
}

func TestProxy_buildConfig_BackendDial(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "dial.com", Backend: "http://localhost:3001/path?query=1", Enabled: true, WAFMode: "block", WAFEnabled: false}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify the upstream dial resolves to the cached IP:port (no path)
	apps := cfg["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	kroxy := servers["kroxy"].(map[string]interface{})
	routesArr := kroxy["routes"].([]interface{})
	// First route (not default)
	firstRoute := routesArr[0].(map[string]interface{})
	handlers := firstRoute["handle"].([]interface{})
	reverseProxy := handlers[len(handlers)-1].(map[string]interface{})
	upstreams := reverseProxy["upstreams"].([]interface{})
	dial := upstreams[0].(map[string]interface{})["dial"].(string)

	// DNS resolution may return 127.0.0.1 or ::1 for localhost; accept either.
	expected := []string{"127.0.0.1:3001", "[::1]:3001"}
	if !slices.Contains(expected, dial) {
		t.Errorf("expected dial one of %v, got %v", expected, dial)
	}
}

func TestProxy_buildConfig_BotProtection(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "bot.com", Backend: "http://localhost:3001", Enabled: true, WAFMode: "block", WAFEnabled: false, BotProtection: "block"}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	apps := cfg["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	kroxy := servers["kroxy"].(map[string]interface{})
	routesArr := kroxy["routes"].([]interface{})
	firstRoute := routesArr[0].(map[string]interface{})
	handlers := firstRoute["handle"].([]interface{})

	found := false
	for _, h := range handlers {
		hm := h.(map[string]interface{})
		if hm["handler"] == "bot_protection" {
			found = true
			if hm["mode"] != "block" {
				t.Errorf("expected mode block, got %v", hm["mode"])
			}
		}
	}
	if !found {
		t.Error("expected bot_protection handler in route")
	}
}

func TestProxy_buildConfig_BotProtectionOff(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "nobot.com", Backend: "http://localhost:3001", Enabled: true, WAFMode: "block", WAFEnabled: false, BotProtection: "off"}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	apps := cfg["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	kroxy := servers["kroxy"].(map[string]interface{})
	routesArr := kroxy["routes"].([]interface{})
	firstRoute := routesArr[0].(map[string]interface{})
	handlers := firstRoute["handle"].([]interface{})

	for _, h := range handlers {
		hm := h.(map[string]interface{})
		if hm["handler"] == "bot_protection" {
			t.Error("expected no bot_protection handler when mode is off")
		}
	}
}

func TestProxy_buildConfig_DefaultRoute(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	apps := cfg["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	kroxy := servers["kroxy"].(map[string]interface{})
	routesArr := kroxy["routes"].([]interface{})

	// Last route should be default with 444
	lastRoute := routesArr[len(routesArr)-1].(map[string]interface{})
	handlers := lastRoute["handle"].([]interface{})
	defaultHandler := handlers[0].(map[string]interface{})
	if defaultHandler["status_code"] != float64(444) {
		t.Errorf("expected default status 444, got %v", defaultHandler["status_code"])
	}
}

func TestProxy_buildConfig_StoreError(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	cleanup() // close store immediately

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	_, err := p.buildConfig()
	if err == nil {
		t.Error("expected error when store is closed")
	}
}

func TestProxy_buildTLSConfig_DefaultTLSMinVersion(t *testing.T) {
	p := &Proxy{store: nil, cfg: &config.Config{ProxyAddr: ":80", HTTPSAddr: ":443", TLSEnabled: true, TLSMinVersion: ""}, waf: nil}
	data, err := p.buildTLSConfig(nil, nil)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	apps := cfg["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	httpsServer := servers["https"].(map[string]interface{})
	policies := httpsServer["tls_connection_policies"].([]interface{})
	policy := policies[0].(map[string]interface{})
	if policy["min_version"] != "tls1.2" {
		t.Errorf("expected default tls1.2, got %v", policy["min_version"])
	}
}

func TestProxy_buildTLSApp_AdminAddrWithColon(t *testing.T) {
	p := &Proxy{store: nil, cfg: &config.Config{TLSEnabled: true, TLSAutoHTTPS: true, TLSACMEEmail: "a@b.com", AdminAddr: ":8081"}, waf: nil}
	app := p.buildTLSApp()
	if app == nil {
		t.Fatal("expected non-nil tlsApp")
	}
	automation := app["automation"].(map[string]interface{})
	onDemand := automation["on_demand"].(map[string]interface{})
	perm := onDemand["permission"].(map[string]interface{})
	endpoint := perm["endpoint"].(string)
	if !strings.Contains(endpoint, "localhost:8081") {
		t.Errorf("expected localhost prefix for colon-only admin addr, got %s", endpoint)
	}
}

func TestProxy_buildTLSApp_AdminAddrFullHost(t *testing.T) {
	p := &Proxy{store: nil, cfg: &config.Config{TLSEnabled: true, TLSAutoHTTPS: true, TLSACMEEmail: "a@b.com", AdminAddr: "127.0.0.1:8081"}, waf: nil}
	app := p.buildTLSApp()
	if app == nil {
		t.Fatal("expected non-nil tlsApp")
	}
	automation := app["automation"].(map[string]interface{})
	onDemand := automation["on_demand"].(map[string]interface{})
	perm := onDemand["permission"].(map[string]interface{})
	endpoint := perm["endpoint"].(string)
	if !strings.Contains(endpoint, "127.0.0.1:8081") {
		t.Errorf("expected 127.0.0.1:8081 in endpoint, got %s", endpoint)
	}
}

// unmarshalHTTPRoutes extracts the "routes" array from an HTTP-only buildConfig
// result (TLSEnabled=false). It fails the test if the expected structure is missing.
func unmarshalHTTPRoutes(t *testing.T, data []byte) []interface{} {
	t.Helper()
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	apps, ok := cfg["apps"].(map[string]interface{})
	if !ok {
		t.Fatal("expected apps key")
	}
	httpApp, ok := apps["http"].(map[string]interface{})
	if !ok {
		t.Fatal("expected http app")
	}
	servers, ok := httpApp["servers"].(map[string]interface{})
	if !ok {
		t.Fatal("expected servers")
	}
	kroxy, ok := servers["kroxy"].(map[string]interface{})
	if !ok {
		t.Fatal("expected kroxy server")
	}
	routesArr, ok := kroxy["routes"].([]interface{})
	if !ok {
		t.Fatal("expected routes array")
	}
	return routesArr
}

func TestProxy_buildConfig_SkipInvalidBackend_BadScheme(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "badscheme.com", Backend: "ftp://1.2.3.4/", Enabled: true, WAFMode: "block"}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	routes := unmarshalHTTPRoutes(t, data)
	if len(routes) != 1 {
		t.Errorf("expected only default route for bad-scheme backend, got %d", len(routes))
	}
}

func TestProxy_buildConfig_SkipInvalidBackend_PrivateIP(t *testing.T) {
	// The proxy test package defaults to allowing private backends via TestMain.
	// Re-enable strict SSRF blocking for this test.
	validation.SetAllowPrivateBackends(false)
	t.Cleanup(func() { validation.SetAllowPrivateBackends(true) })

	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "private.com", Backend: "http://10.0.0.1:8080/", Enabled: true, WAFMode: "block"}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	routes := unmarshalHTTPRoutes(t, data)
	if len(routes) != 1 {
		t.Errorf("expected only default route for private-IP backend, got %d", len(routes))
	}
}

func TestProxy_buildConfig_SkipInvalidBackend_SelfReference(t *testing.T) {
	// Register the proxy listener port so that a backend pointing at it is
	// recognized as a proxy loop. Duplicates are harmless if this test runs
	// multiple times.
	validation.SetProxyAddrs(":8080")

	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "loop.com", Backend: "http://127.0.0.1:8080/", Enabled: true, WAFMode: "block"}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	routes := unmarshalHTTPRoutes(t, data)
	if len(routes) != 1 {
		t.Errorf("expected only default route for self-referencing backend, got %d", len(routes))
	}
}

func TestProxy_buildConfig_KeepsValidBackend_PublicIP(t *testing.T) {
	validation.SetAllowPrivateBackends(false)
	t.Cleanup(func() { validation.SetAllowPrivateBackends(true) })

	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "public.com", Backend: "http://1.2.3.4:80/", Enabled: true, WAFMode: "block"}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	p := &Proxy{store: s, cfg: &config.Config{ProxyAddr: ":8080"}, waf: nil}
	data, err := p.buildConfig()
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	routes := unmarshalHTTPRoutes(t, data)
	if len(routes) != 2 {
		t.Errorf("expected valid route + default route for public-IP backend, got %d", len(routes))
	}
}
