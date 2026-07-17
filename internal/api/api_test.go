package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/version"
)

func newTestStore(t *testing.T) (*store.Store, func()) {
	t.Helper()
	tmp, err := os.CreateTemp("", "kroxy-api-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G104 — test cleanup.
	tmp.Close()

	// Use temp data dir to avoid writing encryption keys to working directory
	dataDir, err := os.MkdirTemp("", "kroxy-test-data-*")
	if err != nil {
		// #nosec G104 — test cleanup on error.
		os.Remove(tmp.Name())
		t.Fatal(err)
	}
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_DATA_DIR", dataDir)

	s, err := store.New(tmp.Name())
	if err != nil {
		// #nosec G104 — test cleanup on error.
		os.Remove(tmp.Name())
		// #nosec G104 — test cleanup on error.
		os.RemoveAll(dataDir)
		os.Unsetenv("KROXY_DATA_DIR")
		t.Fatal(err)
	}

	cleanup := func() {
		// #nosec G104 — test cleanup.
		s.Close()
		// #nosec G104 — test cleanup.
		os.Remove(tmp.Name())
		// #nosec G104 — test cleanup.
		os.RemoveAll(dataDir)
		os.Unsetenv("KROXY_DATA_DIR")
	}
	return s, cleanup
}

func newTestAPIWithEnv(t *testing.T, prod, insecure bool) (*API, func()) {
	s, cleanupStore := newTestStore(t)
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_JWT_SECRET", "test-secret-test-secret-test-secret-test")
	if prod {
		// #nosec G104 — test environment setup.
		os.Setenv("KROXY_PRODUCTION", "true")
	}
	if insecure {
		// #nosec G104 — test environment setup.
		os.Setenv("KROXY_INSECURE_COOKIES", "true")
	}
	a := New(s, 0)
	cleanup := func() {
		cleanupStore()
		os.Unsetenv("KROXY_JWT_SECRET")
		os.Unsetenv("KROXY_PRODUCTION")
		os.Unsetenv("KROXY_INSECURE_COOKIES")
	}
	return a, cleanup
}

func TestCsrfCookie_ProductionIgnoresInsecureOverride(t *testing.T) {
	a, cleanup := newTestAPIWithEnv(t, true, true)
	defer cleanup()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/csrf", nil)
	a.getCsrfToken(w, r)
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected csrf cookie")
	}
	if !cookies[0].Secure {
		t.Errorf("production mode must set Secure on CSRF cookie even when KROXY_INSECURE_COOKIES=true")
	}
}

func TestCsrfCookie_NonProductionHonoursInsecureOverride(t *testing.T) {
	a, cleanup := newTestAPIWithEnv(t, false, true)
	defer cleanup()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/csrf", nil)
	a.getCsrfToken(w, r)
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected csrf cookie")
	}
	if cookies[0].Secure {
		t.Errorf("non-production mode must allow KROXY_INSECURE_COOKIES to clear Secure")
	}
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("expected cookie %q", name)
	return nil
}

func TestRenderTemplateCsrfCookie_ProductionIgnoresInsecureOverride(t *testing.T) {
	a, cleanup := newTestAPIWithEnv(t, true, true)
	defer cleanup()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	a.renderTemplate(w, r, "login", &TemplateData{CSRFToken: "test-token"})
	c := findCookie(t, w.Result().Cookies(), "csrf_token")
	if !c.Secure {
		t.Errorf("production mode must set Secure on rendered CSRF cookie even when KROXY_INSECURE_COOKIES=true")
	}
}

func TestRenderTemplateCsrfCookie_NonProductionHonoursInsecureOverride(t *testing.T) {
	a, cleanup := newTestAPIWithEnv(t, false, true)
	defer cleanup()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	a.renderTemplate(w, r, "login", &TemplateData{CSRFToken: "test-token"})
	c := findCookie(t, w.Result().Cookies(), "csrf_token")
	if c.Secure {
		t.Errorf("non-production mode must allow KROXY_INSECURE_COOKIES to clear Secure on rendered CSRF cookie")
	}
}

// TestRenderTemplate_AuthenticatedPageIncludesSidebar verifies KR-026: authenticated
// pages executed through the "root" template must render the sidebar and navbar
// from the "content" layout, with page content inside <main class="main-content">.
func TestRenderTemplate_AuthenticatedPageIncludesSidebar(t *testing.T) {
	a, cleanup := newTestAPIWithEnv(t, false, true)
	defer cleanup()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	ctx := context.WithValue(r.Context(), cspNonceKey, "test-nonce")
	r = r.WithContext(ctx)

	data := &TemplateData{
		Title:     "Dashboard",
		Page:      "dashboard",
		CSRFToken: "test-token",
		User:      &TemplateUser{ID: 1, Name: "Admin", Email: "admin@example.com", Role: "admin"},
	}
	a.renderTemplate(w, r, "dashboard", data)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	mustContain := []string{
		`<aside class="sidebar"`,
		`<nav class="sidebar-nav">`,
		`<nav class="navbar">`,
		`<main class="main-content">`,
		`Dashboard</span>`,
		`<h1 class="page-title">Dashboard</h1>`,
		`nonce="test-nonce"`,
	}
	for _, s := range mustContain {
		if !strings.Contains(body, s) {
			t.Errorf("authenticated dashboard response missing expected markup %q", s)
		}
	}
	// The page-specific content must appear inside the main content wrapper.
	mainIdx := strings.Index(body, `<main class="main-content">`)
	dashboardTitleIdx := strings.Index(body, `<h1 class="page-title">Dashboard</h1>`)
	if mainIdx == -1 || dashboardTitleIdx == -1 || dashboardTitleIdx < mainIdx {
		t.Errorf("dashboard page content must appear inside <main class=\"main-content\">")
	}
}

func TestLogoutCookie_ProductionIgnoresInsecureOverride(t *testing.T) {
	a, cleanup := newTestAPIWithEnv(t, true, true)
	defer cleanup()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	a.oauthLogout(w, r)
	c := findCookie(t, w.Result().Cookies(), "kroxy_session")
	if c.MaxAge != -1 {
		t.Errorf("logout cookie must be a deletion cookie")
	}
	if !c.Secure {
		t.Errorf("production mode must set Secure on logout deletion cookie even when KROXY_INSECURE_COOKIES=true")
	}
}

func TestLogoutCookie_NonProductionHonoursInsecureOverride(t *testing.T) {
	a, cleanup := newTestAPIWithEnv(t, false, true)
	defer cleanup()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	a.oauthLogout(w, r)
	c := findCookie(t, w.Result().Cookies(), "kroxy_session")
	if c.Secure {
		t.Errorf("non-production mode must allow KROXY_INSECURE_COOKIES to clear Secure on logout deletion cookie")
	}
}

func TestLoginPage_ProductionInsecureCookiesFlagIgnoresOverride(t *testing.T) {
	s, cleanupStore := newTestStore(t)
	defer cleanupStore()
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_JWT_SECRET", "test-secret-test-secret-test-secret-test")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "true")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_INSECURE_COOKIES", "true")
	defer func() {
		os.Unsetenv("KROXY_JWT_SECRET")
		os.Unsetenv("KROXY_PRODUCTION")
		os.Unsetenv("KROXY_INSECURE_COOKIES")
	}()

	a := New(s, 0)
	if err := s.CreateUser(&store.User{Email: "admin@example.com", Name: "Admin", Role: "admin", Password: "x", Enabled: true}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	a.serveLogin(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// The warning is shown when cookies are secure. In production the override is
	// ignored, so the flag is false and the warning must be present.
	if !strings.Contains(w.Body.String(), "Connection not secure.") {
		t.Errorf("production mode must treat cookies as secure even when KROXY_INSECURE_COOKIES=true")
	}
}

func TestLoginPage_NonProductionHonoursInsecureCookiesOverride(t *testing.T) {
	s, cleanupStore := newTestStore(t)
	defer cleanupStore()
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_JWT_SECRET", "test-secret-test-secret-test-secret-test")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_INSECURE_COOKIES", "true")
	defer func() {
		os.Unsetenv("KROXY_JWT_SECRET")
		os.Unsetenv("KROXY_INSECURE_COOKIES")
	}()

	a := New(s, 0)
	if err := s.CreateUser(&store.User{Email: "admin@example.com", Name: "Admin", Role: "admin", Password: "x", Enabled: true}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	a.serveLogin(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// With the override active in non-production mode, cookies are insecure and
	// the warning must be suppressed.
	if strings.Contains(w.Body.String(), "Connection not secure.") {
		t.Errorf("non-production mode must honor KROXY_INSECURE_COOKIES and suppress the warning")
	}
}

func TestParseAdminAllowedIPs(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		expected int
	}{
		{"empty", "", 0},
		{"single_ip", "192.168.1.1", 1},
		{"multiple_ips", "192.168.1.1,10.0.0.1", 2},
		{"cidr", "192.168.0.0/24", 1},
		{"mixed", "192.168.1.1,10.0.0.0/8", 2},
		{"invalid_ignored", "192.168.1.1,not-an-ip", 1},
		{"whitespace", " 192.168.1.1 , 10.0.0.0/8 ", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// #nosec G104 — test environment setup.
			os.Setenv("KROXY_ADMIN_ALLOWED_IPS", tt.env)
			defer os.Unsetenv("KROXY_ADMIN_ALLOWED_IPS")

			networks := parseAdminAllowedIPs()
			if len(networks) != tt.expected {
				t.Fatalf("expected %d networks, got %d", tt.expected, len(networks))
			}
		})
	}
}

func TestAdminIPAllowlistMiddleware_NoAllowlist(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	os.Unsetenv("KROXY_ADMIN_ALLOWED_IPS")
	api := New(s, 0)

	called := false
	handler := api.adminIPAllowlistMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Fatal("expected handler to be called")
	}
}

func TestAdminIPAllowlistMiddleware_AllowedIP(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ADMIN_ALLOWED_IPS", "192.168.1.0/24")
	defer os.Unsetenv("KROXY_ADMIN_ALLOWED_IPS")
	api := New(s, 0)

	called := false
	handler := api.adminIPAllowlistMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Fatal("expected handler to be called")
	}
}

func TestAdminIPAllowlistMiddleware_BlockedIP(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ADMIN_ALLOWED_IPS", "192.168.1.0/24")
	defer os.Unsetenv("KROXY_ADMIN_ALLOWED_IPS")
	api := New(s, 0)

	called := false
	handler := api.adminIPAllowlistMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if called {
		t.Fatal("expected handler NOT to be called")
	}
}

func newAdminRouteContext(t *testing.T, id int) context.Context {
	t.Helper()
	adminSession := &auth.Session{
		UserID: 1,
		Email:  "admin@kroxy.local",
		Name:   "Admin",
		Role:   "admin",
	}
	ctx := context.WithValue(context.Background(), "session", adminSession)
	if id > 0 {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", strconv.Itoa(id))
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	}
	return ctx
}

func createTestOIDCProvider(t *testing.T, s *store.Store) int {
	t.Helper()
	p := &store.OIDCProvider{
		Name:         "Test Provider",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		DiscoveryURL: "https://example.com/.well-known/openid-configuration",
		RedirectURL:  "https://kroxy.local/api/oidc/callback",
	}
	if err := s.CreateOIDCProvider(p); err != nil {
		t.Fatalf("create OIDC provider: %v", err)
	}
	return p.ID
}

func TestCreateRoute_AcceptsDetectWAFMode(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	body := map[string]interface{}{
		"domain":   "detect.example.com",
		"backend":  "http://1.1.1.1:8080",
		"waf_mode": "detect",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createRoute(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for detect waf_mode, got %d: %s", rec.Code, rec.Body.String())
	}

	routes, err := s.GetRoutes()
	if err != nil {
		t.Fatalf("get routes: %v", err)
	}
	if len(routes) != 1 || routes[0].WAFMode != "detect" {
		t.Fatalf("stored WAFMode = %q, want detect", routes[0].WAFMode)
	}
}

func TestCreateRoute_OIDCRequiresProviderID(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	body := map[string]interface{}{
		"domain":       "oidc.example.com",
		"backend":      "http://1.1.1.1:8080",
		"waf_mode":     "block",
		"oidc_enabled": true,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createRoute(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateRoute_OIDCPreservesProviderID(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)
	providerID := createTestOIDCProvider(t, s)

	body := map[string]interface{}{
		"domain":           "oidc.example.com",
		"backend":          "http://1.1.1.1:8080",
		"waf_mode":         "block",
		"oidc_enabled":     true,
		"oidc_provider_id": providerID,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createRoute(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		OIDCEnabled    bool `json:"oidc_enabled"`
		OIDCProviderID int  `json:"oidc_provider_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.OIDCEnabled || resp.OIDCProviderID != providerID {
		t.Fatalf("response oidc_enabled=%v provider_id=%d, want true/%d", resp.OIDCEnabled, resp.OIDCProviderID, providerID)
	}

	routes, err := s.GetRoutes()
	if err != nil {
		t.Fatalf("get routes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].OIDCProviderID != providerID {
		t.Fatalf("stored OIDCProviderID = %d, want %d", routes[0].OIDCProviderID, providerID)
	}
}

func TestUpdateRoute_OIDCRejectsMissingProvider(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)
	route := &store.Route{
		Domain:  "example.com",
		Backend: "http://1.1.1.1:8080",
		WAFMode: "block",
	}
	if err := s.CreateRoute(route); err != nil {
		t.Fatalf("create route: %v", err)
	}

	body := map[string]interface{}{
		"domain":       "example.com",
		"backend":      "http://1.1.1.1:8080",
		"waf_mode":     "block",
		"oidc_enabled": true,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/routes/"+strconv.Itoa(route.ID), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, route.ID))

	rec := httptest.NewRecorder()
	a.updateRoute(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateRoute_OIDCPreservesProviderID(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)
	providerID := createTestOIDCProvider(t, s)
	route := &store.Route{
		Domain:  "example.com",
		Backend: "http://1.1.1.1:8080",
		WAFMode: "block",
	}
	if err := s.CreateRoute(route); err != nil {
		t.Fatalf("create route: %v", err)
	}

	body := map[string]interface{}{
		"domain":           "example.com",
		"backend":          "http://1.1.1.1:8080",
		"waf_mode":         "block",
		"oidc_enabled":     true,
		"oidc_provider_id": providerID,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/routes/"+strconv.Itoa(route.ID), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, route.ID))

	rec := httptest.NewRecorder()
	a.updateRoute(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	routes, err := s.GetRoutes()
	if err != nil {
		t.Fatalf("get routes: %v", err)
	}
	var updated *store.Route
	for i := range routes {
		if routes[i].ID == route.ID {
			updated = &routes[i]
			break
		}
	}
	if updated == nil {
		t.Fatal("updated route not found")
	}
	if !updated.OIDCEnabled || updated.OIDCProviderID != providerID {
		t.Fatalf("stored oidc_enabled=%v provider_id=%d, want true/%d", updated.OIDCEnabled, updated.OIDCProviderID, providerID)
	}
}

func TestCreateRoute_OIDCRejectsNonExistentProvider(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	body := map[string]interface{}{
		"domain":           "oidc.example.com",
		"backend":          "http://1.1.1.1:8080",
		"waf_mode":         "block",
		"oidc_enabled":     true,
		"oidc_provider_id": 99999,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createRoute(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateRoute_OIDCPreservesProviderIDWhenOmitted(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)
	providerID := createTestOIDCProvider(t, s)
	route := &store.Route{
		Domain:         "example.com",
		Backend:        "http://1.1.1.1:8080",
		WAFMode:        "block",
		OIDCEnabled:    true,
		OIDCProviderID: providerID,
	}
	if err := s.CreateRoute(route); err != nil {
		t.Fatalf("create route: %v", err)
	}

	// Update other fields while omitting oidc_provider_id.
	body := map[string]interface{}{
		"domain":       "example.com",
		"backend":      "http://1.1.1.1:8080",
		"waf_mode":     "block",
		"oidc_enabled": true,
		"rate_limit":   100,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/routes/"+strconv.Itoa(route.ID), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, route.ID))

	rec := httptest.NewRecorder()
	a.updateRoute(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	routes, err := s.GetRoutes()
	if err != nil {
		t.Fatalf("get routes: %v", err)
	}
	var updated *store.Route
	for i := range routes {
		if routes[i].ID == route.ID {
			updated = &routes[i]
			break
		}
	}
	if updated == nil {
		t.Fatal("updated route not found")
	}
	if updated.OIDCProviderID != providerID {
		t.Fatalf("stored OIDCProviderID = %d, want %d (preserved)", updated.OIDCProviderID, providerID)
	}
	if updated.RateLimit != 100 {
		t.Fatalf("stored RateLimit = %d, want 100", updated.RateLimit)
	}
}

func TestUpdateRoute_OIDCRejectsNonExistentProvider(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)
	route := &store.Route{
		Domain:  "example.com",
		Backend: "http://1.1.1.1:8080",
		WAFMode: "block",
	}
	if err := s.CreateRoute(route); err != nil {
		t.Fatalf("create route: %v", err)
	}

	body := map[string]interface{}{
		"domain":           "example.com",
		"backend":          "http://1.1.1.1:8080",
		"waf_mode":         "block",
		"oidc_enabled":     true,
		"oidc_provider_id": 99999,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/routes/"+strconv.Itoa(route.ID), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, route.ID))

	rec := httptest.NewRecorder()
	a.updateRoute(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateRoute_InvalidSecurityFields(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	base := map[string]interface{}{
		"domain":   "example.com",
		"backend":  "http://1.1.1.1:8080",
		"waf_mode": "block",
	}

	cases := []struct {
		name string
		key  string
		val  interface{}
	}{
		{"waf_mode", "waf_mode", "invalid-mode"},
		{"waf_paranoia_level", "waf_paranoia_level", 5},
		{"rate_limit negative", "rate_limit", -1},
		{"rate_limit too high", "rate_limit", 100001},
		{"bot_protection", "bot_protection", "captcha"},
		{"block_countries", "block_countries", "USA"},
		{"allow_countries", "allow_countries", "xx,xxx"},
		{"custom_headers not JSON", "custom_headers", "not-json"},
		{"custom_headers CRLF", "custom_headers", `{"X-Header":"bad\r\nvalue"}`},
		{"custom_headers empty name", "custom_headers", `{"":"value"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := make(map[string]interface{})
			for k, v := range base {
				body[k] = v
			}
			body[tc.key] = tc.val
			b, _ := json.Marshal(body)
			req := httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(newAdminRouteContext(t, 0))

			rec := httptest.NewRecorder()
			a.createRoute(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for invalid %s, got %d: %s", tc.key, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCreateRoute_DuplicateDomainReturnsConflict(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	// Seed an existing route for the target domain.
	if err := s.CreateRoute(&store.Route{Domain: "example.com", Backend: "http://1.1.1.1:8080", WAFMode: "block"}); err != nil {
		t.Fatalf("create seed route: %v", err)
	}

	body := map[string]interface{}{
		"domain":   "example.com",
		"backend":  "http://2.2.2.2:9090",
		"waf_mode": "block",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createRoute(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate domain, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("expected actionable error message, got: %s", rec.Body.String())
	}
}

func TestUpdateRoute_DuplicateDomainReturnsConflict(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	first := &store.Route{Domain: "first.example.com", Backend: "http://1.1.1.1:8080", WAFMode: "block"}
	second := &store.Route{Domain: "second.example.com", Backend: "http://2.2.2.2:9090", WAFMode: "block"}
	if err := s.CreateRoute(first); err != nil {
		t.Fatalf("create first route: %v", err)
	}
	if err := s.CreateRoute(second); err != nil {
		t.Fatalf("create second route: %v", err)
	}

	// Attempt to rename the second route to the first domain.
	body := map[string]interface{}{
		"domain":   "first.example.com",
		"backend":  "http://2.2.2.2:9090",
		"waf_mode": "block",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/routes/"+strconv.Itoa(second.ID), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, second.ID))

	rec := httptest.NewRecorder()
	a.updateRoute(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate domain update, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("expected actionable error message, got: %s", rec.Body.String())
	}
}

func TestUpdateRoute_InvalidSecurityFields(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)
	route := &store.Route{
		Domain:  "example.com",
		Backend: "http://1.1.1.1:8080",
		WAFMode: "block",
	}
	if err := s.CreateRoute(route); err != nil {
		t.Fatalf("create route: %v", err)
	}

	body := map[string]interface{}{
		"domain":         "example.com",
		"backend":        "http://1.1.1.1:8080",
		"waf_mode":       "block",
		"rate_limit":     -10,
		"bot_protection": "captcha",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/routes/"+strconv.Itoa(route.ID), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, route.ID))

	rec := httptest.NewRecorder()
	a.updateRoute(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHealthEndpoint_Public(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestReadyEndpoint_RequiresLoopback(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	cases := []struct {
		name       string
		remoteAddr string
		want       int
	}{
		{"loopback_ipv4", "127.0.0.1:12345", http.StatusOK},
		{"loopback_ipv6", "[::1]:12345", http.StatusOK},
		{"public_ip", "203.0.113.1:12345", http.StatusForbidden},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ready", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()
			a.router.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, rec.Code)
			}
		})
	}
}

func TestHealthzEndpoint_RequiresLoopback(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	cases := []struct {
		name       string
		remoteAddr string
		want       int
	}{
		{"loopback_ipv4", "127.0.0.1:12345", http.StatusOK},
		{"loopback_ipv6", "[::1]:12345", http.StatusOK},
		{"public_ip", "203.0.113.1:12345", http.StatusForbidden},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()
			a.router.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, rec.Code)
			}
		})
	}
}

// TestVersionEndpoint_RequiresAuth guards SEC-036: /api/version must no longer
// be public. An unauthenticated request must be rejected (401) rather than
// disclosing the exact application version.
func TestVersionEndpoint_RequiresAuth(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	req.Header.Set("Accept", "application/json") // avoid HTML login redirect
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("expected /api/version to be auth-gated, got 200 (body: %s)", rec.Body.String())
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /api/version, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), version.Version) {
		t.Fatalf("version leaked to unauthenticated client: %s", rec.Body.String())
	}
}

// TestAddRedirectDomain_ValidatesDomain guards SEC-037: addRedirectDomain must
// reject domains that include scheme, port, path, whitespace, or other invalid
// characters. Only valid domain names are persisted.
func TestAddRedirectDomain_ValidatesDomain(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	cases := []struct {
		name      string
		domain    string
		wantCode  int
		persisted bool
	}{
		{"valid", "example.com", http.StatusCreated, true},
		{"valid_subdomain", "sub.example.com", http.StatusCreated, true},
		{"empty", "", http.StatusBadRequest, false},
		{"scheme", "https://example.com", http.StatusBadRequest, false},
		{"port", "example.com:8080", http.StatusBadRequest, false},
		{"path", "example.com/path", http.StatusBadRequest, false},
		{"whitespace", "example com", http.StatusBadRequest, false},
		{"wildcard", "*.example.com", http.StatusBadRequest, false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]interface{}{"domain": tt.domain}
			b, _ := json.Marshal(body)
			req := httptest.NewRequest(http.MethodPost, "/api/redirect-domains", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(newAdminRouteContext(t, 0))

			rec := httptest.NewRecorder()
			a.addRedirectDomain(rec, req)
			if rec.Code != tt.wantCode {
				t.Fatalf("expected %d for %q, got %d: %s", tt.wantCode, tt.domain, rec.Code, rec.Body.String())
			}

			domains, err := s.GetRedirectDomains()
			if err != nil {
				t.Fatalf("get redirect domains: %v", err)
			}
			found := false
			for _, d := range domains {
				if d == tt.domain {
					found = true
					break
				}
			}
			if found != tt.persisted {
				t.Fatalf("domain %q persisted=%v, want persisted=%v (domains=%v)", tt.domain, found, tt.persisted, domains)
			}
		})
	}
}

// TestCreateWAFRule_RejectsInvalidPCRE guards SEC-039: a rule with a malformed
// PCRE regex must be rejected at save time so it can never brick WAF engine
// initialization on the next proxy startup.
func TestCreateWAFRule_RejectsInvalidPCRE(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	body := map[string]interface{}{
		"name":    "invalid-pcre",
		"rule":    `SecRule ARGS "@rx [" "id:999998,phase:2,deny,status:403"`,
		"enabled": true,
		"mode":    "block",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/waf/rules", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createWAFRule(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid PCRE, got %d: %s", rec.Code, rec.Body.String())
	}

	rules, err := s.GetWAFRules()
	if err != nil {
		t.Fatalf("get waf rules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected no rules stored, got %d", len(rules))
	}

	// The response must surface the compile failure details so the UI can show
	// an actionable validation message (KR-012).
	if !strings.Contains(rec.Body.String(), "WAF rule failed to compile") {
		t.Fatalf("expected error body to mention compile failure, got: %s", rec.Body.String())
	}
}

func TestCreateWAFRule_ReturnsValidationError(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	body := map[string]interface{}{
		"name":    "bad-rule",
		"rule":    "This is not a valid SecRule",
		"enabled": true,
		"mode":    "block",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/waf/rules", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createWAFRule(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid rule syntax, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "rule must start with SecRule, SecAction, or SecMarker") {
		t.Fatalf("expected descriptive validation error, got: %s", rec.Body.String())
	}
}

func TestCreateWAFRule_SuccessAuditFlag(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	body := map[string]interface{}{
		"name":    "test-rule",
		"rule":    `SecRule REQUEST_URI "@rx ^/test$" "id:900001,phase:1,deny,status:403,msg:'test'"`,
		"enabled": true,
		"mode":    "block",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/waf/rules", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createWAFRule(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	if !strings.Contains(rec.Body.String(), "id") {
		t.Fatalf("expected response body to contain rule id: %s", rec.Body.String())
	}
}

func TestCreateUser_SuccessAuditFlag(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	body := map[string]interface{}{
		"email":    "newuser@example.com",
		"password": "StrongP@ssw0rd123",
		"name":     "New User",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createUser(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	users, err := s.GetUsers()
	if err != nil {
		t.Fatalf("get users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
}

func TestUpdateSecuritySettings_InvalidSessionDuration(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	cases := []string{"not-a-duration", "-1h", "0s", "30s", "721h"}
	for _, value := range cases {
		body := map[string]interface{}{"session_duration": value}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/api/settings/security", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(newAdminRouteContext(t, 0))

		rec := httptest.NewRecorder()
		a.updateSecuritySettings(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for session_duration %q, got %d: %s", value, rec.Code, rec.Body.String())
		}
	}
}

func TestUpdateSecuritySettings_ValidSessionDuration(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	body := map[string]interface{}{"session_duration": "12h"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/settings/security", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.updateSecuritySettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	got := s.GetSettingDefault("session_duration", "")
	if got != "12h" {
		t.Fatalf("expected session_duration to be saved as 12h, got %q", got)
	}
}

func TestUpdateNetworkSettings_InvalidValues(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	cases := []map[string]interface{}{
		{"listen_port": "0"},
		{"listen_port": "abc"},
		{"listen_port": "70000"},
		{"https_port": "-1"},
		{"max_connections": -1},
		{"max_connections": 1_000_001},
		{"request_timeout": "not-a-duration"},
		{"request_timeout": "500ms"},
		{"request_timeout": "1h1s"},
	}

	for _, body := range cases {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/api/settings/network", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(newAdminRouteContext(t, 0))

		rec := httptest.NewRecorder()
		a.updateNetworkSettings(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %v, got %d: %s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestUpdateNetworkSettings_ValidValues(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	body := map[string]interface{}{
		"listen_port":     "8080",
		"https_port":      "8443",
		"max_connections": 5000,
		"request_timeout": "45s",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/settings/network", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.updateNetworkSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.GetSettingDefault("listen_port", ""); got != "8080" {
		t.Fatalf("expected listen_port 8080, got %q", got)
	}
	if got := s.GetSettingDefault("https_port", ""); got != "8443" {
		t.Fatalf("expected https_port 8443, got %q", got)
	}
	if got := s.GetSettingDefault("max_connections", ""); got != "5000" {
		t.Fatalf("expected max_connections 5000, got %q", got)
	}
	if got := s.GetSettingDefault("request_timeout", ""); got != "45s" {
		t.Fatalf("expected request_timeout 45s, got %q", got)
	}
}

func generateTestCertPEM(t *testing.T, domain string, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	var certBuf, keyBuf strings.Builder
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatal(err)
	}
	return certBuf.String(), keyBuf.String()
}

func TestCreateCertificate_ValidatesPEM(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	certPEM, keyPEM := generateTestCertPEM(t, "valid.example.com", time.Now().Add(24*time.Hour))

	body := map[string]interface{}{
		"domain":      "valid.example.com",
		"type":        "custom",
		"certificate": certPEM,
		"private_key": keyPEM,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/certificates", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createCertificate(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	certs, err := s.GetCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}
	if !strings.Contains(certs[0].CertPath, "valid.example.com") {
		t.Fatalf("expected cert path to contain sanitized domain, got %q", certs[0].CertPath)
	}
}

func TestCreateCertificate_RejectsInvalidPEM(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	certPEM, _ := generateTestCertPEM(t, "valid.example.com", time.Now().Add(24*time.Hour))

	cases := []map[string]interface{}{
		{"domain": "test.example.com", "type": "custom", "certificate": "not-pem", "private_key": "not-pem"},
		{"domain": "test.example.com", "type": "custom", "certificate": certPEM, "private_key": "not-pem"},
	}

	for _, body := range cases {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/certificates", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(newAdminRouteContext(t, 0))

		rec := httptest.NewRecorder()
		a.createCertificate(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %v, got %d: %s", body, rec.Code, rec.Body.String())
		}
	}

	certs, err := s.GetCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected no certificates stored, got %d", len(certs))
	}
}

func TestCreateCertificate_RejectsExpired(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	certPEM, keyPEM := generateTestCertPEM(t, "expired.example.com", time.Now().Add(-time.Hour))

	body := map[string]interface{}{
		"domain":      "expired.example.com",
		"type":        "custom",
		"certificate": certPEM,
		"private_key": keyPEM,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/certificates", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createCertificate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired cert, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateCertificate_RejectsMismatchedKeyPair(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	certPEM, _ := generateTestCertPEM(t, "valid.example.com", time.Now().Add(24*time.Hour))
	_, unrelatedKey := generateTestCertPEM(t, "other.example.com", time.Now().Add(24*time.Hour))

	body := map[string]interface{}{
		"domain":      "valid.example.com",
		"type":        "custom",
		"certificate": certPEM,
		"private_key": unrelatedKey,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/certificates", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createCertificate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched key pair, got %d: %s", rec.Code, rec.Body.String())
	}

	certs, err := s.GetCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected no certificates stored, got %d", len(certs))
	}
}

func TestCreateCertificate_SanitizesFileName(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	a := New(s, 0)

	// Domain validation already rejects path separators; this test covers the
	// defense-in-depth filename sanitizer for otherwise-valid domains with
	// characters that could be risky in filesystem paths.
	domain := "sub.example.com"
	certPEM, keyPEM := generateTestCertPEM(t, domain, time.Now().Add(24*time.Hour))

	body := map[string]interface{}{
		"domain":      domain,
		"type":        "custom",
		"certificate": certPEM,
		"private_key": keyPEM,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/certificates", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(newAdminRouteContext(t, 0))

	rec := httptest.NewRecorder()
	a.createCertificate(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	certs, err := s.GetCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}
	base := filepath.Base(certs[0].CertPath)
	if base != "sub.example.com.crt" {
		t.Fatalf("expected sanitized file name sub.example.com.crt, got %q", base)
	}
}

// TestMassAssignment_DTOsIgnoreServerManagedFields verifies that create/update
// handlers decode into request DTOs rather than store models, so clients cannot
// mass-assign server-managed fields such as ID or CreatedAt.
func TestMassAssignment_DTOsIgnoreServerManagedFields(t *testing.T) {
	injectedID := 99999
	injectedCreatedAt := "2020-01-01T00:00:00Z"

	createTests := []struct {
		name         string
		path         string
		body         map[string]interface{}
		create       func(*API, *http.Request)
		getStoredID  func(*store.Store) int
		getCreatedAt func(*store.Store) time.Time
	}{
		{
			name: "blacklist",
			path: "/api/blacklists",
			body: map[string]interface{}{
				"type":       "ip",
				"value":      "10.0.0.1",
				"enabled":    true,
				"id":         injectedID,
				"created_at": injectedCreatedAt,
			},
			create: func(a *API, r *http.Request) { a.createBlacklist(httptest.NewRecorder(), r) },
			getStoredID: func(s *store.Store) int {
				list, _ := s.GetBlacklists()
				if len(list) != 1 {
					t.Fatalf("expected 1 blacklist, got %d", len(list))
				}
				return list[0].ID
			},
			getCreatedAt: func(s *store.Store) time.Time {
				list, _ := s.GetBlacklists()
				return list[0].CreatedAt
			},
		},
		{
			name: "whitelist",
			path: "/api/whitelists",
			body: map[string]interface{}{
				"type":       "ip",
				"value":      "10.0.0.2",
				"enabled":    true,
				"id":         injectedID,
				"created_at": injectedCreatedAt,
			},
			create: func(a *API, r *http.Request) { a.createWhitelist(httptest.NewRecorder(), r) },
			getStoredID: func(s *store.Store) int {
				list, _ := s.GetWhitelists()
				if len(list) != 1 {
					t.Fatalf("expected 1 whitelist, got %d", len(list))
				}
				return list[0].ID
			},
			getCreatedAt: func(s *store.Store) time.Time {
				list, _ := s.GetWhitelists()
				return list[0].CreatedAt
			},
		},
		{
			name: "rate limit",
			path: "/api/ratelimits",
			body: map[string]interface{}{
				"domain":              "rl.example.com",
				"requests_per_minute": 10,
				"burst":               5,
				"enabled":             true,
				"id":                  injectedID,
			},
			create: func(a *API, r *http.Request) { a.createRateLimit(httptest.NewRecorder(), r) },
			getStoredID: func(s *store.Store) int {
				list, _ := s.GetRateLimits()
				if len(list) != 1 {
					t.Fatalf("expected 1 rate limit, got %d", len(list))
				}
				return list[0].ID
			},
			getCreatedAt: nil, // RateLimit has no CreatedAt
		},
		{
			name: "waf rule",
			path: "/api/waf/rules",
			body: map[string]interface{}{
				"name":    "test-rule",
				"rule":    `SecRule REQUEST_URI "@streq /test" "id:1000,phase:1,block,status:403"`,
				"enabled": true,
				"mode":    "block",
				"id":      injectedID,
			},
			create: func(a *API, r *http.Request) { a.createWAFRule(httptest.NewRecorder(), r) },
			getStoredID: func(s *store.Store) int {
				list, _ := s.GetWAFRules()
				if len(list) != 1 {
					t.Fatalf("expected 1 waf rule, got %d", len(list))
				}
				return list[0].ID
			},
			getCreatedAt: nil, // WAFRule has no CreatedAt
		},
	}

	for _, tc := range createTests {
		t.Run("create "+tc.name, func(t *testing.T) {
			s, cleanup := newTestStore(t)
			defer cleanup()
			a := New(s, 0)

			b, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(newAdminRouteContext(t, 0))
			tc.create(a, req)

			storedID := tc.getStoredID(s)
			if storedID == injectedID {
				t.Fatalf("stored %s ID must not equal injected mass-assignment ID %d", tc.name, injectedID)
			}
			if tc.getCreatedAt != nil {
				createdAt := tc.getCreatedAt(s)
				if createdAt.Format(time.RFC3339) == injectedCreatedAt {
					t.Fatalf("stored %s CreatedAt must not equal injected mass-assignment value %q", tc.name, injectedCreatedAt)
				}
			}
		})
	}

	t.Run("update rate limit ignores body id", func(t *testing.T) {
		s, cleanup := newTestStore(t)
		defer cleanup()
		a := New(s, 0)

		aRecord := &store.RateLimit{Domain: "a.example.com", RequestsPerMinute: 10, Burst: 5, Enabled: true}
		bRecord := &store.RateLimit{Domain: "b.example.com", RequestsPerMinute: 20, Burst: 10, Enabled: true}
		if err := s.CreateRateLimit(aRecord); err != nil {
			t.Fatalf("create rate limit a: %v", err)
		}
		if err := s.CreateRateLimit(bRecord); err != nil {
			t.Fatalf("create rate limit b: %v", err)
		}

		body := map[string]interface{}{
			"domain":              "updated.example.com",
			"requests_per_minute": 30,
			"burst":               15,
			"enabled":             false,
			"id":                  bRecord.ID,
		}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/api/ratelimits/"+strconv.Itoa(aRecord.ID), bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(newAdminRouteContext(t, aRecord.ID))

		rec := httptest.NewRecorder()
		a.updateRateLimit(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}

		limits, err := s.GetRateLimits()
		if err != nil {
			t.Fatalf("get rate limits: %v", err)
		}

		var updatedA, otherB *store.RateLimit
		for i := range limits {
			if limits[i].ID == aRecord.ID {
				updatedA = &limits[i]
			}
			if limits[i].ID == bRecord.ID {
				otherB = &limits[i]
			}
		}
		if updatedA == nil {
			t.Fatal("updated rate limit a not found")
		}
		if updatedA.Domain != "updated.example.com" || updatedA.RequestsPerMinute != 30 || updatedA.Burst != 15 || updatedA.Enabled {
			t.Fatalf("rate limit a not updated as expected: %+v", updatedA)
		}
		if otherB == nil || otherB.Domain != "b.example.com" {
			t.Fatalf("rate limit b was incorrectly affected by mass-assigned id: %+v", otherB)
		}
	})

	t.Run("update waf rule ignores body id", func(t *testing.T) {
		s, cleanup := newTestStore(t)
		defer cleanup()
		a := New(s, 0)

		aRule := &store.WAFRule{Name: "rule-a", Rule: `SecRule REQUEST_URI "@streq /a" "id:1001,phase:1,block,status:403"`, Enabled: true, Mode: "block"}
		bRule := &store.WAFRule{Name: "rule-b", Rule: `SecRule REQUEST_URI "@streq /b" "id:1002,phase:1,block,status:403"`, Enabled: true, Mode: "block"}
		if err := s.CreateWAFRule(aRule); err != nil {
			t.Fatalf("create waf rule a: %v", err)
		}
		if err := s.CreateWAFRule(bRule); err != nil {
			t.Fatalf("create waf rule b: %v", err)
		}

		body := map[string]interface{}{
			"name":    "rule-a-updated",
			"rule":    `SecRule REQUEST_URI "@streq /updated" "id:1003,phase:1,block,status:403"`,
			"enabled": false,
			"mode":    "log_only",
			"id":      bRule.ID,
		}
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, "/api/waf/rules/"+strconv.Itoa(aRule.ID), bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(newAdminRouteContext(t, aRule.ID))

		rec := httptest.NewRecorder()
		a.updateWAFRule(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}

		rules, err := s.GetWAFRules()
		if err != nil {
			t.Fatalf("get waf rules: %v", err)
		}

		var updatedA, otherB *store.WAFRule
		for i := range rules {
			if rules[i].ID == aRule.ID {
				updatedA = &rules[i]
			}
			if rules[i].ID == bRule.ID {
				otherB = &rules[i]
			}
		}
		if updatedA == nil || updatedA.Name != "rule-a-updated" {
			t.Fatalf("waf rule a not updated as expected: %+v", updatedA)
		}
		if otherB == nil || otherB.Name != "rule-b" {
			t.Fatalf("waf rule b was incorrectly affected by mass-assigned id: %+v", otherB)
		}
	})
}
