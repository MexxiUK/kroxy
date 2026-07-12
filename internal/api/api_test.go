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
		{"waf_mode", "waf_mode", "detect"},
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
