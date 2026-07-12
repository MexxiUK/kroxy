package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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
