package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/testutil"
	"github.com/kroxy/kroxy/internal/waf"
)

// mockHandler implements the caddyhttp.Handler interface for testing

type mockHandler struct {
	called bool
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

func TestWAFHandler_Validate(t *testing.T) {
	h := &WAFHandler{Enabled: true, RouteID: 1}
	if err := h.Validate(); err != nil {
		t.Errorf("expected valid handler, got %v", err)
	}

	h = &WAFHandler{Enabled: true, RouteID: -1}
	if err := h.Validate(); err == nil {
		t.Error("expected error for negative routeID")
	}
}

func TestWAFHandler_ServeHTTP_Disabled(t *testing.T) {
	h := &WAFHandler{Enabled: false, RouteID: 1}
	next := &mockHandler{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	if err := h.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Error("expected next handler to be called when WAF disabled")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestWAFHandler_ServeHTTP_NoWAF_FailClosed(t *testing.T) {
	// Ensure no global or route WAF is set
	ClearRouteWAFs()
	SetGlobalWAF(nil)

	h := &WAFHandler{Enabled: true, RouteID: 999}
	next := &mockHandler{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	if err := h.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if next.called {
		t.Error("expected next handler NOT to be called when WAF enabled but missing")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
	body := w.Body.String()
	if !contains(body, "WAF not initialized") {
		t.Errorf("expected WAF not initialized message, got %s", body)
	}
}

func TestWAFHandler_ServeHTTP_WithGlobalWAF(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// Create a real WAF instance
	wafInst, err := waf.New(s, waf.Config{Enabled: true, Mode: "block", Ruleset: "owasp-crs", ParanoiaLevel: 1}, nil, nil, "block")
	if err != nil {
		t.Fatalf("waf.New: %v", err)
	}
	SetGlobalWAF(wafInst)
	defer SetGlobalWAF(nil)

	h := &WAFHandler{Enabled: true, RouteID: 0}
	next := &mockHandler{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	if err := h.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Error("expected next handler to be called for benign request")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestWAFHandler_ServeHTTP_WithRouteWAF(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	r := &store.Route{Domain: "waf-route.com", Backend: "http://localhost:3001", Enabled: true, WAFMode: "block", WAFEnabled: true}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	wafInst, err := waf.New(s, waf.Config{Enabled: true, Mode: "block", Ruleset: "owasp-crs", ParanoiaLevel: 1}, nil, &r.ID, "block")
	if err != nil {
		t.Fatalf("waf.New: %v", err)
	}
	SetRouteWAF(r.ID, wafInst)
	defer ClearRouteWAFs()

	h := &WAFHandler{Enabled: true, RouteID: r.ID}
	next := &mockHandler{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	if err := h.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Error("expected next handler to be called for benign request")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestWAFHandler_ServeHTTP_Blocked(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// Create a real WAF instance
	wafInst, err := waf.New(s, waf.Config{Enabled: true, Mode: "block", Ruleset: "owasp-crs", ParanoiaLevel: 1}, nil, nil, "block")
	if err != nil {
		t.Fatalf("waf.New: %v", err)
	}
	SetGlobalWAF(wafInst)
	defer SetGlobalWAF(nil)

	h := &WAFHandler{Enabled: true, RouteID: 0}
	next := &mockHandler{}
	w := httptest.NewRecorder()
	// SQL injection pattern should be blocked by CRS
	req := httptest.NewRequest("GET", "/?id=1%20UNION%20SELECT%20password%20FROM%20users", nil)

	if err := h.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if next.called {
		t.Error("expected next handler NOT to be called for blocked request")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}
}

func TestWAFHandler_CaddyModule(t *testing.T) {
	h := &WAFHandler{}
	info := h.CaddyModule()
	if info.ID != "http.handlers.waf" {
		t.Errorf("expected module id http.handlers.waf, got %s", info.ID)
	}
	if info.New == nil {
		t.Error("expected New function")
	}
	// Verify New returns a new instance
	mod := info.New()
	if mod == nil {
		t.Error("expected new module instance")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstr(s, substr))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
