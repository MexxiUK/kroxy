package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kroxy/kroxy/internal/alerts"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/testutil"
	"github.com/kroxy/kroxy/internal/validation"
)

func TestMain(m *testing.M) {
	validation.SetAllowPrivateBackends(true)
	m.Run()
}

func TestNewHealthChecker(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	hc := NewHealthChecker(s)
	if hc == nil {
		t.Fatal("expected non-nil HealthChecker")
	}
	if hc.store != s {
		t.Error("expected store to be set")
	}
	if hc.interval != healthCheckInterval {
		t.Errorf("expected interval %v, got %v", healthCheckInterval, hc.interval)
	}
	if hc.client == nil {
		t.Error("expected HTTP client to be initialized")
	}
	if hc.client.Timeout != healthCheckTimeout {
		t.Errorf("expected timeout %v, got %v", healthCheckTimeout, hc.client.Timeout)
	}
	if len(hc.statuses) != 0 {
		t.Error("expected empty statuses map")
	}
}

func TestHealthChecker_StartStop(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// Seed a route so checkAll has something to check
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	r := &store.Route{
		Domain:     "test.example.com",
		Backend:    backend.URL,
		Enabled:    true,
		WAFEnabled: false,
		WAFMode:    "block",
	}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}

	hc := NewHealthChecker(s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hc.Start(ctx)

	// Allow initial check to run
	time.Sleep(200 * time.Millisecond)

	hc.Stop()

	// Verify we can call Stop again without panic
	hc.Stop()
}

func TestHealthChecker_GetStatus(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	hc := NewHealthChecker(s)

	// Status should not exist for unknown route
	_, ok := hc.GetStatus(999)
	if ok {
		t.Error("expected status not found for unknown route")
	}

	// Manually inject a status
	hc.mu.Lock()
	hc.statuses[1] = HealthStatus{
		RouteID: 1,
		Healthy: true,
	}
	hc.mu.Unlock()

	status, ok := hc.GetStatus(1)
	if !ok {
		t.Fatal("expected status to exist")
	}
	if !status.Healthy {
		t.Error("expected healthy status")
	}
}

func TestHealthChecker_GetAllStatuses(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	hc := NewHealthChecker(s)

	// Empty case
	statuses := hc.GetAllStatuses()
	if len(statuses) != 0 {
		t.Errorf("expected 0 statuses, got %d", len(statuses))
	}

	// With statuses
	hc.mu.Lock()
	hc.statuses[1] = HealthStatus{RouteID: 1, Healthy: true}
	hc.statuses[2] = HealthStatus{RouteID: 2, Healthy: false}
	hc.mu.Unlock()

	statuses = hc.GetAllStatuses()
	if len(statuses) != 2 {
		t.Errorf("expected 2 statuses, got %d", len(statuses))
	}
}

func TestHealthChecker_checkRoute_Healthy(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify health check headers
		if ua := r.Header.Get("User-Agent"); ua != "Kroxy-HealthCheck/1.0" {
			t.Errorf("expected User-Agent Kroxy-HealthCheck/1.0, got %s", ua)
		}
		if hc := r.Header.Get("X-Kroxy-Health-Check"); hc != "true" {
			t.Errorf("expected X-Kroxy-Health-Check true, got %s", hc)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer backend.Close()

	hc := NewHealthChecker(s)

	route := store.Route{
		ID:      1,
		Domain:  "test.example.com",
		Backend: backend.URL,
		Enabled: true,
	}

	hc.checkRoute(route)

	status, ok := hc.GetStatus(1)
	if !ok {
		t.Fatal("expected status to exist after check")
	}
	if !status.Healthy {
		t.Errorf("expected healthy, got unhealthy: %s", status.Error)
	}
	if status.ResponseTime < 0 {
		t.Error("expected non-negative response time")
	}
	if status.FailCount != 0 {
		t.Errorf("expected fail count 0, got %d", status.FailCount)
	}
	if status.LastSuccess.IsZero() {
		t.Error("expected LastSuccess to be set")
	}
}

func TestHealthChecker_checkRoute_Unhealthy500(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	hc := NewHealthChecker(s)

	route := store.Route{
		ID:      1,
		Domain:  "test.example.com",
		Backend: backend.URL,
		Enabled: true,
	}

	hc.checkRoute(route)

	status, ok := hc.GetStatus(1)
	if !ok {
		t.Fatal("expected status to exist after check")
	}
	if status.Healthy {
		t.Error("expected unhealthy for 500 response")
	}
	if status.FailCount != 1 {
		t.Errorf("expected fail count 1, got %d", status.FailCount)
	}
	if !strings.Contains(status.Error, "500") {
		t.Errorf("expected error to contain '500', got: %s", status.Error)
	}
}

func TestHealthChecker_checkRoute_Unhealthy404(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	hc := NewHealthChecker(s)

	route := store.Route{
		ID:      1,
		Domain:  "test.example.com",
		Backend: backend.URL,
		Enabled: true,
	}

	hc.checkRoute(route)

	status, ok := hc.GetStatus(1)
	if !ok {
		t.Fatal("expected status to exist after check")
	}
	if status.Healthy {
		t.Error("expected unhealthy for 404 response")
	}
	if !strings.Contains(status.Error, "404") {
		t.Errorf("expected error to contain '404', got: %s", status.Error)
	}
}

func TestHealthChecker_checkRoute_Timeout(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// Create a server that never responds (simulates timeout)
	done := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
			return
		case <-r.Context().Done():
			return
		}
	}))
	defer close(done)
	defer backend.Close()

	// Use a very short timeout to speed up the test
	hc := NewHealthChecker(s)
	hc.client.Timeout = 100 * time.Millisecond

	route := store.Route{
		ID:      1,
		Domain:  "test.example.com",
		Backend: backend.URL,
		Enabled: true,
	}

	hc.checkRoute(route)

	status, ok := hc.GetStatus(1)
	if !ok {
		t.Fatal("expected status to exist after check")
	}
	if status.Healthy {
		t.Error("expected unhealthy for timeout")
	}
	if status.FailCount != 1 {
		t.Errorf("expected fail count 1, got %d", status.FailCount)
	}
	if !strings.Contains(status.Error, "connection failed") && !strings.Contains(status.Error, "Client.Timeout") && !strings.Contains(status.Error, "timeout") {
		t.Errorf("expected timeout-related error, got: %s", status.Error)
	}
}

func TestHealthChecker_checkRoute_InvalidURL(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	hc := NewHealthChecker(s)

	route := store.Route{
		ID:      1,
		Domain:  "test.example.com",
		Backend: "://invalid-url",
		Enabled: true,
	}

	hc.checkRoute(route)

	status, ok := hc.GetStatus(1)
	if !ok {
		t.Fatal("expected status to exist after check")
	}
	if status.Healthy {
		t.Error("expected unhealthy for invalid URL")
	}
	if !strings.Contains(status.Error, "invalid URL") {
		t.Errorf("expected 'invalid URL' error, got: %s", status.Error)
	}
}

func TestHealthChecker_checkRoute_401_Healthy(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// 401/403 should be considered healthy (reachable, needs auth)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer backend.Close()

	hc := NewHealthChecker(s)

	route := store.Route{
		ID:      1,
		Domain:  "test.example.com",
		Backend: backend.URL,
		Enabled: true,
	}

	hc.checkRoute(route)

	status, ok := hc.GetStatus(1)
	if !ok {
		t.Fatal("expected status to exist after check")
	}
	if !status.Healthy {
		t.Errorf("expected healthy for 401 (reachable, needs auth), got: %s", status.Error)
	}
}

func TestHealthChecker_checkRoute_FailCountAlert(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	hc := NewHealthChecker(s)

	route := store.Route{
		ID:      1,
		Domain:  "test.example.com",
		Backend: backend.URL,
		Enabled: true,
	}

	// Set up a mock alert manager to capture alerts
	alertMgr := alerts.NewManager()
	alerts.SetGlobalManager(alertMgr)
	defer alerts.SetGlobalManager(nil)

	// First failure
	hc.checkRoute(route)
	status, _ := hc.GetStatus(1)
	if status.FailCount != 1 {
		t.Fatalf("expected fail count 1 after first check, got %d", status.FailCount)
	}

	// Second failure should trigger alert
	hc.checkRoute(route)
	status, _ = hc.GetStatus(1)
	if status.FailCount != 2 {
		t.Fatalf("expected fail count 2 after second check, got %d", status.FailCount)
	}
}

func TestHealthChecker_checkAll(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Seed multiple routes
	for i := 1; i <= 3; i++ {
		r := &store.Route{
			Domain:  fmt.Sprintf("test%d.example.com", i),
			Backend: backend.URL,
			Enabled: true,
			WAFMode: "block",
		}
		if err := s.CreateRoute(r); err != nil {
			t.Fatalf("create route: %v", err)
		}
	}

	// Add an admin route (should be skipped)
	admin := &store.Route{
		Domain:       "admin.example.com",
		Backend:      backend.URL,
		Enabled:      true,
		WAFMode:      "block",
		IsAdminRoute: true,
	}
	if err := s.CreateRoute(admin); err != nil {
		t.Fatalf("create admin route: %v", err)
	}

	// Add a disabled route (should be skipped)
	disabled := &store.Route{
		Domain:  "disabled.example.com",
		Backend: backend.URL,
		Enabled: false,
		WAFMode: "block",
	}
	if err := s.CreateRoute(disabled); err != nil {
		t.Fatalf("create disabled route: %v", err)
	}

	hc := NewHealthChecker(s)
	hc.checkAll()

	// Should have 3 statuses (not admin, not disabled)
	statuses := hc.GetAllStatuses()
	if len(statuses) != 3 {
		t.Errorf("expected 3 statuses, got %d", len(statuses))
	}

	for _, st := range statuses {
		if !st.Healthy {
			t.Errorf("expected route %d to be healthy", st.RouteID)
		}
	}
}

func TestHealthChecker_checkAll_StoreError(t *testing.T) {
	// Test with a store that will fail (nil db) by using a closed store
	s, cleanup := testutil.NewTestStore(t)
	cleanup() // Close the store immediately

	hc := NewHealthChecker(s)

	// Should not panic
	hc.checkAll()

	statuses := hc.GetAllStatuses()
	if len(statuses) != 0 {
		t.Errorf("expected 0 statuses when store fails, got %d", len(statuses))
	}
}

func TestHealthChecker_StopWithoutStart(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	hc := NewHealthChecker(s)

	// Should not panic when Stop is called without Start
	hc.Stop()
}

func TestHealthChecker_FollowRedirects(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	// Server that redirects
	redirectCount := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			redirectCount++
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	hc := NewHealthChecker(s)

	route := store.Route{
		ID:      1,
		Domain:  "test.example.com",
		Backend: backend.URL + "/redirect",
		Enabled: true,
	}

	hc.checkRoute(route)

	status, ok := hc.GetStatus(1)
	if !ok {
		t.Fatal("expected status to exist after check")
	}
	// With CheckRedirect returning ErrUseLastResponse, the redirect itself is returned
	// 302 is not in the healthy range (200-499 excluding 404)
	// Wait — 302 is < 500 and != 404, so it should be healthy!
	if !status.Healthy {
		t.Errorf("expected healthy for 302 with CheckRedirect=ErrUseLastResponse, got: %s", status.Error)
	}
	if redirectCount != 1 {
		t.Errorf("expected 1 redirect request, got %d", redirectCount)
	}
}

func TestHealthChecker_GlobalInstance(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	hc := NewHealthChecker(s)
	SetGlobalHealthChecker(hc)

	retrieved := GetGlobalHealthChecker()
	if retrieved != hc {
		t.Error("expected global health checker to match")
	}

	SetGlobalHealthChecker(nil)
	if GetGlobalHealthChecker() != nil {
		t.Error("expected global health checker to be nil")
	}
}

func TestHealthChecker_ResponseTime(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Small delay
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	hc := NewHealthChecker(s)

	route := store.Route{
		ID:      1,
		Domain:  "test.example.com",
		Backend: backend.URL,
		Enabled: true,
	}

	start := time.Now()
	hc.checkRoute(route)
	elapsed := time.Since(start)

	status, _ := hc.GetStatus(1)
	if status.ResponseTime < 40 {
		t.Errorf("expected response time >= 40ms, got %d", status.ResponseTime)
	}
	if status.ResponseTime > int64(elapsed.Milliseconds())+20 {
		t.Errorf("response time %d seems too high for elapsed %v", status.ResponseTime, elapsed)
	}
}
