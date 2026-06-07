package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockNextHandler struct {
	called bool
}

func (m *mockNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

func TestRateLimitHandler_Validate(t *testing.T) {
	h := &RateLimitHandler{Rate: 10, Burst: 5}
	if err := h.Validate(); err != nil {
		t.Errorf("expected valid, got %v", err)
	}

	h = &RateLimitHandler{Rate: 0, Burst: 5}
	if err := h.Validate(); err == nil {
		t.Error("expected error for zero rate")
	}

	h = &RateLimitHandler{Rate: 10, Burst: 0}
	if err := h.Validate(); err == nil {
		t.Error("expected error for zero burst")
	}
}

func TestRateLimitHandler_ServeHTTP_Allowed(t *testing.T) {
	h := &RateLimitHandler{Rate: 10, Burst: 5}
	next := &mockNextHandler{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	if err := h.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Error("expected next handler to be called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRateLimitHandler_ServeHTTP_Exceeded(t *testing.T) {
	h := &RateLimitHandler{Rate: 2, Burst: 2}
	next := &mockNextHandler{}

	// Exhaust the burst
	for i := 0; i < h.Burst; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.0.2.1:12345"
		_ = h.ServeHTTP(w, req, next)
	}

	// Next request should be rate limited
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"

	if err := h.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
}

func TestRateLimitHandler_ServeHTTP_WindowReset(t *testing.T) {
	// Manually create a bucket at the old window
	ip := "192.0.2.2"
	ipBucketsMu.Lock()
	ipBuckets[ip] = &ipBucket{count: 999, window: time.Now().Add(-2 * time.Minute).Truncate(time.Minute)}
	ipBucketsMu.Unlock()

	h := &RateLimitHandler{Rate: 10, Burst: 5}
	next := &mockNextHandler{}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip + ":12345"

	if err := h.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	// Old bucket should be replaced, so request passes
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 after window reset, got %d", w.Code)
	}
}

func TestRateLimitHandler_ServeHTTP_DifferentIPs(t *testing.T) {
	h := &RateLimitHandler{Rate: 1, Burst: 1}

	// First IP hits limit
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.0.2.3:12345"
		_ = h.ServeHTTP(w, req, &mockNextHandler{})
	}

	// Different IP should still be allowed
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.4:12345"
	next := &mockNextHandler{}

	if err := h.ServeHTTP(w, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for different IP, got %d", w.Code)
	}
}

func TestRateLimitHandler_CaddyModule(t *testing.T) {
	h := &RateLimitHandler{}
	info := h.CaddyModule()
	if info.ID != "http.handlers.rate_limit" {
		t.Errorf("expected module id http.handlers.rate_limit, got %s", info.ID)
	}
}
