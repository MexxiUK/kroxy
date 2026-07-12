package proxy

import (
	"net/http/httptest"
	"testing"
)

func TestStripInternalHeadersHandler_RemovesKroxyHeaders(t *testing.T) {
	h := &StripInternalHeadersHandler{}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Kroxy-WAF-Verified", "spoofed")
	req.Header.Set("X-Kroxy-Health-Check", "true")
	req.Header.Set("X-Custom-Header", "keep")

	next := &mockNextHandler{}
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if req.Header.Get("X-Kroxy-WAF-Verified") != "" {
		t.Error("expected X-Kroxy-WAF-Verified to be stripped")
	}
	if req.Header.Get("X-Kroxy-Health-Check") != "" {
		t.Error("expected X-Kroxy-Health-Check to be stripped")
	}
	if req.Header.Get("X-Custom-Header") != "keep" {
		t.Error("expected X-Custom-Header to be preserved")
	}
	if !next.called {
		t.Error("expected next handler to be called")
	}
}
