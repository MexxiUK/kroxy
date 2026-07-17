package dto

import (
	"testing"
	"time"

	"github.com/kroxy/kroxy/internal/store"
)

func TestMaskIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"ipv4", "192.168.1.100", "192.168.1.0"},
		{"ipv4_last", "10.0.0.1", "10.0.0.0"},
		{"ipv6", "2001:db8::1", "***"},
		{"ipv6_loopback", "::1", "***"},
		{"empty", "", ""},
		{"invalid", "not-an-ip", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskIP(tt.input)
			if got != tt.expected {
				t.Fatalf("MaskIP(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestRouteRequest_ToStore_PreservesOIDCProviderID(t *testing.T) {
	req := RouteRequest{
		Domain:           "example.com",
		Backend:          "http://localhost:8080",
		Enabled:          true,
		OIDCEnabled:      true,
		OIDCProviderID:   7,
		WAFParanoiaLevel: 2,
	}
	got := req.ToStore()
	if got.OIDCProviderID != 7 {
		t.Fatalf("ToStore OIDCProviderID = %d, want 7", got.OIDCProviderID)
	}
	if got.IsAdminRoute {
		t.Fatalf("ToStore must force IsAdminRoute=false")
	}
}

func TestRouteFromStore_IncludesOIDCProviderID(t *testing.T) {
	now := time.Now()
	r := store.Route{
		ID:             3,
		Domain:         "example.com",
		Backend:        "http://1.1.1.1:8080",
		OIDCEnabled:    true,
		OIDCProviderID: 7,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	got := RouteFromStore(r)
	if got.OIDCProviderID != 7 {
		t.Fatalf("RouteFromStore OIDCProviderID = %d, want 7", got.OIDCProviderID)
	}
	if got.Backend != r.Backend {
		t.Fatalf("RouteFromStore Backend = %q, want %q", got.Backend, r.Backend)
	}
}
