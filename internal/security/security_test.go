package security

import (
	"net/http"
	"os"
	"sync"
	"testing"
)

func TestGetClientIP_Direct(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "192.0.2.1:12345",
		Header:     make(http.Header),
	}
	ip := GetClientIP(req)
	if ip != "192.0.2.1" {
		t.Fatalf("expected 192.0.2.1, got %s", ip)
	}
}

func TestGetClientIP_TrustedProxy(t *testing.T) {
	// Clear any cached trusted proxies so we start fresh
	cachedTrustedProxies = nil
	trustedProxiesOnce = sync.Once{}
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_TRUSTED_PROXIES", "192.168.1.1")
	defer os.Unsetenv("KROXY_TRUSTED_PROXIES")

	req := &http.Request{
		RemoteAddr: "192.168.1.1:12345",
		Header:     make(http.Header),
	}
	// X-Forwarded-For with rightmost trusted proxy and then client IP
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.1, 192.168.1.1")
	ip := GetClientIP(req)
	if ip != "203.0.113.1" {
		t.Fatalf("expected 203.0.113.1 (first non-trusted from right), got %s", ip)
	}
}

func TestGetClientIP_UntrustedProxy(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "10.0.0.1:12345", // untrusted
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	ip := GetClientIP(req)
	if ip != "10.0.0.1" {
		t.Fatalf("expected direct RemoteAddr 10.0.0.1, got %s", ip)
	}
}

func TestGetClientIP_IPSpoofing(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345", // localhost is trusted
		Header:     make(http.Header),
	}
	// Leftmost attacker IP must be ignored
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 192.168.1.100, 127.0.0.1")
	ip := GetClientIP(req)
	if ip != "192.168.1.100" {
		t.Fatalf("expected 192.168.1.100 (ignoring leftmost spoof), got %s", ip)
	}
}

func TestGetClientIP_InvalidXFF(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345", // localhost is trusted
		Header:     make(http.Header),
	}
	// Malformed/attacker-controlled entries should be skipped; the valid client
	// IP to the left of the trusted proxy should be returned.
	req.Header.Set("X-Forwarded-For", "not-an-ip, 203.0.113.1, 127.0.0.1")
	ip := GetClientIP(req)
	if ip != "203.0.113.1" {
		t.Fatalf("expected 203.0.113.1 after skipping invalid entries, got %s", ip)
	}
}
