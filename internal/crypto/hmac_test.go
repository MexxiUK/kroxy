package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"
)

const testBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestSignAndVerifyWAFHeader(t *testing.T) {
	// Set a known signing key for predictable results
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMzItY2hhcmFjdGVycy1sb25n")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "")
	// Reset the once for testing
	ResetSigningKeyForTest()

	signed, err := SignWAFHeader("example.com", "GET", "/api/test", 1, testBodyHash)
	if err != nil {
		t.Fatalf("SignWAFHeader failed: %v", err)
	}

	err = VerifyWAFHeader(signed, "example.com", "GET", "/api/test", 1, testBodyHash, 5*time.Minute)
	if err != nil {
		t.Errorf("VerifyWAFHeader failed: %v", err)
	}
}

func TestVerifyWAFHeader_WrongHost(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMzItY2hhcmFjdGVycy1sb25n")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "")
	ResetSigningKeyForTest()

	signed, _ := SignWAFHeader("example.com", "GET", "/api/test", 1, testBodyHash)

	err := VerifyWAFHeader(signed, "evil.com", "GET", "/api/test", 1, testBodyHash, 5*time.Minute)
	if err == nil {
		t.Error("Expected verification to fail with wrong host")
	}
}

func TestVerifyWAFHeader_WrongMethod(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMzItY2hhcmFjdGVycy1sb25n")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "")
	ResetSigningKeyForTest()

	signed, _ := SignWAFHeader("example.com", "GET", "/api/test", 1, testBodyHash)

	err := VerifyWAFHeader(signed, "example.com", "POST", "/api/test", 1, testBodyHash, 5*time.Minute)
	if err == nil {
		t.Error("Expected verification to fail with wrong method")
	}
}

func TestVerifyWAFHeader_WrongRouteID(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMzItY2hhcmFjdGVycy1sb25n")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "")
	ResetSigningKeyForTest()

	signed, _ := SignWAFHeader("example.com", "GET", "/api/test", 1, testBodyHash)

	err := VerifyWAFHeader(signed, "example.com", "GET", "/api/test", 2, testBodyHash, 5*time.Minute)
	if err == nil {
		t.Error("Expected verification to fail with wrong route ID")
	}
}

func TestVerifyWAFHeader_WrongBodyHash(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMzItY2hhcmFjdGVycy1sb25n")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "")
	ResetSigningKeyForTest()

	signed, _ := SignWAFHeader("example.com", "GET", "/api/test", 1, testBodyHash)

	err := VerifyWAFHeader(signed, "example.com", "GET", "/api/test", 1, "0000000000000000000000000000000000000000000000000000000000000000", 5*time.Minute)
	if err == nil {
		t.Error("Expected verification to fail with wrong body hash")
	}
}

func TestVerifyWAFHeader_ExpiredTimestamp(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMzItY2hhcmFjdGVycy1sb25n")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "")
	ResetSigningKeyForTest()

	// Manually construct a header with a timestamp 10 minutes in the past
	oldTimestamp := time.Now().UTC().Add(-10 * time.Minute).Unix()
	key, _ := GetWAFSigningKey()
	message := fmt.Sprintf("%d|%s|%s|%s|%d|%s", oldTimestamp, "example.com", "GET", "/api/test", 1, testBodyHash)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	header := fmt.Sprintf("v1:%d:%s", oldTimestamp, sig)

	err := VerifyWAFHeader(header, "example.com", "GET", "/api/test", 1, testBodyHash, 5*time.Minute)
	if err != ErrExpiredHeader {
		t.Errorf("Expected ErrExpiredHeader, got: %v", err)
	}
}

func TestVerifyWAFHeader_TamperedHMAC(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMzItY2hhcmFjdGVycy1sb25n")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "")
	ResetSigningKeyForTest()

	signed, _ := SignWAFHeader("example.com", "GET", "/api/test", 1, testBodyHash)

	// Tamper with the HMAC portion (last part after the second colon)
	tampered := signed[:len(signed)-4] + "XXXX"
	err := VerifyWAFHeader(tampered, "example.com", "GET", "/api/test", 1, testBodyHash, 5*time.Minute)
	if err == nil {
		t.Error("Expected verification to fail with tampered HMAC")
	}
}

func TestVerifyWAFHeader_InvalidFormat(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtYXQtbGVhc3QtMzItY2hhcmFjdGVycy1sb25n")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "")
	ResetSigningKeyForTest()

	tests := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"no colons", "invalid"},
		{"one colon", "v1:123"},
		{"wrong version", "v2:1234567890:abc"},
		{"non-numeric timestamp", "v1:notanumber:abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyWAFHeader(tt.value, "example.com", "GET", "/test", 1, testBodyHash, 5*time.Minute)
			if err == nil {
				t.Error("Expected verification to fail for invalid format")
			}
		})
	}
}

func TestGetWAFSigningKey_DevMode(t *testing.T) {
	os.Unsetenv("KROXY_WAF_SIGNING_KEY")
	os.Unsetenv("KROXY_PRODUCTION")
	ResetSigningKeyForTest()

	key, err := GetWAFSigningKey()
	if err != nil {
		t.Fatalf("GetWAFSigningKey failed in dev mode: %v", err)
	}
	if len(key) < 32 {
		t.Errorf("Expected key length >= 32, got %d", len(key))
	}
}

func TestGetWAFSigningKey_ProductionRequired(t *testing.T) {
	os.Unsetenv("KROXY_WAF_SIGNING_KEY")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "true")
	ResetSigningKeyForTest()
	defer os.Unsetenv("KROXY_PRODUCTION")

	_, err := GetWAFSigningKey()
	if err == nil {
		t.Error("Expected error when KROXY_WAF_SIGNING_KEY not set in production mode")
	}
}

func TestGetWAFSigningKey_ProductionWithKey(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dGhpcy1pcy1hLXZlcnktbG9uZy1wcm9kdWN0aW9uLWtleS10aGF0LWlzLWF0LWxlYXN0LTMyLWNoYXJz")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "true")
	ResetSigningKeyForTest()
	defer os.Unsetenv("KROXY_WAF_SIGNING_KEY")
	defer os.Unsetenv("KROXY_PRODUCTION")

	key, err := GetWAFSigningKey()
	if err != nil {
		t.Fatalf("GetWAFSigningKey failed in production mode with key: %v", err)
	}
	if string(key) != "this-is-a-very-long-production-key-that-is-at-least-32-chars" {
		t.Errorf("Key mismatch")
	}
}

func TestGetWAFSigningKey_InvalidBase64(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "not-valid-base64!!!")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "true")
	ResetSigningKeyForTest()
	defer os.Unsetenv("KROXY_WAF_SIGNING_KEY")
	defer os.Unsetenv("KROXY_PRODUCTION")

	_, err := GetWAFSigningKey()
	if err == nil {
		t.Error("Expected error when KROXY_WAF_SIGNING_KEY is not valid base64")
	}
}

func TestGetWAFSigningKey_TooShort(t *testing.T) {
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_WAF_SIGNING_KEY", "dG9vLXNob3J0") // base64 of "too-short"
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_PRODUCTION", "true")
	ResetSigningKeyForTest()
	defer os.Unsetenv("KROXY_WAF_SIGNING_KEY")
	defer os.Unsetenv("KROXY_PRODUCTION")

	_, err := GetWAFSigningKey()
	if err == nil {
		t.Error("Expected error when KROXY_WAF_SIGNING_KEY decodes to fewer than 32 bytes")
	}
}
