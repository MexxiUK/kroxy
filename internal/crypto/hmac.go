package crypto

import (
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	wafSigningKey     []byte
	wafSigningKeyOnce sync.Once
	wafKeyLoadErr     error
)

const (
	// WAFHeaderName is the HTTP header added to requests that pass WAF inspection.
	WAFHeaderName = "X-Kroxy-WAF-Verified"

	// WAFHeaderVersion is the version prefix for the header value format.
	WAFHeaderVersion = "v1"

	// WAFHeaderTimestampMaxSkew is the maximum clock skew allowed between
	// Kroxy and the verifying backend.
	WAFHeaderTimestampMaxSkew = 5 * time.Minute
)

var (
	ErrNoSigningKey  = errors.New("no WAF signing key configured")
	ErrInvalidHeader = errors.New("invalid WAF verification header format")
	ErrExpiredHeader = errors.New("WAF verification header timestamp expired")
	ErrInvalidHMAC   = errors.New("WAF verification header HMAC mismatch")
	ErrWrongVersion  = errors.New("unsupported WAF verification header version")
)

// GetWAFSigningKey returns the WAF signing key, loading it once from the
// KROXY_WAF_SIGNING_KEY environment variable. In production mode, the key
// is required. In dev mode, a random key is auto-generated.
func GetWAFSigningKey() ([]byte, error) {
	wafSigningKeyOnce.Do(func() {
		key := os.Getenv("KROXY_WAF_SIGNING_KEY")
		if key == "" {
			if os.Getenv("KROXY_PRODUCTION") == "true" {
				wafKeyLoadErr = errors.New("KROXY_WAF_SIGNING_KEY must be set in production mode")
				return
			}
			keyBytes := make([]byte, 32)
			if _, randErr := cryptoRand.Read(keyBytes); randErr != nil {
				log.Fatalf("crypto: failed to generate WAF signing key: %v", randErr)
			}
			wafSigningKey = keyBytes
			log.Println("WARNING: Using random WAF signing key (not persistent across restarts). Set KROXY_WAF_SIGNING_KEY for production use.")
			return
		}
		if len(key) < 32 {
			if os.Getenv("KROXY_PRODUCTION") == "true" {
				wafKeyLoadErr = fmt.Errorf("KROXY_WAF_SIGNING_KEY must be at least 32 characters, got %d", len(key))
				return
			}
			log.Printf("WARNING: KROXY_WAF_SIGNING_KEY is only %d characters. Recommended minimum is 32 characters.", len(key)) // #nosec G706 — %d prints an integer length, not user input
		}
		wafSigningKey = []byte(key)
	})
	return wafSigningKey, wafKeyLoadErr
}

// SignWAFHeader produces the full header value for X-Kroxy-WAF-Verified.
// The format is: v1:<unix_timestamp>:<base64_hmac>
// The HMAC covers: timestamp|host|method|path|routeID
func SignWAFHeader(host, method, path string, routeID int) (string, error) {
	key, err := GetWAFSigningKey()
	if err != nil {
		return "", err
	}

	timestamp := time.Now().UTC().Unix()
	message := fmt.Sprintf("%d|%s|%s|%s|%d",
		timestamp, host, method, path, routeID)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s:%d:%s", WAFHeaderVersion, timestamp, sig), nil
}

// VerifyWAFHeader parses and verifies a X-Kroxy-WAF-Verified header value.
// It checks the version prefix, timestamp freshness (within maxSkew),
// and recomputes the HMAC to compare against the provided signature.
func VerifyWAFHeader(headerValue, host, method, path string, routeID int, maxSkew time.Duration) error {
	parts := strings.SplitN(headerValue, ":", 3)
	if len(parts) != 3 {
		return ErrInvalidHeader
	}

	if parts[0] != WAFHeaderVersion {
		return ErrWrongVersion
	}

	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return ErrInvalidHeader
	}

	// Check timestamp freshness
	now := time.Now().UTC().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > maxSkew {
		return ErrExpiredHeader
	}

	// Recompute HMAC
	key, err := GetWAFSigningKey()
	if err != nil {
		return err
	}

	message := fmt.Sprintf("%d|%s|%s|%s|%d",
		timestamp, host, method, path, routeID)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return ErrInvalidHMAC
	}

	return nil
}

// ResetSigningKeyForTest resets the signing key state for testing.
// This is not thread-safe and should only be called in test code.
func ResetSigningKeyForTest() {
	wafSigningKey = nil
	wafKeyLoadErr = nil
	wafSigningKeyOnce = sync.Once{}
}
