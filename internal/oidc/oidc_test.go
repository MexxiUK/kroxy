package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

func TestPKCEChallenge(t *testing.T) {
	verifier := "test-verifier-12345"
	challenge := pkceChallenge(verifier)

	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])

	if challenge != expected {
		t.Fatalf("expected %q, got %q", expected, challenge)
	}
}

func TestGetAuthURL_IncludesPKCEAndNonce(t *testing.T) {
	m := NewManager(nil)
	m.providers[1] = &oauthProvider{
		name: "test",
		oauthConfig: &oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Endpoint:     oauth2.Endpoint{AuthURL: "https://example.com/auth"},
			RedirectURL:  "https://kroxy.example.com/callback",
			Scopes:       []string{"openid", "email", "profile"},
		},
	}

	authURL, err := m.GetAuthURL(1, "state-123", "verifier-123", "nonce-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}
	q := u.Query()

	if got := q.Get("state"); got != "state-123" {
		t.Errorf("expected state %q, got %q", "state-123", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("expected code_challenge_method S256, got %q", got)
	}
	if got := q.Get("nonce"); got != "nonce-123" {
		t.Errorf("expected nonce %q, got %q", "nonce-123", got)
	}

	challenge := q.Get("code_challenge")
	if challenge == "" {
		t.Fatalf("auth URL missing code_challenge")
	}
	sum := sha256.Sum256([]byte("verifier-123"))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != expected {
		t.Errorf("expected code_challenge %q, got %q", expected, challenge)
	}
}
