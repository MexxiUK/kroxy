package testutil

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/store"
)

// NewTestAuth creates an auth instance with a pinned JWT secret for deterministic tests.
func NewTestAuth(t *testing.T, s *store.Store) *auth.Auth {
	t.Helper()

	os.Setenv("KROXY_JWT_SECRET", "test-secret-test-secret-test-secret-test")
	defer os.Unsetenv("KROXY_JWT_SECRET")

	return auth.New(s)
}

// CreateSession creates a valid session in the store and returns the session ID.
// The auth layer will load it from the database on first validation.
func CreateSession(t *testing.T, s *store.Store, userID int, email string) string {
	t.Helper()

	sess := &store.Session{
		ID:           auth.GenerateSecret(32),
		UserID:       storeUserID(userID),
		UserEmail:    email,
		UserName:     email,
		ProviderName: "local",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess.ID
}

// Login attempts to authenticate via the auth layer.
func Login(t *testing.T, a *auth.Auth, email, password string) (*auth.LoginResponse, error) {
	t.Helper()
	return a.Login(email, password, "127.0.0.1", "test-agent")
}

// MustLogin succeeds or fails the test immediately.
func MustLogin(t *testing.T, a *auth.Auth, email, password string) *auth.LoginResponse {
	t.Helper()
	resp, err := a.Login(email, password, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	return resp
}

// SessionCookie builds an HTTP request carrying the given session cookie.
func SessionCookie(r *http.Request, sessionID string) *http.Request {
	r.AddCookie(&http.Cookie{	// #nosec G124 — test helper cookie, not used in production
		Name:  "kroxy_session",
		Value: sessionID,
	})
	return r
}

func storeUserID(id int) string {
	// store.Session.UserID is a string column; mirror the convention used
	// in the auth layer (strconv.Itoa of the int user ID).
	var buf [32]byte
	n := 0
	if id == 0 {
		return "0"
	}
	for id > 0 {
		buf[31-n] = byte('0' + id%10)
		id /= 10
		n++
	}
	return string(buf[32-n:])
}
