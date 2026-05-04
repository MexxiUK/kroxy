package testutil

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// NewTestStore creates a temporary SQLite database, applies migrations,
// and returns the store. The caller must call cleanup when done.
func NewTestStore(t *testing.T) (*store.Store, func()) {
	t.Helper()

	tmp, err := os.CreateTemp("", "kroxy-test-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	tmp.Close()

	s, err := store.New(tmp.Name())
	if err != nil {
		os.Remove(tmp.Name())
		t.Fatalf("open store: %v", err)
	}

	cleanup := func() {
		s.Close()
		os.Remove(tmp.Name())
	}

	return s, cleanup
}

// SeedAdminUser creates an admin user with a bcrypt-hashed password.
func SeedAdminUser(t *testing.T, s *store.Store, email, password string) *store.User {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	u := &store.User{
		Email:    email,
		Name:     email,
		Password: string(hash),
		Role:     "admin",
		Enabled:  true,
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

// SeedUser creates a regular (non-admin) user with a bcrypt-hashed password.
func SeedUser(t *testing.T, s *store.Store, email, password string) *store.User {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	u := &store.User{
		Email:    email,
		Name:     email,
		Password: string(hash),
		Role:     "user",
		Enabled:  true,
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

// SeedRoute creates a test route.
func SeedRoute(t *testing.T, s *store.Store, domain, backend string) *store.Route {
	t.Helper()

	r := &store.Route{
		Domain:     domain,
		Backend:    backend,
		Enabled:    true,
		WAFEnabled: false,
	}
	if err := s.CreateRoute(r); err != nil {
		t.Fatalf("create route: %v", err)
	}
	return r
}

// SeedSession creates a persisted store session.
func SeedSession(t *testing.T, s *store.Store, userID int, email string) *store.Session {
	t.Helper()

	sess := &store.Session{
		ID:           auth.GenerateSecret(32),
		UserID:       strconv.Itoa(userID),
		UserEmail:    email,
		UserName:     email,
		ProviderName: "local",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess
}
