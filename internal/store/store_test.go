package store

import (
	"os"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	tmp, err := os.CreateTemp("", "kroxy-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	// Use temp data dir to avoid writing encryption keys to working directory
	dataDir, err := os.MkdirTemp("", "kroxy-test-data-*")
	if err != nil {
		os.Remove(tmp.Name())
		t.Fatal(err)
	}
	os.Setenv("KROXY_DATA_DIR", dataDir)

	s, err := New(tmp.Name())
	if err != nil {
		os.Remove(tmp.Name())
		os.RemoveAll(dataDir)
		os.Unsetenv("KROXY_DATA_DIR")
		t.Fatal(err)
	}

	cleanup := func() {
		s.Close()
		os.Remove(tmp.Name())
		os.RemoveAll(dataDir)
		os.Unsetenv("KROXY_DATA_DIR")
	}
	return s, cleanup
}

func TestStore_CRUD(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	// Test Create
	route := &Route{
		Domain:     "example.com",
		Backend:    "http://localhost:3000",
		Enabled:    true,
		WAFEnabled: true,
		WAFMode:    "block",
	}
	if err := s.CreateRoute(route); err != nil {
		t.Fatalf("CreateRoute failed: %v", err)
	}
	if route.ID == 0 {
		t.Fatal("Expected route ID to be set")
	}

	// Test Read
	routes, err := s.GetRoutes()
	if err != nil {
		t.Fatalf("GetRoutes failed: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("Expected 1 route, got %d", len(routes))
	}
	if routes[0].Domain != "example.com" {
		t.Fatalf("Expected domain example.com, got %s", routes[0].Domain)
	}

	// Test Update
	route.Backend = "http://localhost:4000"
	if err := s.UpdateRoute(route); err != nil {
		t.Fatalf("UpdateRoute failed: %v", err)
	}

	// Test Delete
	if err := s.DeleteRoute(route.ID); err != nil {
		t.Fatalf("DeleteRoute failed: %v", err)
	}

	routes, err = s.GetRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatalf("Expected 0 routes after delete, got %d", len(routes))
	}
}

func TestStore_UserCRUD(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	u := &User{
		Email:    "test@example.com",
		Name:     "Test User",
		Password: "hashedpassword",
		Role:     "user",
		Enabled:  true,
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if u.ID == 0 {
		t.Fatal("Expected user ID to be set")
	}

	// Get by ID
	got, err := s.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("GetUserByID failed: %v", err)
	}
	if got.Email != u.Email {
		t.Fatalf("expected email %s, got %s", u.Email, got.Email)
	}

	// Get by Email (case insensitive)
	got, err = s.GetUserByEmail("TEST@EXAMPLE.COM")
	if err != nil {
		t.Fatalf("GetUserByEmail failed: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("expected user ID %d, got %d", u.ID, got.ID)
	}

	// Update password
	if err := s.UpdateUserPassword(u.ID, "newhash"); err != nil {
		t.Fatalf("UpdateUserPassword failed: %v", err)
	}
	got, _ = s.GetUserByID(u.ID)
	if got.Password != "newhash" {
		t.Fatal("expected password to be updated")
	}

	// Update role
	if err := s.UpdateUserRole(u.ID, "admin"); err != nil {
		t.Fatalf("UpdateUserRole failed: %v", err)
	}
	got, _ = s.GetUserByID(u.ID)
	if got.Role != "admin" {
		t.Fatalf("expected role admin, got %s", got.Role)
	}

	// Update enabled
	if err := s.UpdateUserEnabled(u.ID, false); err != nil {
		t.Fatalf("UpdateUserEnabled failed: %v", err)
	}
	got, _ = s.GetUserByID(u.ID)
	if got.Enabled {
		t.Fatal("expected user to be disabled")
	}

	// Delete user
	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}
	_, err = s.GetUserByID(u.ID)
	if err == nil {
		t.Fatal("expected user to be deleted")
	}
}

func TestStore_SessionCRUD(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	sess := &Session{
		ID:           "test-session-id",
		UserEmail:    "user@example.com",
		UserName:     "User",
		UserID:       "1",
		ProviderName: "local",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	got, err := s.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if got.UserEmail != sess.UserEmail {
		t.Fatalf("expected email %s, got %s", sess.UserEmail, got.UserEmail)
	}

	// Update expiry
	newExpiry := time.Now().Add(48 * time.Hour)
	if err := s.UpdateSessionExpiry(sess.ID, newExpiry); err != nil {
		t.Fatalf("UpdateSessionExpiry failed: %v", err)
	}
	got, _ = s.GetSession(sess.ID)
	if !got.ExpiresAt.Equal(newExpiry) {
		t.Fatal("expected expiry to be updated")
	}

	// Cleanup sessions should not delete valid sessions
	if err := s.CleanupSessions(); err != nil {
		t.Fatalf("CleanupSessions failed: %v", err)
	}
	_, err = s.GetSession(sess.ID)
	if err != nil {
		t.Fatal("expected session to still exist")
	}

	// Expire and cleanup
	s.UpdateSessionExpiry(sess.ID, time.Now().Add(-1*time.Hour))
	if err := s.CleanupSessions(); err != nil {
		t.Fatalf("CleanupSessions failed: %v", err)
	}
	_, err = s.GetSession(sess.ID)
	if err == nil {
		t.Fatal("expected expired session to be deleted")
	}

	// Delete session
	s.CreateSession(sess)
	if err := s.DeleteSession(sess.ID); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}
	_, err = s.GetSession(sess.ID)
	if err == nil {
		t.Fatal("expected session to be deleted")
	}
}

func TestStore_APIKeyCRUD(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	key := &APIKey{
		KeyID:         "key_123",
		KeySecretHash: "hash",
		UserID:        1,
		Name:          "test-key",
		CreatedAt:     time.Now(),
	}
	if err := s.CreateAPIKey(key); err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}

	got, err := s.GetAPIKey("key_123")
	if err != nil {
		t.Fatalf("GetAPIKey failed: %v", err)
	}
	if got.Name != "test-key" {
		t.Fatalf("expected name test-key, got %s", got.Name)
	}

	keys, err := s.GetAPIKeysByUser(1)
	if err != nil {
		t.Fatalf("GetAPIKeysByUser failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// Delete by keyID
	if err := s.DeleteAPIKey("key_123"); err != nil {
		t.Fatalf("DeleteAPIKey failed: %v", err)
	}
	_, err = s.GetAPIKey("key_123")
	if err == nil {
		t.Fatal("expected key to be deleted")
	}

	// Create again for DeleteAPIKeyByUser test
	s.CreateAPIKey(key)
	deleted, err := s.DeleteAPIKeyByUser("key_123", 1)
	if err != nil {
		t.Fatalf("DeleteAPIKeyByUser failed: %v", err)
	}
	if !deleted {
		t.Fatal("expected deletion to succeed")
	}
	deleted, err = s.DeleteAPIKeyByUser("key_123", 2)
	if err != nil {
		t.Fatalf("DeleteAPIKeyByUser unexpected error: %v", err)
	}
	if deleted {
		t.Fatal("expected deletion to fail for wrong user")
	}
}

func TestStore_OIDCProviderCRUD(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	p := &OIDCProvider{
		Name:         "google",
		ClientID:     "client-id",
		ClientSecret: "secret",
		DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
		RedirectURL:  "https://app.example.com/callback",
	}
	if err := s.CreateOIDCProvider(p); err != nil {
		t.Fatalf("CreateOIDCProvider failed: %v", err)
	}
	if p.ID == 0 {
		t.Fatal("Expected provider ID to be set")
	}

	got, err := s.GetOIDCProvider(p.ID)
	if err != nil {
		t.Fatalf("GetOIDCProvider failed: %v", err)
	}
	if got.Name != "google" {
		t.Fatalf("expected name google, got %s", got.Name)
	}

	// Update
	p.Name = "github"
	if err := s.UpdateOIDCProvider(p); err != nil {
		t.Fatalf("UpdateOIDCProvider failed: %v", err)
	}
	got, _ = s.GetOIDCProvider(p.ID)
	if got.Name != "github" {
		t.Fatalf("expected name github, got %s", got.Name)
	}
}

func TestStore_FailedAttemptsAndLockout(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	email := "user@example.com"
	for i := 0; i < 3; i++ {
		if err := s.RecordFailedAttempt(email, 3, 15*time.Minute); err != nil {
			t.Fatalf("RecordFailedAttempt failed: %v", err)
		}
	}

	locked, lockedUntil, err := s.IsLocked(email)
	if err != nil {
		t.Fatalf("IsLocked failed: %v", err)
	}
	if !locked {
		t.Fatal("expected account to be locked")
	}
	if lockedUntil == nil {
		t.Fatal("expected lockout time")
	}

	// Clear attempts
	if err := s.ClearFailedAttempts(email); err != nil {
		t.Fatalf("ClearFailedAttempts failed: %v", err)
	}
	locked, _, err = s.IsLocked(email)
	if err != nil {
		t.Fatalf("IsLocked after clear failed: %v", err)
	}
	if locked {
		t.Fatal("expected account to be unlocked after clear")
	}
}

func TestStore_FailedAttemptsResetAfterLockoutExpires(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	email := "expired@example.com"
	lockoutDuration := 2 * time.Second

	for i := 0; i < 3; i++ {
		if err := s.RecordFailedAttempt(email, 3, lockoutDuration); err != nil {
			t.Fatalf("RecordFailedAttempt failed: %v", err)
		}
	}

	locked, _, err := s.IsLocked(email)
	if err != nil {
		t.Fatalf("IsLocked failed: %v", err)
	}
	if !locked {
		t.Fatal("expected account to be locked")
	}

	// Wait for the lockout to expire
	time.Sleep(2 * lockoutDuration)

	// A single new failure after expiry should NOT immediately re-lock
	if err := s.RecordFailedAttempt(email, 3, lockoutDuration); err != nil {
		t.Fatalf("RecordFailedAttempt after expiry failed: %v", err)
	}

	locked, _, err = s.IsLocked(email)
	if err != nil {
		t.Fatalf("IsLocked after expiry failed: %v", err)
	}
	if locked {
		t.Fatal("expected account to be unlocked after lockout expiry and a single new failure")
	}
}

func TestStore_TokenValidation(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	// Create a user to associate tokens with
	u := &User{Email: "test@example.com", Name: "Test", Password: "hash", Role: "user", Enabled: true}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Password reset token
	tokenHash := "reset-token-hash"
	expiresAt := time.Now().Add(1 * time.Hour)
	if err := s.CreatePasswordResetToken(u.ID, tokenHash, expiresAt); err != nil {
		t.Fatalf("CreatePasswordResetToken failed: %v", err)
	}
	uid, err := s.ValidatePasswordResetToken(tokenHash)
	if err != nil {
		t.Fatalf("ValidatePasswordResetToken failed: %v", err)
	}
	if uid != u.ID {
		t.Fatalf("expected user ID %d, got %d", u.ID, uid)
	}
	// Re-validation should fail (token consumed)
	_, err = s.ValidatePasswordResetToken(tokenHash)
	if err == nil {
		t.Fatal("expected second validation to fail")
	}
}
