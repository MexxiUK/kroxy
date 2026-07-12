package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/kroxy/kroxy/internal/crypto"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/totp"
	"github.com/pquerna/otp"
	pquernatotp "github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func newTestStore(t *testing.T) (*store.Store, func()) {
	t.Helper()
	tmp, err := os.CreateTemp("", "kroxy-auth-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G104 — test cleanup.
	tmp.Close()

	// Use temp data dir to avoid writing encryption keys to working directory
	dataDir, err := os.MkdirTemp("", "kroxy-test-data-*")
	if err != nil {
		// #nosec G104 — test cleanup on error.
		os.Remove(tmp.Name())
		t.Fatal(err)
	}
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_DATA_DIR", dataDir)

	s, err := store.New(tmp.Name())
	if err != nil {
		// #nosec G104 — test cleanup on error.
		os.Remove(tmp.Name())
		// #nosec G104 — test cleanup on error.
		os.RemoveAll(dataDir)
		os.Unsetenv("KROXY_DATA_DIR")
		t.Fatal(err)
	}

	cleanup := func() {
		// #nosec G104 — test cleanup.
		s.Close()
		// #nosec G104 — test cleanup.
		os.Remove(tmp.Name())
		// #nosec G104 — test cleanup.
		os.RemoveAll(dataDir)
		os.Unsetenv("KROXY_DATA_DIR")
	}
	return s, cleanup
}

func newTestAuth(t *testing.T) (*Auth, *store.Store, func()) {
	t.Helper()
	s, cleanupStore := newTestStore(t)
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_JWT_SECRET", "test-secret-test-secret-test-secret-test")
	defer os.Unsetenv("KROXY_JWT_SECRET")
	a := New(s)
	return a, s, cleanupStore
}

func newTestAuthWithEnv(t *testing.T, prod, insecure bool) (*Auth, *store.Store, func()) {
	t.Helper()
	s, cleanupStore := newTestStore(t)
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_JWT_SECRET", "test-secret-test-secret-test-secret-test")
	if prod {
		// #nosec G104 — test environment setup.
		os.Setenv("KROXY_PRODUCTION", "true")
	}
	if insecure {
		// #nosec G104 — test environment setup.
		os.Setenv("KROXY_INSECURE_COOKIES", "true")
	}
	a := New(s)
	cleanup := func() {
		cleanupStore()
		os.Unsetenv("KROXY_JWT_SECRET")
		os.Unsetenv("KROXY_PRODUCTION")
		os.Unsetenv("KROXY_INSECURE_COOKIES")
	}
	return a, s, cleanup
}

func TestCreateSessionCookie_ProductionIgnoresInsecureOverride(t *testing.T) {
	a, _, cleanup := newTestAuthWithEnv(t, true, true)
	defer cleanup()
	c := a.CreateSessionCookie("sid")
	if !c.Secure {
		t.Errorf("production mode must set Secure even when KROXY_INSECURE_COOKIES=true")
	}
}

func TestCreateSessionCookie_NonProductionHonoursInsecureOverride(t *testing.T) {
	a, _, cleanup := newTestAuthWithEnv(t, false, true)
	defer cleanup()
	c := a.CreateSessionCookie("sid")
	if c.Secure {
		t.Errorf("non-production mode must allow KROXY_INSECURE_COOKIES to clear Secure")
	}
}

func TestCreateSessionCookie_NonProductionSecureByDefault(t *testing.T) {
	a, _, cleanup := newTestAuthWithEnv(t, false, false)
	defer cleanup()
	c := a.CreateSessionCookie("sid")
	if !c.Secure {
		t.Errorf("non-production mode must set Secure by default")
	}
}

func TestCreate2FAPendingCookie_ProductionIgnoresInsecureOverride(t *testing.T) {
	a, _, cleanup := newTestAuthWithEnv(t, true, true)
	defer cleanup()
	c := a.Create2FAPendingCookie("pid")
	if !c.Secure {
		t.Errorf("production mode must set Secure on pending-2FA cookie even when KROXY_INSECURE_COOKIES=true")
	}
}

func seedUser(t *testing.T, s *store.Store, email, password, role string, enabled bool) *store.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{
		Email:    email,
		Name:     email,
		Password: string(hash),
		Role:     role,
		Enabled:  enabled,
	}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLogin_Success(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	seedUser(t, s, "user@example.com", "Password123!", "user", true)
	resp, err := a.Login("user@example.com", "Password123!", "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp.SessionID == "" {
		t.Fatal("expected session ID")
	}
}

func TestLogin_Failure(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	seedUser(t, s, "user@example.com", "Password123!", "user", true)
	_, err := a.Login("user@example.com", "wrongpassword", "127.0.0.1", "test")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if err.Error() != "invalid credentials" {
		t.Fatalf("expected generic error, got: %v", err)
	}
}

func TestLogin_AccountLockout(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	seedUser(t, s, "user@example.com", "Password123!", "user", true)
	for i := 0; i < 3; i++ {
		_, err := a.Login("user@example.com", "wrongpassword", "127.0.0.1", "test")
		if err == nil {
			t.Fatal("expected error")
		}
	}
	// 4th attempt should be locked out
	_, err := a.Login("user@example.com", "Password123!", "127.0.0.1", "test")
	if err == nil {
		t.Fatal("expected lockout error")
	}
	if err.Error() == "invalid credentials" {
		t.Fatal("expected lockout error, got invalid credentials")
	}
}

func TestLogin_CaseInsensitiveEmail(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	seedUser(t, s, "User@Example.COM", "Password123!", "user", true)
	resp, err := a.Login("user@example.com", "Password123!", "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("expected success with lowercase email, got: %v", err)
	}
	if resp.SessionID == "" {
		t.Fatal("expected session ID")
	}
}

func TestValidateSession_Success(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	u := seedUser(t, s, "user@example.com", "Password123!", "user", true)
	resp, err := a.Login("user@example.com", "Password123!", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "test")
	req.AddCookie(a.CreateSessionCookie(resp.SessionID))

	sess, err := a.ValidateSession(req)
	if err != nil {
		t.Fatalf("expected valid session, got: %v", err)
	}
	if sess.UserID != u.ID {
		t.Fatalf("expected user ID %d, got %d", u.ID, sess.UserID)
	}
}

func TestValidateSession_Expired(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	seedUser(t, s, "user@example.com", "Password123!", "user", true)
	resp, err := a.Login("user@example.com", "Password123!", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}

	// Manually expire the session in store
	// #nosec G104 — test setup.
	s.UpdateSessionExpiry(resp.SessionID, time.Now().Add(-1*time.Hour))
	// Also delete from in-memory cache so it falls back to DB
	a.sessions.Delete(resp.SessionID)

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(a.CreateSessionCookie(resp.SessionID))

	_, err = a.ValidateSession(req)
	if err == nil {
		t.Fatal("expected expired session to fail")
	}
}

func TestValidateSession_DisabledUser(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	u := seedUser(t, s, "user@example.com", "Password123!", "user", true)
	resp, err := a.Login("user@example.com", "Password123!", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}

	// Disable user
	if err := s.UpdateUserEnabled(u.ID, false); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(a.CreateSessionCookie(resp.SessionID))

	_, err = a.ValidateSession(req)
	if err == nil {
		t.Fatal("expected disabled user session to fail")
	}
}

func TestValidateAPIKey_Success(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	u := seedUser(t, s, "user@example.com", "Password123!", "user", true)
	keyID, keySecret, err := a.GenerateAPIKey(u.ID, "test-key", nil)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "ApiKey "+keyID+":"+keySecret)

	apiKey, err := a.validateAPIKey(req)
	if err != nil {
		t.Fatalf("expected valid API key, got: %v", err)
	}
	if apiKey.KeyID != keyID {
		t.Fatalf("expected key ID %s, got %s", keyID, apiKey.KeyID)
	}
}

func TestValidateAPIKey_InvalidSecret(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	u := seedUser(t, s, "user@example.com", "Password123!", "user", true)
	keyID, _, err := a.GenerateAPIKey(u.ID, "test-key", nil)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "ApiKey "+keyID+":wrongsecret")

	_, err = a.validateAPIKey(req)
	if err == nil {
		t.Fatal("expected invalid API key secret error")
	}
	if err.Error() != "invalid API key secret" {
		t.Fatalf("expected generic error, got: %v", err)
	}
}

func TestRequireAuth_APIKey_SetsUserContext(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	u := seedUser(t, s, "admin@example.com", "Password123!", "admin", true)
	keyID, keySecret, err := a.GenerateAPIKey(u.ID, "admin-key", nil)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/api/routes", nil)
	req.Header.Set("Authorization", "ApiKey "+keyID+":"+keySecret)

	var got *User
	handler := a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = GetUserFromContext(r.Context())
	}))

	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got == nil {
		t.Fatal("GetUserFromContext returned nil for API-key auth")
	}
	if got.ID != u.ID {
		t.Errorf("expected user ID %d, got %d", u.ID, got.ID)
	}
	if got.Role != "admin" {
		t.Errorf("expected admin role, got %s", got.Role)
	}
	if got.Email != u.Email {
		t.Errorf("expected email %s, got %s", u.Email, got.Email)
	}
}

func TestGenerateAPIKey(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	u := seedUser(t, s, "user@example.com", "Password123!", "user", true)
	keyID, keySecret, err := a.GenerateAPIKey(u.ID, "test-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	if keyID == "" {
		t.Fatal("expected key ID")
	}
	if keySecret == "" {
		t.Fatal("expected key secret")
	}

	// Verify stored in database
	dbKeys, err := s.GetAPIKeysByUser(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(dbKeys) != 1 {
		t.Fatalf("expected 1 API key in DB, got %d", len(dbKeys))
	}
	// Verify bcrypt hash
	if err := bcrypt.CompareHashAndPassword([]byte(dbKeys[0].KeySecretHash), []byte(keySecret)); err != nil {
		t.Fatal("expected bcrypt hash to match secret")
	}
	// Verify HMAC pre-check value is populated
	if dbKeys[0].KeySecretHMAC == "" {
		t.Fatal("expected HMAC pre-check value to be stored")
	}
}

func TestChangePassword(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	u := seedUser(t, s, "user@example.com", "OldPass123!", "user", true)
	// Create a session first
	resp, _ := a.Login("user@example.com", "OldPass123!", "127.0.0.1", "test")

	err := a.ChangePassword(u.ID, "OldPass123!", "NewPass456!")
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	// Old password should fail
	_, err = a.Login("user@example.com", "OldPass123!", "127.0.0.1", "test")
	if err == nil {
		t.Fatal("expected old password to fail")
	}

	// New password should succeed
	_, err = a.Login("user@example.com", "NewPass456!", "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("expected new password to succeed, got: %v", err)
	}

	// Old session should be invalidated
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(a.CreateSessionCookie(resp.SessionID))
	_, err = a.ValidateSession(req)
	if err == nil {
		t.Fatal("expected session to be invalidated after password change")
	}
}

func TestVerify2FA_Success(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	// Generate TOTP secret
	secret, _, err := totp.GenerateSecret("kroxy", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	encSecret, err := crypto.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}

	u := seedUser(t, s, "user@example.com", "Password123!", "user", true)
	// Update user with TOTP secret
	if err := s.UpdateTOTPSecret(u.ID, encSecret); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableTOTP(u.ID); err != nil {
		t.Fatal(err)
	}

	// Login should return pending 2FA
	resp, err := a.Login("user@example.com", "Password123!", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Requires2FA {
		t.Fatal("expected 2FA to be required")
	}

	// Generate valid TOTP code
	code, err := pquernatotp.GenerateCodeCustom(secret, time.Now().UTC(), pquernatotp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
		Skew:      0,
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyResp, err := a.Verify2FA(resp.PendingID, code, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("expected 2FA verification success, got: %v", err)
	}
	if verifyResp.SessionID == "" {
		t.Fatal("expected session ID after 2FA verification")
	}
}

func TestVerify2FA_TooManyAttempts(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	secret, _, err := totp.GenerateSecret("kroxy", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	encSecret, err := crypto.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}

	u := seedUser(t, s, "user@example.com", "Password123!", "user", true)
	if err := s.UpdateTOTPSecret(u.ID, encSecret); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableTOTP(u.ID); err != nil {
		t.Fatal(err)
	}

	resp, err := a.Login("user@example.com", "Password123!", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}

	// 5 wrong attempts
	for i := 0; i < 5; i++ {
		_, err := a.Verify2FA(resp.PendingID, "000000", "127.0.0.1", "test")
		if err == nil {
			t.Fatal("expected error for wrong code")
		}
	}

	// 6th attempt should be locked out (pending session deleted after 5 attempts)
	_, err = a.Verify2FA(resp.PendingID, "000000", "127.0.0.1", "test")
	if err == nil {
		t.Fatal("expected lockout error")
	}
}

func TestVerify2FA_SessionBindingMismatch(t *testing.T) {
	a, s, cleanup := newTestAuth(t)
	defer cleanup()

	secret, _, err := totp.GenerateSecret("kroxy", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	encSecret, err := crypto.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}

	u := seedUser(t, s, "user@example.com", "Password123!", "user", true)
	if err := s.UpdateTOTPSecret(u.ID, encSecret); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableTOTP(u.ID); err != nil {
		t.Fatal(err)
	}

	resp, err := a.Login("user@example.com", "Password123!", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}

	code, err := pquernatotp.GenerateCodeCustom(secret, time.Now().UTC(), pquernatotp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
		Skew:      0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Different IP or User-Agent must be rejected.
	_, err = a.Verify2FA(resp.PendingID, code, "10.0.0.1", "test")
	if err == nil {
		t.Fatal("expected 2FA session binding mismatch error")
	}
	_, err = a.Verify2FA(resp.PendingID, code, "127.0.0.1", "attacker")
	if err == nil {
		t.Fatal("expected 2FA session binding mismatch error for user agent")
	}
}

func TestCheckSessionBinding_Disabled(t *testing.T) {
	a, _, cleanup := newTestAuth(t)
	defer cleanup()

	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_STRICT_SESSION_BINDING", "false")
	defer os.Unsetenv("KROXY_STRICT_SESSION_BINDING")
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	session := &Session{UserID: 1, IP: "10.0.0.1", UserAgent: "old-ua"}
	if !a.checkSessionBinding(req, session, "sess-id") {
		t.Fatal("expected binding to pass when disabled")
	}
}

func TestCheckSessionBinding_EnabledMatch(t *testing.T) {
	a, _, cleanup := newTestAuth(t)
	defer cleanup()

	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_STRICT_SESSION_BINDING", "true")
	defer os.Unsetenv("KROXY_STRICT_SESSION_BINDING")

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("User-Agent", "test-ua")

	session := &Session{UserID: 1, IP: "192.168.1.100", UserAgent: "test-ua"}
	if !a.checkSessionBinding(req, session, "sess-id") {
		t.Fatal("expected binding to pass when IP and UA match")
	}
}

func TestCheckSessionBinding_EnabledMismatch(t *testing.T) {
	a, _, cleanup := newTestAuth(t)
	defer cleanup()

	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_STRICT_SESSION_BINDING", "true")
	defer os.Unsetenv("KROXY_STRICT_SESSION_BINDING")

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("User-Agent", "attacker-ua")

	session := &Session{UserID: 1, IP: "192.168.1.100", UserAgent: "legit-ua"}
	if a.checkSessionBinding(req, session, "sess-id") {
		t.Fatal("expected binding to fail when UA mismatches")
	}
}

func TestCheckSessionBinding_LegacySession(t *testing.T) {
	a, _, cleanup := newTestAuth(t)
	defer cleanup()

	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_STRICT_SESSION_BINDING", "true")
	defer os.Unsetenv("KROXY_STRICT_SESSION_BINDING")

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("User-Agent", "attacker-ua")

	// Legacy sessions have empty IP and UA — grandfathered
	session := &Session{UserID: 1, IP: "", UserAgent: ""}
	if !a.checkSessionBinding(req, session, "sess-id") {
		t.Fatal("expected legacy session to pass")
	}
}
