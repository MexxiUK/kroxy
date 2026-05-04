//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/kroxy/kroxy/internal/testutil"
)

// newTestServer spins up an httptest.Server with the API handler.
func newTestServer(t *testing.T) (string, func()) {
	t.Helper()
	os.Setenv("KROXY_INSECURE_COOKIES", "true")

	s, cleanupStore := testutil.NewTestStore(t)
	a := New(s)
	server := httptest.NewServer(a)

	cleanup := func() {
		server.Close()
		cleanupStore()
		os.Unsetenv("KROXY_INSECURE_COOKIES")
	}
	return server.URL, cleanup
}

// newAuthenticatedClient sets up the test server, creates an admin user,
// logs in, and returns the base URL, an authenticated http.Client, and a cleanup function.
func newAuthenticatedClient(t *testing.T) (string, *http.Client, func()) {
	t.Helper()
	baseURL, cleanup := newTestServer(t)
	client, csrfToken := testutil.AdminClient(t, baseURL)

	// Wrap client transport with CSRF injection
	baseTransport := client.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	client.Transport = &testutil.CSRFTransport{
		Base:      baseTransport,
		CSRFToken: csrfToken,
	}

	return baseURL, client, cleanup
}

func TestStatus(t *testing.T) {
	baseURL, cleanup := newTestServer(t)
	defer cleanup()

	resp, err := http.Get(baseURL + "/api/status")
	if err != nil {
		t.Fatalf("GET /api/status failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if body["status"] != "running" {
		t.Fatalf("expected status running, got %v", body["status"])
	}
}

func TestHealth(t *testing.T) {
	baseURL, cleanup := newTestServer(t)
	defer cleanup()

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestCSRF(t *testing.T) {
	baseURL, cleanup := newTestServer(t)
	defer cleanup()

	resp, err := http.Get(baseURL + "/api/csrf")
	if err != nil {
		t.Fatalf("GET /api/csrf failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if body["csrf_token"] == "" {
		t.Fatal("expected csrf_token in response")
	}
	// Verify cookie is set
	cookies := resp.Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "csrf_token" && c.Value == body["csrf_token"] {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected csrf_token cookie to be set")
	}
}

func TestSetup_FirstUser(t *testing.T) {
	baseURL, cleanup := newTestServer(t)
	defer cleanup()

	// First setup should succeed
	body := map[string]string{
		"email":    "admin@kroxy.local",
		"password": "AdminPass1!123",
		"name":     "Admin",
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/api/setup", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	// Second setup should be rejected
	resp2, err := http.Post(baseURL+"/api/setup", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("second setup failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp2.StatusCode)
	}
}

func TestLogin_Success(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	// Use the client to verify the session works
	resp, err := client.Get(baseURL + "/api/user")
	if err != nil {
		t.Fatalf("GET /api/user failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if user["email"] != "admin@kroxy.local" {
		t.Fatalf("expected admin@kroxy.local, got %v", user["email"])
	}
}

func TestLogin_Failure(t *testing.T) {
	baseURL, cleanup := newTestServer(t)
	defer cleanup()

	// Setup admin first
	setupBody := map[string]string{
		"email":    "admin@kroxy.local",
		"password": "AdminPass1!123",
		"name":     "Admin",
	}
	b, _ := json.Marshal(setupBody)
	resp, _ := http.Post(baseURL+"/api/setup", "application/json", bytes.NewReader(b))
	resp.Body.Close()

	// Try wrong password
	loginBody := map[string]string{
		"email":    "admin@kroxy.local",
		"password": "wrongpassword",
	}
	b, _ = json.Marshal(loginBody)
	resp, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if body["error"] != "Invalid credentials" {
		t.Fatalf("expected generic error, got %v", body["error"])
	}
}

func TestLogin_AccountLockout(t *testing.T) {
	baseURL, cleanup := newTestServer(t)
	defer cleanup()

	// Setup admin
	setupBody := map[string]string{
		"email":    "admin@kroxy.local",
		"password": "AdminPass1!123",
		"name":     "Admin",
	}
	b, _ := json.Marshal(setupBody)
	resp, _ := http.Post(baseURL+"/api/setup", "application/json", bytes.NewReader(b))
	resp.Body.Close()

	// 3 failed attempts
	loginBody := map[string]string{
		"email":    "admin@kroxy.local",
		"password": "wrongpassword",
	}
	b, _ = json.Marshal(loginBody)
	for i := 0; i < 3; i++ {
		resp, _ := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(b))
		resp.Body.Close()
	}

	// 4th attempt with correct password should still be locked out
	correctBody := map[string]string{
		"email":    "admin@kroxy.local",
		"password": "AdminPass1!123",
	}
	b, _ = json.Marshal(correctBody)
	resp, err := http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 (locked out), got %d", resp.StatusCode)
	}
}

func TestListUsers_NoPasswordLeak(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	resp, err := client.Get(baseURL + "/api/users")
	if err != nil {
		t.Fatalf("GET /api/users failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var users []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(users) == 0 {
		t.Fatal("expected at least one user")
	}
	for _, u := range users {
		if _, ok := u["password"]; ok && u["password"] != "" {
			t.Fatalf("password field should be empty, got %v", u["password"])
		}
	}
}

func TestCreateUser(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	body := map[string]string{
		"email":    "newuser@example.com",
		"password": "NewUserPass1!",
		"name":     "New User",
	}
	b, _ := json.Marshal(body)
	resp, err := client.Post(baseURL+"/api/users", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /api/users failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if user["email"] != "newuser@example.com" {
		t.Fatalf("expected newuser@example.com, got %v", user["email"])
	}
}

func TestDeleteUser(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	// Create another user
	body := map[string]string{
		"email":    "delete.me@example.com",
		"password": "DeleteMe1!123",
		"name":     "Delete Me",
	}
	b, _ := json.Marshal(body)
	resp, _ := client.Post(baseURL+"/api/users", "application/json", bytes.NewReader(b))
	var created map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	userID := int(created["id"].(float64))

	req, _ := http.NewRequest(http.MethodDelete, baseURL+"/api/users/"+strconv.Itoa(userID), nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DELETE /api/users failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

func TestCreateRoute_SSRFValidation(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	tests := []struct {
		name    string
		backend string
		wantErr bool
	}{
		{"valid backend", "http://1.1.1.1", false},
		{"localhost blocked", "http://localhost:3000", true},
		{"private IP blocked", "http://10.0.0.1:3000", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]interface{}{
				"domain":   "test.example.com",
				"backend":  tt.backend,
				"enabled":  true,
				"waf_mode": "block",
			}
			b, _ := json.Marshal(body)
			resp, err := client.Post(baseURL+"/api/routes", "application/json", bytes.NewReader(b))
			if err != nil {
				t.Fatalf("POST /api/routes failed: %v", err)
			}
			defer resp.Body.Close()
			if tt.wantErr && resp.StatusCode == http.StatusCreated {
				t.Fatal("expected error for invalid backend")
			}
			if !tt.wantErr && resp.StatusCode != http.StatusCreated {
				t.Fatalf("expected 201, got %d", resp.StatusCode)
			}
		})
	}
}

func TestCreateAndDeleteRoute(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	body := map[string]interface{}{
		"domain":   "route.example.com",
		"backend":  "http://1.1.1.1",
		"enabled":  true,
		"waf_mode": "block",
	}
	b, _ := json.Marshal(body)
	resp, err := client.Post(baseURL+"/api/routes", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /api/routes failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	// List routes
	resp, err = client.Get(baseURL + "/api/routes")
	if err != nil {
		t.Fatalf("GET /api/routes failed: %v", err)
	}
	defer resp.Body.Close()
	var listBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&listBody); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	routes := listBody["routes"].([]interface{})
	if len(routes) == 0 {
		t.Fatal("expected at least one route")
	}
}

func TestCreateWebhook_URLValidation(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	body := map[string]interface{}{
		"name":    "test-webhook",
		"url":     "https://1.1.1.1/notify",
		"events":  "alert",
		"enabled": true,
	}
	b, _ := json.Marshal(body)
	resp, err := client.Post(baseURL+"/api/webhooks", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /api/webhooks failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	// Invalid URL should be rejected
	body["url"] = "http://localhost:3000"
	b, _ = json.Marshal(body)
	resp, err = client.Post(baseURL+"/api/webhooks", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /api/webhooks failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for localhost URL, got %d", resp.StatusCode)
	}
}

func TestGenerateAPIKey(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	body := map[string]string{"name": "test-key"}
	b, _ := json.Marshal(body)
	resp, err := client.Post(baseURL+"/api/auth/api-key", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /api/user/api-key failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if result["key_id"] == "" {
		t.Fatal("expected key_id")
	}
	if result["key_secret"] == "" {
		t.Fatal("expected key_secret")
	}

	// Delete the key
	req, _ := http.NewRequest(http.MethodDelete, baseURL+"/api/user/api-keys/"+result["key_id"], nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DELETE /api/user/api-keys failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
}

func TestAPIKey_DurationValidation(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	body := map[string]string{
		"name":     "test-key",
		"duration": "-1h",
	}
	b, _ := json.Marshal(body)
	resp, err := client.Post(baseURL+"/api/auth/api-key", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /api/user/api-key failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative duration, got %d", resp.StatusCode)
	}
}

func TestChangePassword(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	body := map[string]string{
		"current_password": "AdminPass1!123",
		"new_password":     "NewPass1234!!",
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, baseURL+"/api/user/password", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT /api/user/password failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Old password should no longer work
	loginBody := map[string]string{
		"email":    "admin@kroxy.local",
		"password": "AdminPass1!123",
	}
	b, _ = json.Marshal(loginBody)
	resp, err = http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for old password, got %d", resp.StatusCode)
	}
}

func TestChangePassword_WeakPassword(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	body := map[string]string{
		"current_password": "AdminPass1!123",
		"new_password":     "short",
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, baseURL+"/api/user/password", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT /api/user/password failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak password, got %d", resp.StatusCode)
	}
}

func TestDisable2FA_NotEnabled(t *testing.T) {
	baseURL, client, cleanup := newAuthenticatedClient(t)
	defer cleanup()

	// Disabling 2FA when not enabled should return 400
	body := map[string]string{
		"password": "AdminPass1!123",
		"code":     "000000",
	}
	b, _ := json.Marshal(body)
	resp, err := client.Post(baseURL+"/api/user/2fa/disable", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /api/user/2fa/disable failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 when 2FA not enabled, got %d", resp.StatusCode)
	}
}
