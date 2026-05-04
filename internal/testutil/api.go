package testutil

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"testing"
)

// AdminClient creates an admin user via setup, logs in, and returns an
// http.Client with cookies and a CSRF token value.
func AdminClient(t *testing.T, baseURL string) (*http.Client, string) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	// 1. Setup admin user
	setupBody, _ := json.Marshal(map[string]string{
		"email":    "admin@kroxy.local",
		"password": "AdminPass1!123",
		"name":     "Admin",
	})
	resp, err := client.Post(baseURL+"/api/setup", "application/json", bytes.NewReader(setupBody))
	if err != nil {
		t.Fatalf("setup request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("setup unexpected status: %d", resp.StatusCode)
	}

	// 2. Login
	loginBody, _ := json.Marshal(map[string]string{
		"email":    "admin@kroxy.local",
		"password": "AdminPass1!123",
	})
	resp, err = client.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login unexpected status: %d", resp.StatusCode)
	}

	// 3. Fetch CSRF token
	resp, err = client.Get(baseURL + "/api/csrf")
	if err != nil {
		t.Fatalf("csrf request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("csrf unexpected status: %d", resp.StatusCode)
	}
	var csrfResp struct {
		Token string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&csrfResp); err != nil {
		t.Fatalf("decode csrf response: %v", err)
	}

	return client, csrfResp.Token
}

// CSRFTransport wraps an http.RoundTripper and injects X-CSRF-Token
// on mutating requests (POST, PUT, DELETE, PATCH).
type CSRFTransport struct {
	Base      http.RoundTripper
	CSRFToken string
}

func (t *CSRFTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.CSRFToken != "" && (req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodDelete || req.Method == http.MethodPatch) {
		req = req.Clone(req.Context())
		req.Header.Set("X-CSRF-Token", t.CSRFToken)
	}
	return t.Base.RoundTrip(req)
}
