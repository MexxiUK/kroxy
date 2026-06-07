package testutil

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// AdminClient creates an admin user via setup, logs in, completes mandatory TOTP
// setup if required, and returns an http.Client with cookies, a CSRF token value,
// and the TOTP secret (empty string if TOTP was not set up during the flow).
func AdminClient(t *testing.T, baseURL string) (*http.Client, string, string) {
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

	// Helper to fetch CSRF token
	fetchCSRF := func() string {
		resp, err := client.Get(baseURL + "/api/csrf")
		if err != nil {
			t.Fatalf("csrf request: %v", err)
		}
		var csrfResp struct {
			Token string `json:"csrf_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&csrfResp); err != nil {
			resp.Body.Close()
			t.Fatalf("decode csrf response: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("csrf unexpected status: %d", resp.StatusCode)
		}
		return csrfResp.Token
	}

	// Helper to login and return the TOTP secret if setup is required
	loginAndSetupTOTP := func() (csrfToken string, totpSecret string) {
		loginBody, _ := json.Marshal(map[string]string{
			"email":    "admin@kroxy.local",
			"password": "AdminPass1!123",
		})
		resp, err := client.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
		if err != nil {
			t.Fatalf("login request: %v", err)
		}
		var loginResp struct {
			SessionID        string `json:"session_id"`
			Requires2FA      bool   `json:"requires_2fa"`
			PendingID        string `json:"pending_id"`
			Setup2FARequired bool   `json:"setup_2fa_required"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
			resp.Body.Close()
			t.Fatalf("decode login response: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login unexpected status: %d", resp.StatusCode)
		}

		csrfToken = fetchCSRF()

		// If this is the first login and 2FA is not yet set up, do setup now.
		// Note: enable2FA invalidates all sessions, so we must re-login afterwards.
		if loginResp.Setup2FARequired {
			req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/user/2fa/setup", nil)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", csrfToken)
			resp, err = client.Do(req)
			if err != nil {
				t.Fatalf("2fa setup request: %v", err)
			}
			var setupResp struct {
				Secret string `json:"secret"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&setupResp); err != nil {
				resp.Body.Close()
				t.Fatalf("decode 2fa setup response: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("2fa setup unexpected status: %d", resp.StatusCode)
			}
			totpSecret = setupResp.Secret

			code, err := totp.GenerateCode(totpSecret, time.Now().UTC())
			if err != nil {
				t.Fatalf("generate totp code: %v", err)
			}
			enableBody, _ := json.Marshal(map[string]string{"code": code})
			req, _ = http.NewRequest(http.MethodPost, baseURL+"/api/user/2fa/enable", bytes.NewReader(enableBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", csrfToken)
			resp, err = client.Do(req)
			if err != nil {
				t.Fatalf("2fa enable request: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("2fa enable unexpected status: %d", resp.StatusCode)
			}
		}
		return csrfToken, totpSecret
	}

	// First login — may set up TOTP. Enable2FA invalidates the session.
	csrfToken, totpSecret := loginAndSetupTOTP()

	// If we set up TOTP, the session was invalidated. Re-login with 2FA verification.
	if totpSecret != "" {
		loginBody, _ := json.Marshal(map[string]string{
			"email":    "admin@kroxy.local",
			"password": "AdminPass1!123",
		})
		resp, err := client.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(loginBody))
		if err != nil {
			t.Fatalf("re-login request: %v", err)
		}
		var loginResp struct {
			Requires2FA bool   `json:"requires_2fa"`
			PendingID   string `json:"pending_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
			resp.Body.Close()
			t.Fatalf("decode re-login response: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("re-login unexpected status: %d", resp.StatusCode)
		}
		if !loginResp.Requires2FA {
			t.Fatalf("expected requires_2fa after re-login")
		}

		code, err := totp.GenerateCode(totpSecret, time.Now().UTC())
		if err != nil {
			t.Fatalf("generate totp code for verify: %v", err)
		}
		verifyBody, _ := json.Marshal(map[string]string{
			"pending_id": loginResp.PendingID,
			"code":       code,
		})
		resp, err = client.Post(baseURL+"/api/auth/2fa/verify", "application/json", bytes.NewReader(verifyBody))
		if err != nil {
			t.Fatalf("2fa verify request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("2fa verify unexpected status: %d", resp.StatusCode)
		}

		// Fetch fresh CSRF token after new session created
		csrfToken = fetchCSRF()
	}

	return client, csrfToken, totpSecret
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
