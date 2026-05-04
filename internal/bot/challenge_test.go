package bot

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateChallenge(t *testing.T) {
	cm := NewChallengeManager("test-secret")
	nonce, diff := cm.GenerateChallenge()
	if len(nonce) != 16 {
		t.Fatalf("expected nonce length 16, got %d", len(nonce))
	}
	if diff != 18 {
		t.Fatalf("expected difficulty 18, got %d", diff)
	}
}

func TestVerifyChallenge_Success(t *testing.T) {
	cm := NewChallengeManager("test-secret")
	nonce, _ := cm.GenerateChallenge()

	// Brute-force the counter
	var counter int
	for i := 0; i < 5_000_000; i++ {
		if cm.VerifyChallenge(nonce, i) {
			counter = i
			break
		}
	}
	if counter == 0 {
		t.Fatal("could not find valid counter")
	}
	if !cm.VerifyChallenge(nonce, counter) {
		t.Fatal("expected verification to pass")
	}
}

func TestVerifyChallenge_InvalidNonce(t *testing.T) {
	cm := NewChallengeManager("test-secret")
	if cm.VerifyChallenge("short", 0) {
		t.Fatal("expected short nonce to fail")
	}
}

func TestVerifyChallenge_WrongCounter(t *testing.T) {
	cm := NewChallengeManager("test-secret")
	nonce, _ := cm.GenerateChallenge()
	if cm.VerifyChallenge(nonce, -1) {
		t.Fatal("expected negative counter to fail")
	}
	if cm.VerifyChallenge(nonce, 99999999) {
		t.Fatal("expected wrong counter to fail")
	}
}

func TestHandleVerify_NonceReplay(t *testing.T) {
	cm := NewChallengeManager("test-secret")
	secret := []byte("test-secret")

	// Find a valid counter
	nonce, _ := cm.GenerateChallenge()
	var counter int
	for i := 0; i < 5_000_000; i++ {
		if cm.VerifyChallenge(nonce, i) {
			counter = i
			break
		}
	}

	body1, _ := json.Marshal(map[string]interface{}{"nonce": nonce, "counter": counter, "elapsed": 100})
	req1 := httptest.NewRequest(http.MethodPost, "/.kroxy/challenge/verify", bytes.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	cm.HandleVerify(rec1, req1, secret)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first verify expected 200, got %d", rec1.Code)
	}

	// Replay same nonce+counter
	req2 := httptest.NewRequest(http.MethodPost, "/.kroxy/challenge/verify", bytes.NewReader(body1))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	cm.HandleVerify(rec2, req2, secret)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("replay expected 403, got %d", rec2.Code)
	}
}

func TestHandleVerify_RateLimit(t *testing.T) {
	cm := NewChallengeManager("test-secret")
	secret := []byte("test-secret")

	// Make 11 requests quickly from same IP (limit is 10/min)
	for i := 0; i < 11; i++ {
		nonce, _ := cm.GenerateChallenge()
		var counter int
		for c := 0; c < 5_000_000; c++ {
			if cm.VerifyChallenge(nonce, c) {
				counter = c
				break
			}
		}

		body, _ := json.Marshal(map[string]interface{}{"nonce": nonce, "counter": counter, "elapsed": 100})
		req := httptest.NewRequest(http.MethodPost, "/.kroxy/challenge/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		cm.HandleVerify(rec, req, secret)

		if i < 10 && rec.Code != http.StatusOK {
			t.Fatalf("request %d expected 200, got %d", i+1, rec.Code)
		}
		if i == 10 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d expected 429, got %d", i+1, rec.Code)
		}
	}
}

func TestSetPassCookie_BindsToIP(t *testing.T) {
	secret := []byte("test-secret")
	rec := httptest.NewRecorder()
	SetPassCookie(rec, "192.0.2.1", secret)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie to be set")
	}
	if cookies[0].Name != "kroxy_bot_pass" {
		t.Fatalf("expected cookie name kroxy_bot_pass, got %s", cookies[0].Name)
	}
}

func TestCheckPassCookie_WrongIP(t *testing.T) {
	secret := []byte("test-secret")
	rec := httptest.NewRecorder()
	SetPassCookie(rec, "192.0.2.1", secret)

	// Build request with cookie but different IP
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if CheckPassCookie(req, "192.0.2.2", secret) {
		t.Fatal("expected cookie to fail for different IP")
	}
}
