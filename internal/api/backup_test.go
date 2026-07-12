package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/crypto"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/version"
)

func newBackupAPI(t *testing.T) (*API, *store.Store, func()) {
	s, cleanupStore := newTestStore(t)
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_JWT_SECRET", "test-secret-test-secret-test-secret-test")
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	crypto.ResetEncryptionKeyForTest()
	crypto.ResetBackupHMACKeyForTest()
	a := New(s, 0)
	a.audit = audit.GetLogger()
	cleanup := func() {
		cleanupStore()
		os.Unsetenv("KROXY_JWT_SECRET")
		os.Unsetenv("KROXY_ENCRYPTION_KEY")
		crypto.ResetEncryptionKeyForTest()
		crypto.ResetBackupHMACKeyForTest()
	}
	return a, s, cleanup
}

func withAdminContext(r *http.Request) *http.Request {
	// importBackup derives the user from the session context.
	session := &auth.Session{
		ID:     "test-session",
		UserID: 1,
		Email:  "admin@kroxy.local",
		Name:   "Admin",
		Role:   "admin",
	}
	ctx := context.WithValue(r.Context(), "session", session)
	return r.WithContext(ctx)
}

func routeOnlyBackup() []byte {
	b := map[string]interface{}{
		"version": version.Version,
		"routes":  []map[string]interface{}{},
	}
	data, _ := json.Marshal(b)
	return data
}

func partialBackupWithWAFRules() []byte {
	b := map[string]interface{}{
		"version":   version.Version,
		"routes":    []map[string]interface{}{},
		"waf_rules": []map[string]interface{}{{"name": "test"}},
	}
	data, _ := json.Marshal(b)
	return data
}

func partialBackupWithSettings() []byte {
	b := map[string]interface{}{
		"version":  version.Version,
		"routes":   []map[string]interface{}{},
		"settings": map[string]string{"global_waf_mode": "block"},
	}
	data, _ := json.Marshal(b)
	return data
}

func TestImportBackup_RouteOnlyOK(t *testing.T) {
	a, _, cleanup := newBackupAPI(t)
	defer cleanup()

	body := routeOnlyBackup()
	r := httptest.NewRequest(http.MethodPost, "/api/backup/import", bytes.NewReader(body))
	r = withAdminContext(r)
	w := httptest.NewRecorder()

	a.importBackup(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for route-only backup, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImportBackup_RejectsPartialBackupWithWAFRules(t *testing.T) {
	a, _, cleanup := newBackupAPI(t)
	defer cleanup()

	body := partialBackupWithWAFRules()
	r := httptest.NewRequest(http.MethodPost, "/api/backup/import", bytes.NewReader(body))
	r = withAdminContext(r)
	w := httptest.NewRecorder()

	a.importBackup(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for partial backup with WAF rules, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImportBackup_RejectsPartialBackupWithSettings(t *testing.T) {
	a, _, cleanup := newBackupAPI(t)
	defer cleanup()

	body := partialBackupWithSettings()
	r := httptest.NewRequest(http.MethodPost, "/api/backup/import", bytes.NewReader(body))
	r = withAdminContext(r)
	w := httptest.NewRecorder()

	a.importBackup(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for partial backup with settings, got %d: %s", w.Code, w.Body.String())
	}
}

func signBackup(t *testing.T, payload backupPayload, key []byte) []byte {
	t.Helper()
	unsigned, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	mac := hmac.New(sha256.New, key)
	// #nosec G104 — hmac.Write never returns an error in practice.
	mac.Write(unsigned)
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	var body map[string]json.RawMessage
	if err := json.Unmarshal(unsigned, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	body["signature"] = json.RawMessage(`"` + sig + `"`)
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal signed backup: %v", err)
	}
	return out
}

func TestImportBackup_AcceptsDerivedHMACSignature(t *testing.T) {
	a, _, cleanup := newBackupAPI(t)
	defer cleanup()

	derivedKey, err := crypto.GetBackupHMACKey()
	if err != nil {
		t.Fatalf("get backup hmac key: %v", err)
	}
	payload := backupPayload{Version: version.Version, Routes: []store.Route{}}
	body := signBackup(t, payload, derivedKey)

	r := httptest.NewRequest(http.MethodPost, "/api/backup/import", bytes.NewReader(body))
	r = withAdminContext(r)
	w := httptest.NewRecorder()

	a.importBackup(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for signed route-only backup, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImportBackup_AcceptsLegacyRawKeySignature(t *testing.T) {
	a, _, cleanup := newBackupAPI(t)
	defer cleanup()

	rawKey, err := crypto.GetEncryptionKey()
	if err != nil {
		t.Fatalf("get encryption key: %v", err)
	}
	payload := backupPayload{Version: version.Version, Routes: []store.Route{}}
	body := signBackup(t, payload, rawKey)

	r := httptest.NewRequest(http.MethodPost, "/api/backup/import", bytes.NewReader(body))
	r = withAdminContext(r)
	w := httptest.NewRecorder()

	a.importBackup(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for legacy signed route-only backup, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImportBackup_RejectsInvalidSignature(t *testing.T) {
	a, _, cleanup := newBackupAPI(t)
	defer cleanup()

	payload := backupPayload{Version: version.Version, Routes: []store.Route{}}
	// Sign with a key that is neither the derived backup HMAC key nor the raw
	// encryption key, so both verification paths must reject it.
	wrongKey := bytes.Repeat([]byte{0xff}, 32)
	body := signBackup(t, payload, wrongKey)

	r := httptest.NewRequest(http.MethodPost, "/api/backup/import", bytes.NewReader(body))
	r = withAdminContext(r)
	w := httptest.NewRecorder()

	a.importBackup(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for invalid backup signature, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImportBackup_DetectsTamperedRouteBackend(t *testing.T) {
	a, _, cleanup := newBackupAPI(t)
	defer cleanup()

	derivedKey, err := crypto.GetBackupHMACKey()
	if err != nil {
		t.Fatalf("get backup hmac key: %v", err)
	}

	payload := backupPayload{
		Version: version.Version,
		Routes: []store.Route{
			{
				Domain:  "example.com",
				Backend: "http://original-backend:8080",
			},
		},
	}
	body := signBackup(t, payload, derivedKey)

	// Tamper with a field that is now part of the signed payload.
	var tampered map[string]interface{}
	if err := json.Unmarshal(body, &tampered); err != nil {
		t.Fatalf("unmarshal signed backup: %v", err)
	}
	routes := tampered["routes"].([]interface{})
	route := routes[0].(map[string]interface{})
	route["backend"] = "http://evil.com"
	tampered["routes"] = routes
	body, err = json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal tampered backup: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/backup/import", bytes.NewReader(body))
	r = withAdminContext(r)
	w := httptest.NewRecorder()

	a.importBackup(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for tampered route backend, got %d: %s", w.Code, w.Body.String())
	}
}
