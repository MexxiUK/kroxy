package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/version"
)

func newBackupAPI(t *testing.T) (*API, *store.Store, func()) {
	s, cleanupStore := newTestStore(t)
	// #nosec G104 — test environment setup.
	os.Setenv("KROXY_JWT_SECRET", "test-secret-test-secret-test-secret-test")
	a := New(s, 0)
	a.audit = audit.GetLogger()
	cleanup := func() {
		cleanupStore()
		os.Unsetenv("KROXY_JWT_SECRET")
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
