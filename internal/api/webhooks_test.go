package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/store"
)

func TestUpdateWebhook_PreservesSecretWhenOmitted(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	a := New(s, 0)

	// Create a webhook with a secret.
	wh := &store.Webhook{
		Name:    "notify-webhook",
		URL:     "https://1.1.1.1/notify",
		Events:  "alert",
		Secret:  "super-secret-value",
		Enabled: true,
	}
	if err := s.CreateWebhook(wh); err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	// Build an admin session context to bypass auth middleware.
	adminSession := &auth.Session{
		UserID: 1,
		Email:  "admin@kroxy.local",
		Name:   "Admin",
		Role:   "admin",
	}
	ctx := context.WithValue(context.Background(), "session", adminSession)

	// Update only the name, omitting the secret.
	body := map[string]interface{}{
		"name":    "renamed-webhook",
		"url":     "https://1.1.1.1/notify",
		"events":  "alert",
		"enabled": true,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/api/webhooks/"+strconv.Itoa(wh.ID), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	// Inject chi routing context so chi.URLParam works.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", strconv.Itoa(wh.ID))
	reqCtx := context.WithValue(ctx, chi.RouteCtxKey, rctx)
	req = req.WithContext(reqCtx)

	rec := httptest.NewRecorder()
	a.updateWebhook(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Verify the secret was preserved.
	updated, err := s.GetWebhook(wh.ID)
	if err != nil {
		t.Fatalf("get updated webhook: %v", err)
	}
	if updated == nil {
		t.Fatal("updated webhook not found")
	}
	if updated.Secret != wh.Secret {
		t.Fatalf("expected secret %q to be preserved, got %q", wh.Secret, updated.Secret)
	}
	if updated.Name != "renamed-webhook" {
		t.Fatalf("expected name to be updated to %q, got %q", "renamed-webhook", updated.Name)
	}
}
