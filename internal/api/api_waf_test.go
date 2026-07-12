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

func TestUpdateWAFRule_RequiresNameAndRule(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	a := New(s, 0)

	// Seed a valid rule first.
	rule := &store.WAFRule{
		Name:    "valid-rule",
		Rule:    `SecRule REQUEST_URI "@rx ^/test$" "id:900001,phase:1,deny,status:403,msg:'test'"`,
		Enabled: true,
		Mode:    "block",
	}
	if err := s.CreateWAFRule(rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}

	// Create an admin session context to bypass auth middleware.
	adminSession := &auth.Session{
		UserID: 1,
		Email:  "admin@kroxy.local",
		Name:   "Admin",
		Role:   "admin",
	}
	ctx := context.WithValue(context.Background(), "session", adminSession)

	cases := []struct {
		name       string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name: "empty name rejected",
			body: map[string]interface{}{
				"name": "",
				"rule": `SecRule REQUEST_URI "@rx ^/test$" "id:900002,phase:1,deny,status:403,msg:'test'"`,
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "empty rule rejected",
			body: map[string]interface{}{
				"name": "renamed-rule",
				"rule": "",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "valid update accepted",
			body: map[string]interface{}{
				"name":       "renamed-rule",
				"rule":       `SecRule REQUEST_URI "@rx ^/test$" "id:900003,phase:1,deny,status:403,msg:'test'"`,
				"enabled":    true,
				"mode":       "block",
				"exclusions": "",
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPut, "/api/waf/rules/"+strconv.Itoa(rule.ID), bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")

			// Inject chi routing context with the URL parameter so chi.URLParam works.
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", strconv.Itoa(rule.ID))
			reqCtx := context.WithValue(ctx, chi.RouteCtxKey, rctx)
			req = req.WithContext(reqCtx)

			rec := httptest.NewRecorder()
			a.updateWAFRule(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}
