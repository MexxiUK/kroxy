package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/kroxy/kroxy/internal/alerts"
	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/api/dto"
	"github.com/kroxy/kroxy/internal/security"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/validation"
)

// toWebhookResponse converts a store.Webhook to the API-safe DTO.
func toWebhookResponse(wh store.Webhook) dto.WebhookResponse {
	return dto.WebhookResponse{
		ID:        wh.ID,
		Name:      wh.Name,
		URL:       wh.URL,
		Events:    wh.Events,
		Enabled:   wh.Enabled,
		CreatedAt: wh.CreatedAt,
	}
}

// toWebhookResponses converts a slice of store.Webhooks to API-safe DTOs.
func toWebhookResponses(webhooks []store.Webhook) []dto.WebhookResponse {
	result := make([]dto.WebhookResponse, len(webhooks))
	for i, wh := range webhooks {
		result[i] = toWebhookResponse(wh)
	}
	return result
}

func (a *API) listWebhooks(w http.ResponseWriter, r *http.Request) {
	webhooks, err := a.store.GetWebhooks()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get webhooks")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"webhooks": toWebhookResponses(webhooks)})
}

func (a *API) createWebhook(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var wh store.Webhook
	if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if wh.Name == "" || wh.URL == "" {
		respondError(w, http.StatusBadRequest, "Name and URL are required")
		return
	}
	if err := validation.ValidateBackendURL(wh.URL); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid webhook URL: "+err.Error())
		return
	}

	if err := a.store.CreateWebhook(&wh); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create webhook")
		return
	}

	// Update alert manager with new webhooks
	if am := alerts.GetGlobalManager(); am != nil {
		webhooks, _ := a.store.GetWebhooks()
		am.UpdateWebhooks(webhooksToAlertWebhooks(webhooks))
	}

	a.audit.Log(audit.Event{
		Type:      "webhook_created",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"name": wh.Name, "url": wh.URL},
	})

	// Return the secret only once during creation, similar to API keys.
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"webhook": toWebhookResponse(wh),
		"secret":  wh.Secret,
	})
}

func (a *API) updateWebhook(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid webhook ID")
		return
	}

	var wh store.Webhook
	if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	wh.ID = id

	if wh.Name == "" || wh.URL == "" {
		respondError(w, http.StatusBadRequest, "Name and URL are required")
		return
	}
	if err := validation.ValidateBackendURL(wh.URL); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid webhook URL: "+err.Error())
		return
	}

	if err := a.store.UpdateWebhook(&wh); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update webhook")
		return
	}

	// Update alert manager
	if am := alerts.GetGlobalManager(); am != nil {
		webhooks, _ := a.store.GetWebhooks()
		am.UpdateWebhooks(webhooksToAlertWebhooks(webhooks))
	}

	a.audit.Log(audit.Event{
		Type:      "webhook_updated",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"id": id, "name": wh.Name},
	})

	// Never return the secret on update.
	respondJSON(w, http.StatusOK, toWebhookResponse(wh))
}

func (a *API) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid webhook ID")
		return
	}

	if err := a.store.DeleteWebhook(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete webhook")
		return
	}

	// Update alert manager
	if am := alerts.GetGlobalManager(); am != nil {
		webhooks, _ := a.store.GetWebhooks()
		am.UpdateWebhooks(webhooksToAlertWebhooks(webhooks))
	}

	a.audit.Log(audit.Event{
		Type:      "webhook_deleted",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
		Details:   map[string]interface{}{"id": id},
	})

	w.WriteHeader(http.StatusNoContent)
}

func webhooksToAlertWebhooks(webhooks []store.Webhook) []alerts.Webhook {
	result := make([]alerts.Webhook, len(webhooks))
	for i, w := range webhooks {
		result[i] = alerts.Webhook{
			ID:        w.ID,
			Name:      w.Name,
			URL:       w.URL,
			Events:    w.Events,
			Enabled:   w.Enabled,
			Secret:    w.Secret,
			CreatedAt: w.CreatedAt,
		}
	}
	return result
}
