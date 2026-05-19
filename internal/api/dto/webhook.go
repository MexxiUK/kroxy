package dto

import "time"

// WebhookResponse is the API-safe representation of a webhook.
// It intentionally omits the Secret field to prevent leakage.
type WebhookResponse struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Events    string    `json:"events"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}
