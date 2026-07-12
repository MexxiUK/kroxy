package alerts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kroxy/kroxy/internal/validation"
)

// Manager handles webhook alerts for Kroxy events.
type Manager struct {
	mu          sync.RWMutex
	webhooks    []Webhook
	cooldowns   map[string]time.Time
	cooldownDur time.Duration
	client      *http.Client
	semaphore   chan struct{} // Limits concurrent webhook sends
}

// Webhook represents a configured webhook endpoint.
type Webhook struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Events    string    `json:"events"` // comma-separated list of event types
	Enabled   bool      `json:"enabled"`
	Secret    string    `json:"secret,omitempty"` // for HMAC signature
	CreatedAt time.Time `json:"created_at"`
}

// Event represents an alert event.
type Event struct {
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"` // info, warning, critical
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	RouteID   int                    `json:"route_id,omitempty"`
	Domain    string                 `json:"domain,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

const defaultCooldown = 5 * time.Minute

const maxConcurrentWebhookSends = 10

// NewManager creates an alert manager.
func NewManager() *Manager {
	return &Manager{
		cooldowns:   make(map[string]time.Time),
		cooldownDur: defaultCooldown,
		client:      &http.Client{Timeout: 10 * time.Second},
		semaphore:   make(chan struct{}, maxConcurrentWebhookSends),
	}
}

// Send sends an alert event to all matching webhooks.
func (m *Manager) Send(event Event) {
	m.mu.RLock()
	webhooks := make([]Webhook, len(m.webhooks))
	copy(webhooks, m.webhooks)
	m.mu.RUnlock()

	for _, wh := range webhooks {
		if !wh.Enabled {
			continue
		}
		if !m.eventMatches(wh.Events, event.Type) {
			continue
		}

		// Check cooldown
		key := fmt.Sprintf("%s:%s", wh.URL, event.Type)
		if m.isOnCooldown(key) {
			continue
		}

		select {
		case m.semaphore <- struct{}{}:
			go func(wh Webhook, event Event) {
				defer func() { <-m.semaphore }()
				m.sendWebhook(wh, event)
			}(wh, event)
		default:
			log.Printf("Alert: dropping webhook to %s, concurrency limit reached", wh.URL)
		}
		m.setCooldown(key)
	}
}

func (m *Manager) sendWebhook(wh Webhook, event Event) {
	// SSRF protection: reject webhooks pointing to private/reserved/loopback addresses.
	if err := validation.ValidateBackendURL(wh.URL); err != nil {
		log.Printf("Alert: dropping webhook to %s: unsafe URL: %v", wh.URL, err)
		return
	}

	payload, err := json.Marshal(event)
	if err != nil {
		log.Printf("Alert: failed to marshal event: %v", err)
		return
	}

	req, err := http.NewRequest("POST", wh.URL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("Alert: failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Kroxy-Alert/1.0")
	if wh.Secret != "" {
		// Timestamp + HMAC provides replay resistance: receivers can reject old signatures.
		timestamp := time.Now().UTC().Unix()
		req.Header.Set("X-Kroxy-Timestamp", strconv.FormatInt(timestamp, 10))
		req.Header.Set("X-Kroxy-Signature", m.sign(payload, wh.Secret, timestamp))
	}

	resp, err := m.client.Do(req)
	if err != nil {
		log.Printf("Alert: failed to send webhook to %s: %v", wh.URL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Alert: webhook %s returned %d", wh.URL, resp.StatusCode)
	}
}

func (m *Manager) eventMatches(patterns, eventType string) bool {
	if patterns == "" || patterns == "*" || patterns == "all" {
		return true
	}
	for _, p := range strings.Split(patterns, ",") {
		if strings.TrimSpace(p) == eventType {
			return true
		}
	}
	return false
}

func (m *Manager) isOnCooldown(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t, ok := m.cooldowns[key]; ok {
		return time.Now().Before(t.Add(m.cooldownDur))
	}
	return false
}

func (m *Manager) setCooldown(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cooldowns[key] = time.Now()
}

func (m *Manager) sign(payload []byte, secret string, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d|", timestamp)))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// UpdateWebhooks replaces the webhook list.
func (m *Manager) UpdateWebhooks(webhooks []Webhook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webhooks = webhooks
}

// Common alert helpers
func (m *Manager) BackendDown(routeID int, domain, backend string, err error) {
	m.Send(Event{
		Type:      "backend_down",
		Severity:  "critical",
		Title:     fmt.Sprintf("Backend %s is unreachable", domain),
		Message:   fmt.Sprintf("Health check failed for %s (%s): %v", domain, backend, err),
		RouteID:   routeID,
		Domain:    domain,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"backend": backend,
			"error":   err.Error(),
		},
	})
}

func (m *Manager) WAFSpike(domain string, blocks int) {
	m.Send(Event{
		Type:      "waf_spike",
		Severity:  "warning",
		Title:     fmt.Sprintf("WAF blocking spike on %s", domain),
		Message:   fmt.Sprintf("WAF blocked %d requests in the last minute", blocks),
		Domain:    domain,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"blocks": blocks,
		},
	})
}

func (m *Manager) CertExpiring(domain string, days int) {
	m.Send(Event{
		Type:      "cert_expiring",
		Severity:  "warning",
		Title:     fmt.Sprintf("Certificate for %s expires in %d days", domain, days),
		Message:   "SSL certificate will expire soon. Renewal is recommended.",
		Domain:    domain,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"days_remaining": days,
		},
	})
}

var globalManager *Manager

// SetGlobalManager sets the global alert manager.
func SetGlobalManager(m *Manager) {
	globalManager = m
}

// GetGlobalManager returns the global alert manager.
func GetGlobalManager() *Manager {
	return globalManager
}

// Send is a convenience function.
func Send(event Event) {
	if globalManager != nil {
		globalManager.Send(event)
	}
}
