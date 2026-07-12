package store

import "time"

type Route struct {
	ID               int       `json:"id"`
	Domain           string    `json:"domain"`
	Backend          string    `json:"backend"`
	Enabled          bool      `json:"enabled"`
	WAFEnabled       bool      `json:"waf_enabled"`
	WAFMode          string    `json:"waf_mode"`
	WAFParanoiaLevel int       `json:"waf_paranoia_level"`
	OIDCEnabled      bool      `json:"oidc_enabled"`
	OIDCProviderID   int       `json:"oidc_provider_id"`
	RateLimit        int       `json:"rate_limit"`
	EnableGzip       bool      `json:"enable_gzip"`
	EnableBrotli     bool      `json:"enable_brotli"`
	EnableCache      bool      `json:"enable_cache"`
	CustomHeaders    string    `json:"custom_headers"`
	BlockCountries   string    `json:"block_countries"`
	AllowCountries   string    `json:"allow_countries"`
	RequireHTTPS     bool      `json:"require_https"`
	IsAdminRoute     bool      `json:"-"` // Internally-created admin self-route
	BotProtection    string    `json:"bot_protection"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type OIDCProvider struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"-"` // Never expose in API
	DiscoveryURL string `json:"discovery_url"`
	RedirectURL  string `json:"redirect_url"`
}

type Certificate struct {
	ID        int       `json:"id"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`   // "letsencrypt" or "custom"
	Issuer    string    `json:"issuer"` // "Let's Encrypt" or "Custom"
	CertPath  string    `json:"cert_path"`
	KeyPath   string    `json:"key_path"`
	AutoRenew bool      `json:"auto_renew"`
	Status    string    `json:"status"` // "pending", "active", "failed"
	ExpiresAt time.Time `json:"expires_at"`
}

type WAFRule struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Rule       string `json:"rule"`
	Enabled    bool   `json:"enabled"`
	Mode       string `json:"mode"`                 // "block" or "log_only"
	Exclusions string `json:"exclusions,omitempty"` // comma-separated CRS rule IDs to exclude
	RouteID    *int   `json:"route_id,omitempty"`   // nil = global rule, non-nil = route-specific
}

type SecurityEvent struct {
	ID        int       `json:"id"`
	EventType string    `json:"event_type"`
	ClientIP  string    `json:"client_ip"`
	Host      string    `json:"host"`
	URI       string    `json:"uri"`
	Method    string    `json:"method"`
	UserAgent string    `json:"user_agent"`
	RuleName  string    `json:"rule_name"`
	RuleID    int       `json:"rule_id,omitempty"`
	RouteID   int       `json:"route_id,omitempty"`
	Action    string    `json:"action"` // "blocked" or "detected"
	CreatedAt time.Time `json:"created_at"`
}

type Session struct {
	ID           string    `json:"id"`
	UserEmail    string    `json:"user_email"`
	UserName     string    `json:"user_name"`
	UserID       string    `json:"user_id"`
	ProviderName string    `json:"provider_name"`
	ClientIP     string    `json:"client_ip"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Blacklist struct {
	ID        int       `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type Whitelist struct {
	ID        int       `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type RateLimit struct {
	ID                int    `json:"id"`
	Domain            string `json:"domain"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	Burst             int    `json:"burst"`
	Enabled           bool   `json:"enabled"`
}

type User struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Password    string `json:"-"`
	Enabled     bool   `json:"enabled"`
	TOTPSecret  string `json:"-"` // Encrypted TOTP secret
	TOTPEnabled bool   `json:"totp_enabled"`
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID            int        `json:"id"`
	KeyID         string     `json:"key_id"`
	KeySecretHash string     `json:"-"` // Never expose in API
	KeySecretHMAC string     `json:"-"` // Fast pre-check before bcrypt (never expose)
	UserID        int        `json:"user_id"`
	Name          string     `json:"name"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at"`
	LastUsed      *time.Time `json:"last_used"`
}

// Webhook represents a configured webhook endpoint for alerts.
type Webhook struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Events    string    `json:"events"`
	Secret    string    `json:"secret,omitempty"` // Encrypted at rest; decrypted in memory when needed
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}
