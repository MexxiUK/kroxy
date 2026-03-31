package store

import "time"

type Route struct {
	ID              int       `json:"id"`
	Domain          string    `json:"domain"`
	Backend         string    `json:"backend"`
	Enabled         bool      `json:"enabled"`
	WAFEnabled      bool      `json:"waf_enabled"`
	OIDCEnabled     bool      `json:"oidc_enabled"`
	OIDCProviderID  int       `json:"oidc_provider_id"`
	RateLimit       int       `json:"rate_limit"`
	EnableGzip      bool      `json:"enable_gzip"`
	EnableBrotli    bool      `json:"enable_brotli"`
	EnableCache     bool      `json:"enable_cache"`
	CustomHeaders   string    `json:"custom_headers"`
	BlockCountries  string    `json:"block_countries"`
	AllowCountries  string    `json:"allow_countries"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type OIDCProvider struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"-"` // Never expose in API
	DiscoveryURL string `json:"discovery_url"`
	RedirectURL  string `json:"redirect_url"`
}

// OIDCProviderResponse is the safe API response (without secrets)
type OIDCProviderResponse struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	DiscoveryURL string `json:"discovery_url"`
	RedirectURL  string `json:"redirect_url"`
}

type Certificate struct {
	ID        int       `json:"id"`
	Domain    string    `json:"domain"`
	CertPath  string    `json:"cert_path"`
	KeyPath   string    `json:"key_path"`
	AutoRenew bool      `json:"auto_renew"`
	ExpiresAt time.Time `json:"expires_at"`
}

type WAFRule struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Rule    string `json:"rule"`
	Enabled bool   `json:"enabled"`
}

type Session struct {
	ID           string    `json:"id"`
	UserEmail    string    `json:"user_email"`
	UserName     string    `json:"user_name"`
	UserID       string    `json:"user_id"`
	ProviderName string    `json:"provider_name"`
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
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Password string `json:"-"`
	Enabled  bool   `json:"enabled"`
}

type Header struct {
	ID      int    `json:"id"`
	Domain  string `json:"domain"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Enabled bool   `json:"enabled"`
}

type Redirect struct {
	ID           int    `json:"id"`
	FromPattern  string `json:"from_pattern"`
	ToURL        string `json:"to_url"`
	StatusCode   int    `json:"status_code"`
	Enabled      bool   `json:"enabled"`
}

type AntibotConfig struct {
	ID             int    `json:"id"`
	Domain         string `json:"domain"`
	ChallengeType  string `json:"challenge_type"`
	Enabled        bool   `json:"enabled"`
	WhitelistBots  bool   `json:"whitelist_bots"`
}

type CustomPage struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Enabled bool   `json:"enabled"`
}

// Backend represents a load-balanced backend server
type Backend struct {
	ID          int       `json:"id"`
	RouteID     int       `json:"route_id"`
	URL         string    `json:"url"`
	Weight      int       `json:"weight"`
	Healthy     bool      `json:"healthy"`
	LastCheck   time.Time `json:"last_check"`
	LastError   string    `json:"last_error"`
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID            int        `json:"id"`
	KeyID         string    `json:"key_id"`
	KeySecretHash string    `json:"-"` // Never expose in API
	UserID        int       `json:"user_id"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at"`
	LastUsed      *time.Time `json:"last_used"`
}