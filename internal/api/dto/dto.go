package dto

import (
	"fmt"
	"net"
	"time"

	"github.com/kroxy/kroxy/internal/store"
)

// RouteResponse is the safe API representation of a route.
// Omits Backend (internal URL), OIDCProviderID, and IsAdminRoute.
type RouteResponse struct {
	ID               int       `json:"id"`
	Domain           string    `json:"domain"`
	Enabled          bool      `json:"enabled"`
	WAFEnabled       bool      `json:"waf_enabled"`
	WAFMode          string    `json:"waf_mode"`
	WAFParanoiaLevel int       `json:"waf_paranoia_level"`
	OIDCEnabled      bool      `json:"oidc_enabled"`
	RateLimit        int       `json:"rate_limit"`
	EnableGzip       bool      `json:"enable_gzip"`
	EnableBrotli     bool      `json:"enable_brotli"`
	EnableCache      bool      `json:"enable_cache"`
	CustomHeaders    string    `json:"custom_headers"`
	BlockCountries   string    `json:"block_countries"`
	AllowCountries   string    `json:"allow_countries"`
	RequireHTTPS     bool      `json:"require_https"`
	BotProtection    string    `json:"bot_protection"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// RouteFromStore maps a store.Route to a safe RouteResponse.
func RouteFromStore(r store.Route) RouteResponse {
	return RouteResponse{
		ID:               r.ID,
		Domain:           r.Domain,
		Enabled:          r.Enabled,
		WAFEnabled:       r.WAFEnabled,
		WAFMode:          r.WAFMode,
		WAFParanoiaLevel: r.WAFParanoiaLevel,
		OIDCEnabled:      r.OIDCEnabled,
		RateLimit:        r.RateLimit,
		EnableGzip:       r.EnableGzip,
		EnableBrotli:     r.EnableBrotli,
		EnableCache:      r.EnableCache,
		CustomHeaders:    r.CustomHeaders,
		BlockCountries:   r.BlockCountries,
		AllowCountries:   r.AllowCountries,
		RequireHTTPS:     r.RequireHTTPS,
		BotProtection:    r.BotProtection,
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,
	}
}

// CertificateResponse is the safe API representation of a certificate.
// Omits CertPath and KeyPath (filesystem paths to private key material).
type CertificateResponse struct {
	ID        int       `json:"id"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	Issuer    string    `json:"issuer"`
	AutoRenew bool      `json:"auto_renew"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CertificateFromStore maps a store.Certificate to a safe CertificateResponse.
func CertificateFromStore(c store.Certificate) CertificateResponse {
	return CertificateResponse{
		ID:        c.ID,
		Domain:    c.Domain,
		Type:      c.Type,
		Issuer:    c.Issuer,
		AutoRenew: c.AutoRenew,
		Status:    c.Status,
		ExpiresAt: c.ExpiresAt,
	}
}

// WAFRuleResponse is the safe API representation of a WAF rule.
// WAF rules contain no sensitive fields, but this isolates the API contract.
type WAFRuleResponse struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Rule       string `json:"rule"`
	Enabled    bool   `json:"enabled"`
	Mode       string `json:"mode"`
	Exclusions string `json:"exclusions,omitempty"`
	RouteID    *int   `json:"route_id,omitempty"`
}

// WAFFromStore maps a store.WAFRule to a safe WAFRuleResponse.
func WAFFromStore(r store.WAFRule) WAFRuleResponse {
	return WAFRuleResponse{
		ID:         r.ID,
		Name:       r.Name,
		Rule:       r.Rule,
		Enabled:    r.Enabled,
		Mode:       r.Mode,
		Exclusions: r.Exclusions,
		RouteID:    r.RouteID,
	}
}

// SecurityEventResponse is the safe API representation of a security event.
// Masks ClientIP and UserAgent to protect PII.
type SecurityEventResponse struct {
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
	Action    string    `json:"action"`
	CreatedAt time.Time `json:"created_at"`
}

// MaskIP hides the last octet of an IPv4 address or last group of IPv6.
func MaskIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0", v4[0], v4[1], v4[2])
	}
	return "***"
}

// SecurityEventFromStore maps a store.SecurityEvent to a safe SecurityEventResponse.
func SecurityEventFromStore(e store.SecurityEvent) SecurityEventResponse {
	return SecurityEventResponse{
		ID:        e.ID,
		EventType: e.EventType,
		ClientIP:  MaskIP(e.ClientIP),
		Host:      e.Host,
		URI:       e.URI,
		Method:    e.Method,
		UserAgent: "", // User-Agent is PII; never expose
		RuleName:  e.RuleName,
		RuleID:    e.RuleID,
		RouteID:   e.RouteID,
		Action:    e.Action,
		CreatedAt: e.CreatedAt,
	}
}

// UserResponse is the safe API representation of a user.
type UserResponse struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Enabled     bool   `json:"enabled"`
	TOTPEnabled bool   `json:"totp_enabled"`
}

// UserFromStore maps a store.User to a safe UserResponse.
func UserFromStore(u store.User) UserResponse {
	return UserResponse{
		ID:          u.ID,
		Email:       u.Email,
		Name:        u.Name,
		Role:        u.Role,
		Enabled:     u.Enabled,
		TOTPEnabled: u.TOTPEnabled,
	}
}

// BlacklistResponse is the safe API representation of a blacklist entry.
type BlacklistResponse struct {
	ID        int       `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// BlacklistFromStore maps a store.Blacklist to a safe BlacklistResponse.
func BlacklistFromStore(b store.Blacklist) BlacklistResponse {
	return BlacklistResponse{
		ID:        b.ID,
		Type:      b.Type,
		Value:     b.Value,
		Enabled:   b.Enabled,
		CreatedAt: b.CreatedAt,
	}
}

// WhitelistResponse is the safe API representation of a whitelist entry.
type WhitelistResponse struct {
	ID        int       `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

// WhitelistFromStore maps a store.Whitelist to a safe WhitelistResponse.
func WhitelistFromStore(w store.Whitelist) WhitelistResponse {
	return WhitelistResponse{
		ID:        w.ID,
		Type:      w.Type,
		Value:     w.Value,
		Enabled:   w.Enabled,
		CreatedAt: w.CreatedAt,
	}
}

// RateLimitResponse is the safe API representation of a rate limit rule.
type RateLimitResponse struct {
	ID                int    `json:"id"`
	Domain            string `json:"domain"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	Burst             int    `json:"burst"`
	Enabled           bool   `json:"enabled"`
}

// RateLimitFromStore maps a store.RateLimit to a safe RateLimitResponse.
func RateLimitFromStore(rl store.RateLimit) RateLimitResponse {
	return RateLimitResponse{
		ID:                rl.ID,
		Domain:            rl.Domain,
		RequestsPerMinute: rl.RequestsPerMinute,
		Burst:             rl.Burst,
		Enabled:           rl.Enabled,
	}
}
