package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/kroxy/kroxy/internal/api/dto"
	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/security"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/validation"
	"github.com/kroxy/kroxy/internal/version"
)

// Backup represents a full system backup.
type Backup struct {
	Version       string               `json:"version"`
	CreatedAt     time.Time            `json:"created_at"`
	Routes        []store.Route        `json:"routes"`
	OIDCProviders []store.OIDCProvider `json:"oidc_providers,omitempty"`
	WAFRules      []store.WAFRule      `json:"waf_rules,omitempty"`
	Certificates  []store.Certificate  `json:"certificates,omitempty"`
	Blacklists    []store.Blacklist    `json:"blacklists,omitempty"`
	Whitelists    []store.Whitelist    `json:"whitelists,omitempty"`
	RateLimits    []store.RateLimit    `json:"rate_limits,omitempty"`
	Settings      map[string]string    `json:"settings,omitempty"`
}

const backupVersion = version.Version

// safeOIDCProvider is the redacted form used in backup exports.
type safeOIDCProvider struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	DiscoveryURL string `json:"discovery_url"`
	RedirectURL  string `json:"redirect_url"`
}

func (a *API) exportBackup(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	routes, err := a.store.GetRoutes()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to get routes")
		return
	}

	providers, _ := a.store.GetOIDCProviders()
	rules, _ := a.store.GetWAFRules()
	certs, _ := a.store.GetCertificates()
	blacklists, _ := a.store.GetBlacklists()
	whitelists, _ := a.store.GetWhitelists()
	rateLimits, _ := a.store.GetRateLimits()

	settings := make(map[string]string)
	for _, key := range []string{"waf_paranoia_level", "global_waf_mode"} {
		if val, err := a.store.GetSetting(key); err == nil {
			settings[key] = val
		}
	}

	// Build safe DTO slices for export (omit sensitive fields)
	routeResponses := make([]dto.RouteResponse, len(routes))
	for i, r := range routes {
		routeResponses[i] = dto.RouteFromStore(r)
	}

	safeProviders := make([]safeOIDCProvider, len(providers))
	for i, p := range providers {
		safeProviders[i] = safeOIDCProvider{
			ID:           p.ID,
			Name:         p.Name,
			ClientID:     p.ClientID,
			DiscoveryURL: p.DiscoveryURL,
			RedirectURL:  p.RedirectURL,
		}
	}

	wafResponses := make([]dto.WAFRuleResponse, len(rules))
	for i, rl := range rules {
		wafResponses[i] = dto.WAFFromStore(rl)
	}

	certResponses := make([]dto.CertificateResponse, len(certs))
	for i, c := range certs {
		certResponses[i] = dto.CertificateFromStore(c)
	}

	blResponses := make([]dto.BlacklistResponse, len(blacklists))
	for i, b := range blacklists {
		blResponses[i] = dto.BlacklistFromStore(b)
	}

	wlResponses := make([]dto.WhitelistResponse, len(whitelists))
	for i, wl := range whitelists {
		wlResponses[i] = dto.WhitelistFromStore(wl)
	}

	rlResponses := make([]dto.RateLimitResponse, len(rateLimits))
	for i, rl := range rateLimits {
		rlResponses[i] = dto.RateLimitFromStore(rl)
	}

	// Use an anonymous struct for JSON serialization so the export
	// format can differ from the import-compatible Backup struct.
	response := struct {
		Version       string                    `json:"version"`
		CreatedAt     time.Time                 `json:"created_at"`
		Routes        []dto.RouteResponse       `json:"routes"`
		OIDCProviders []safeOIDCProvider        `json:"oidc_providers,omitempty"`
		WAFRules      []dto.WAFRuleResponse     `json:"waf_rules,omitempty"`
		Certificates  []dto.CertificateResponse `json:"certificates,omitempty"`
		Blacklists    []dto.BlacklistResponse   `json:"blacklists,omitempty"`
		Whitelists    []dto.WhitelistResponse   `json:"whitelists,omitempty"`
		RateLimits    []dto.RateLimitResponse   `json:"rate_limits,omitempty"`
		Settings      map[string]string         `json:"settings,omitempty"`
	}{
		Version:       backupVersion,
		CreatedAt:     time.Now(),
		Routes:        routeResponses,
		OIDCProviders: safeProviders,
		WAFRules:      wafResponses,
		Certificates:  certResponses,
		Blacklists:    blResponses,
		Whitelists:    wlResponses,
		RateLimits:    rlResponses,
		Settings:      settings,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=kroxy-backup-"+time.Now().Format("20060102-150405")+".json")
	respondJSON(w, http.StatusOK, response)

	a.audit.Log(audit.Event{
		Type:      "backup_exported",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
	})
}

func (a *API) importBackup(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	var backup Backup
	if err := json.NewDecoder(r.Body).Decode(&backup); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid backup file")
		return
	}

	if backup.Version == "" {
		respondError(w, http.StatusBadRequest, "Invalid backup: missing version")
		return
	}

	// Import routes
	for _, route := range backup.Routes {
		if route.IsAdminRoute {
			continue // Skip admin self-route
		}
		// Check if route already exists
		existing, _ := a.store.GetRoutes()
		found := false
		for _, e := range existing {
			if e.Domain == route.Domain {
				found = true
				break
			}
		}
		if !found {
			route.ID = 0 // Reset ID for insert
			if err := validation.ValidateBackendURL(route.Backend); err != nil {
				log.Printf("Warning: skipping import of route %s due to unsafe backend URL: %v", route.Domain, err)
				continue
			}
			if err := a.store.CreateRoute(&route); err != nil {
				log.Printf("Warning: failed to import route %s: %v", route.Domain, err)
			}
		}
	}

	// Reload proxy
	if a.proxyReloadFunc != nil {
		if err := a.proxyReloadFunc(); err != nil {
			log.Printf("Warning: failed to reload proxy after import: %v", err)
		}
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "imported"})

	a.audit.Log(audit.Event{
		Type:      "backup_imported",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
	})
}
