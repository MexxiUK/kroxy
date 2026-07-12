package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/crypto"
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
	Signature     string               `json:"signature,omitempty"`
}

const backupVersion = version.Version

// backupPayload is the signed subset of a backup. It mirrors the import-compatible
// Backup struct so the signature covers every field that importBackup reads,
// while omitting the Signature field itself.
type backupPayload struct {
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

// backupHMAC returns the server-side HMAC of backup data for integrity verification.
// The key is derived from the encryption key via HKDF so the same master secret
// is not reused for both AES-GCM and backup authentication.
func backupHMAC(data []byte) string {
	key, err := crypto.GetBackupHMACKey()
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	// #nosec G104 — hmac.Write never returns an error in practice.
	mac.Write(data)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// verifyBackupHMAC checks a backup signature against the signed payload.
// To preserve compatibility with backups created before the dedicated key was
// introduced, it also accepts a signature produced with the raw encryption key.
func verifyBackupHMAC(data []byte, sig string) bool {
	derivedKey, err := crypto.GetBackupHMACKey()
	if err != nil {
		return false
	}

	expectedDerived := backupHMACWithKey(data, derivedKey)
	matchDerived := subtle.ConstantTimeCompare([]byte(expectedDerived), []byte(sig))

	// Legacy fallback: old backups were signed with the raw encryption key.
	legacyKey, legacyErr := crypto.GetEncryptionKey()
	matchLegacy := 0
	if legacyErr == nil {
		expectedLegacy := backupHMACWithKey(data, legacyKey)
		matchLegacy = subtle.ConstantTimeCompare([]byte(expectedLegacy), []byte(sig))
	}

	return matchDerived|matchLegacy != 0
}

func backupHMACWithKey(data, key []byte) string {
	mac := hmac.New(sha256.New, key)
	// #nosec G104 — hmac.Write never returns an error in practice.
	mac.Write(data)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
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

	// Build the import-compatible backup struct directly so the signed bytes
	// cover every field that importBackup will read. Sensitive fields such as
	// OIDC client secrets are excluded from JSON by struct tags on store types.
	backup := Backup{
		Version:       backupVersion,
		CreatedAt:     time.Now(),
		Routes:        routes,
		OIDCProviders: providers,
		WAFRules:      rules,
		Certificates:  certs,
		Blacklists:    blacklists,
		Whitelists:    whitelists,
		RateLimits:    rateLimits,
		Settings:      settings,
	}

	// Serialize without the signature so the HMAC covers every other field.
	unsigned, err := json.Marshal(backup)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to serialize backup")
		return
	}

	// Sign the backup so imports can verify integrity.
	backup.Signature = backupHMAC(unsigned)

	signed, err := json.Marshal(backup)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to serialize signed backup")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=kroxy-backup-"+time.Now().Format("20060102-150405")+".json")
	w.WriteHeader(http.StatusOK)
	// #nosec G104 — best-effort backup download write.
	w.Write(signed)

	a.audit.Log(audit.Event{
		Type:      "backup_exported",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
	})
}

func (a *API) importBackup(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	body, err := io.ReadAll(io.LimitReader(r.Body, a.maxBodyBytes+1))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Failed to read backup file")
		return
	}
	if int64(len(body)) > a.maxBodyBytes {
		respondError(w, http.StatusRequestEntityTooLarge, "Backup file exceeds maximum size")
		return
	}

	var backup Backup
	if err := json.Unmarshal(body, &backup); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid backup file")
		return
	}

	if backup.Version == "" {
		respondError(w, http.StatusBadRequest, "Invalid backup: missing version")
		return
	}

	// In production mode, backups must be signed to prevent tampered imports.
	if os.Getenv("KROXY_PRODUCTION") == "true" && backup.Signature == "" {
		respondError(w, http.StatusForbidden, "Backup signature required in production mode")
		return
	}

	// Verify HMAC signature if one is present.
	if backup.Signature != "" {
		var payload backupPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid backup structure")
			return
		}
		unsigned, err := json.Marshal(payload)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to verify backup signature")
			return
		}
		if !crypto.IsEncryptionAvailable() {
			respondError(w, http.StatusServiceUnavailable, "Backup signature required but no HMAC key available")
			return
		}
		if !verifyBackupHMAC(unsigned, backup.Signature) {
			respondError(w, http.StatusForbidden, "Invalid backup signature")
			return
		}
	}

	// Reject partial backups: if the backup contains any category other than
	// routes, importing only routes would silently drop security-critical
	// configuration. Fail closed until full restore is implemented.
	if len(backup.OIDCProviders) > 0 ||
		len(backup.WAFRules) > 0 ||
		len(backup.Certificates) > 0 ||
		len(backup.Blacklists) > 0 ||
		len(backup.Whitelists) > 0 ||
		len(backup.RateLimits) > 0 ||
		len(backup.Settings) > 0 {
		respondError(w, http.StatusBadRequest, "Backup contains unsupported categories; only route-only backups may be imported")
		return
	}

	// Import routes
	for _, route := range backup.Routes {
		if route.IsAdminRoute {
			continue // Skip admin self-route
		}
		// Validate domain and backend format before touching the database.
		if strings.TrimSpace(route.Domain) == "" || strings.TrimSpace(route.Backend) == "" {
			log.Printf("Warning: skipping import of route with empty domain or backend")
			continue
		}
		if err := validation.ValidateBackendURL(route.Backend); err != nil {
			log.Printf("Warning: skipping import of route %s due to unsafe backend URL: %v", route.Domain, err)
			continue
		}
		if err := validation.ValidateNoSelfReference(route.Backend, false); err != nil {
			log.Printf("Warning: skipping import of route %s due to self-reference: %v", route.Domain, err)
			continue
		}

		// Check if route already exists
		existing, err := a.store.GetRoutes()
		if err != nil {
			log.Printf("Warning: failed to check existing routes during import: %v", err)
			continue
		}
		found := false
		for _, e := range existing {
			if e.Domain == route.Domain {
				found = true
				break
			}
		}
		if !found {
			route.ID = 0 // Reset ID for insert
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
