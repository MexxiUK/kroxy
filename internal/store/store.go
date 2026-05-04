package store

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kroxy/kroxy/internal/crypto"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db     *sql.DB
	dbPath string
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Use versioned migrations
	migrator := NewMigrator(db)
	if err := migrator.Up(); err != nil {
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	// Set database file permissions to owner read/write only (0600)
	// This prevents other users from reading sensitive data
	if err := os.Chmod(path, 0600); err != nil {
		// Log but don't fail - database is still usable
		// This can happen if running as non-root or on certain filesystems
		log.Printf("Warning: failed to set database file permissions on %s: %v", path, err)
	}

	// Warn if encryption is not configured in production mode
	crypto.RequireEncryptionInProduction()

	return &Store{db: db, dbPath: path}, nil
}

func (s *Store) DatabasePath() string {
	return s.dbPath
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Ping checks database connectivity with a lightweight query
func (s *Store) Ping(ctx context.Context) error {
	return s.db.QueryRowContext(ctx, "SELECT 1").Scan(new(int))
}

// Route methods

func (s *Store) GetRoutes() ([]Route, error) {
	rows, err := s.db.Query(`SELECT id, domain, backend, enabled, waf_enabled, waf_mode, waf_paranoia_level, oidc_enabled, oidc_provider_id,
		rate_limit, enable_gzip, enable_brotli, enable_cache, custom_headers, block_countries, allow_countries, require_https,
		is_admin_route, bot_protection, created_at, updated_at FROM routes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var routes []Route
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var r Route
		if err := rows.Scan(&r.ID, &r.Domain, &r.Backend, &r.Enabled, &r.WAFEnabled, &r.WAFMode, &r.WAFParanoiaLevel, &r.OIDCEnabled, &r.OIDCProviderID,
			&r.RateLimit, &r.EnableGzip, &r.EnableBrotli, &r.EnableCache, &r.CustomHeaders, &r.BlockCountries, &r.AllowCountries, &r.RequireHTTPS,
			&r.IsAdminRoute, &r.BotProtection, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		routes = append(routes, r)
	}
	return routes, nil
}

func (s *Store) CreateRoute(r *Route) error {
	result, err := s.db.Exec(
		"INSERT INTO routes (domain, backend, enabled, waf_enabled, waf_mode, waf_paranoia_level, oidc_enabled, oidc_provider_id, rate_limit, enable_gzip, enable_brotli, enable_cache, custom_headers, block_countries, allow_countries, require_https, is_admin_route, bot_protection) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		r.Domain, r.Backend, r.Enabled, r.WAFEnabled, r.WAFMode, r.WAFParanoiaLevel, r.OIDCEnabled, r.OIDCProviderID, r.RateLimit, r.EnableGzip, r.EnableBrotli, r.EnableCache, r.CustomHeaders, r.BlockCountries, r.AllowCountries, r.RequireHTTPS, r.IsAdminRoute, r.BotProtection,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	r.ID = int(id)
	return nil
}

func (s *Store) DeleteRoute(id int) error {
	_, err := s.db.Exec("DELETE FROM routes WHERE id = ?", id)
	return err
}

func (s *Store) UpdateRoute(r *Route) error {
	_, err := s.db.Exec(
		"UPDATE routes SET domain = ?, backend = ?, enabled = ?, waf_enabled = ?, waf_mode = ?, waf_paranoia_level = ?, oidc_enabled = ?, oidc_provider_id = ?, rate_limit = ?, enable_gzip = ?, enable_brotli = ?, enable_cache = ?, custom_headers = ?, block_countries = ?, allow_countries = ?, require_https = ?, is_admin_route = ?, bot_protection = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		r.Domain, r.Backend, r.Enabled, r.WAFEnabled, r.WAFMode, r.WAFParanoiaLevel, r.OIDCEnabled, r.OIDCProviderID, r.RateLimit, r.EnableGzip, r.EnableBrotli, r.EnableCache, r.CustomHeaders, r.BlockCountries, r.AllowCountries, r.RequireHTTPS, r.IsAdminRoute, r.BotProtection, r.ID,
	)
	return err
}

// GetAdminRoute returns the admin self-route (is_admin_route = 1)
func (s *Store) GetAdminRoute() (*Route, error) {
	row := s.db.QueryRow(`SELECT id, domain, backend, enabled, waf_enabled, waf_mode, waf_paranoia_level, oidc_enabled, oidc_provider_id,
		rate_limit, enable_gzip, enable_brotli, enable_cache, custom_headers, block_countries, allow_countries, require_https,
		is_admin_route, bot_protection, created_at, updated_at FROM routes WHERE is_admin_route = 1`)
	var r Route
	err := row.Scan(&r.ID, &r.Domain, &r.Backend, &r.Enabled, &r.WAFEnabled, &r.WAFMode, &r.WAFParanoiaLevel, &r.OIDCEnabled, &r.OIDCProviderID,
		&r.RateLimit, &r.EnableGzip, &r.EnableBrotli, &r.EnableCache, &r.CustomHeaders, &r.BlockCountries, &r.AllowCountries, &r.RequireHTTPS,
		&r.IsAdminRoute, &r.BotProtection, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// OIDC Provider methods

func (s *Store) GetOIDCProviders() ([]OIDCProvider, error) {
	rows, err := s.db.Query("SELECT id, name, client_id, client_secret, discovery_url, redirect_url FROM oidc_providers")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []OIDCProvider
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var p OIDCProvider
		if err := rows.Scan(&p.ID, &p.Name, &p.ClientID, &p.ClientSecret, &p.DiscoveryURL, &p.RedirectURL); err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, nil
}

func (s *Store) GetOIDCProvider(id int) (*OIDCProvider, error) {
	row := s.db.QueryRow("SELECT id, name, client_id, client_secret, discovery_url, redirect_url FROM oidc_providers WHERE id = ?", id)
	var p OIDCProvider
	var encryptedSecret string
	err := row.Scan(&p.ID, &p.Name, &p.ClientID, &encryptedSecret, &p.DiscoveryURL, &p.RedirectURL)
	if err != nil {
		return nil, err
	}
	// Decrypt client secret (handles plaintext for backward compatibility)
	decryptedSecret, err := crypto.Decrypt(encryptedSecret)
	if err != nil {
		// If decryption fails, try using the value as-is (backward compatibility)
		p.ClientSecret = encryptedSecret
	} else {
		p.ClientSecret = decryptedSecret
	}
	return &p, nil
}

func (s *Store) CreateOIDCProvider(p *OIDCProvider) error {
	// Encrypt client secret before storing
	encryptedSecret, err := crypto.Encrypt(p.ClientSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt client secret: %w", err)
	}

	result, err := s.db.Exec(
		"INSERT INTO oidc_providers (name, client_id, client_secret, discovery_url, redirect_url) VALUES (?, ?, ?, ?, ?)",
		p.Name, p.ClientID, encryptedSecret, p.DiscoveryURL, p.RedirectURL,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	p.ID = int(id)
	return nil
}

func (s *Store) DeleteOIDCProvider(id int) error {
	_, err := s.db.Exec("DELETE FROM oidc_providers WHERE id = ?", id)
	return err
}

// Session methods

func (s *Store) GetSession(id string) (*Session, error) {
	row := s.db.QueryRow("SELECT id, user_email, user_name, user_id, provider_name, created_at, expires_at FROM sessions WHERE id = ?", id)
	var sess Session
	err := row.Scan(&sess.ID, &sess.UserEmail, &sess.UserName, &sess.UserID, &sess.ProviderName, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Store) CreateSession(sess *Session) error {
	_, err := s.db.Exec(
		"INSERT INTO sessions (id, user_email, user_name, user_id, provider_name, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		sess.ID, sess.UserEmail, sess.UserName, sess.UserID, sess.ProviderName, sess.CreatedAt, sess.ExpiresAt,
	)
	return err
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	return err
}

func (s *Store) UpdateSessionExpiry(id string, expiresAt time.Time) error {
	_, err := s.db.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", expiresAt, id)
	return err
}

func (s *Store) CleanupSessions() error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE datetime(expires_at) < datetime('now')")
	return err
}

// Blacklist methods

func (s *Store) GetBlacklists() ([]Blacklist, error) {
	rows, err := s.db.Query("SELECT id, type, value, enabled, created_at FROM blacklists")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Blacklist
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var b Blacklist
		if err := rows.Scan(&b.ID, &b.Type, &b.Value, &b.Enabled, &b.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, b)
	}
	return list, nil
}

func (s *Store) CreateBlacklist(b *Blacklist) error {
	result, err := s.db.Exec("INSERT INTO blacklists (type, value, enabled) VALUES (?, ?, ?)", b.Type, b.Value, b.Enabled)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	b.ID = int(id)
	return nil
}

func (s *Store) DeleteBlacklist(id int) error {
	_, err := s.db.Exec("DELETE FROM blacklists WHERE id = ?", id)
	return err
}

// Whitelist methods

func (s *Store) GetWhitelists() ([]Whitelist, error) {
	rows, err := s.db.Query("SELECT id, type, value, enabled, created_at FROM whitelists")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Whitelist
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var w Whitelist
		if err := rows.Scan(&w.ID, &w.Type, &w.Value, &w.Enabled, &w.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, w)
	}
	return list, nil
}

func (s *Store) CreateWhitelist(w *Whitelist) error {
	result, err := s.db.Exec("INSERT INTO whitelists (type, value, enabled) VALUES (?, ?, ?)", w.Type, w.Value, w.Enabled)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	w.ID = int(id)
	return nil
}

func (s *Store) DeleteWhitelist(id int) error {
	_, err := s.db.Exec("DELETE FROM whitelists WHERE id = ?", id)
	return err
}

// RateLimit methods

func (s *Store) GetRateLimits() ([]RateLimit, error) {
	rows, err := s.db.Query("SELECT id, domain, requests_per_minute, burst, enabled FROM rate_limits")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var limits []RateLimit
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var r RateLimit
		if err := rows.Scan(&r.ID, &r.Domain, &r.RequestsPerMinute, &r.Burst, &r.Enabled); err != nil {
			return nil, err
		}
		limits = append(limits, r)
	}
	return limits, nil
}

func (s *Store) CreateRateLimit(r *RateLimit) error {
	result, err := s.db.Exec("INSERT INTO rate_limits (domain, requests_per_minute, burst, enabled) VALUES (?, ?, ?, ?)", r.Domain, r.RequestsPerMinute, r.Burst, r.Enabled)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	r.ID = int(id)
	return nil
}

func (s *Store) UpdateRateLimit(r *RateLimit) error {
	_, err := s.db.Exec("UPDATE rate_limits SET domain = ?, requests_per_minute = ?, burst = ?, enabled = ? WHERE id = ?", r.Domain, r.RequestsPerMinute, r.Burst, r.Enabled, r.ID)
	return err
}

func (s *Store) DeleteRateLimit(id int) error {
	_, err := s.db.Exec("DELETE FROM rate_limits WHERE id = ?", id)
	return err
}

// User methods

func (s *Store) GetUsers() ([]User, error) {
	rows, err := s.db.Query("SELECT id, email, name, role, enabled, totp_enabled FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.Enabled, &u.TOTPEnabled); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	row := s.db.QueryRow("SELECT id, email, name, role, password, enabled, totp_secret, totp_enabled FROM users WHERE LOWER(email) = LOWER(?)", email)
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.Password, &u.Enabled, &u.TOTPSecret, &u.TOTPEnabled)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetUserByID(id int) (*User, error) {
	row := s.db.QueryRow("SELECT id, email, name, role, password, enabled, totp_secret, totp_enabled FROM users WHERE id = ?", id)
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.Password, &u.Enabled, &u.TOTPSecret, &u.TOTPEnabled)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) CreateUser(u *User) error {
	result, err := s.db.Exec("INSERT INTO users (email, name, role, password, enabled) VALUES (?, ?, ?, ?, ?)", u.Email, u.Name, u.Role, u.Password, u.Enabled)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	u.ID = int(id)
	return nil
}

// UpdateTOTPSecret stores the encrypted TOTP secret for a user
func (s *Store) UpdateTOTPSecret(userID int, encryptedSecret string) error {
	_, err := s.db.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", encryptedSecret, userID)
	return err
}

// EnableTOTP enables TOTP verification for a user
func (s *Store) EnableTOTP(userID int) error {
	_, err := s.db.Exec("UPDATE users SET totp_enabled = 1 WHERE id = ?", userID)
	return err
}

// DisableTOTP disables TOTP and clears the secret for a user
func (s *Store) DisableTOTP(userID int) error {
	_, err := s.db.Exec("UPDATE users SET totp_enabled = 0, totp_secret = '' WHERE id = ?", userID)
	return err
}

func (s *Store) DeleteUser(id int) error {
	_, err := s.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// Certificate methods

func (s *Store) GetCertificates() ([]Certificate, error) {
	rows, err := s.db.Query("SELECT id, domain, type, issuer, cert_path, key_path, auto_renew, status, expires_at FROM certificates")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var c Certificate
		if err := rows.Scan(&c.ID, &c.Domain, &c.Type, &c.Issuer, &c.CertPath, &c.KeyPath, &c.AutoRenew, &c.Status, &c.ExpiresAt); err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func (s *Store) CreateCertificate(c *Certificate) error {
	result, err := s.db.Exec(
		"INSERT INTO certificates (domain, type, issuer, cert_path, key_path, auto_renew, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		c.Domain, c.Type, c.Issuer, c.CertPath, c.KeyPath, c.AutoRenew, c.Status, c.ExpiresAt,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	c.ID = int(id)
	return nil
}

func (s *Store) DeleteCertificate(id int) error {
	_, err := s.db.Exec("DELETE FROM certificates WHERE id = ?", id)
	return err
}

func (s *Store) GetCertificateByID(id int) (*Certificate, error) {
	var c Certificate
	err := s.db.QueryRow("SELECT id, domain, type, issuer, cert_path, key_path, auto_renew, status, expires_at FROM certificates WHERE id = ?", id).
		Scan(&c.ID, &c.Domain, &c.Type, &c.Issuer, &c.CertPath, &c.KeyPath, &c.AutoRenew, &c.Status, &c.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) UpdateCertificateExpiry(id int, expiresAt time.Time) error {
	_, err := s.db.Exec("UPDATE certificates SET expires_at = ? WHERE id = ?", expiresAt, id)
	return err
}

func (s *Store) UpdateCertificateStatus(id int, status string) error {
	_, err := s.db.Exec("UPDATE certificates SET status = ? WHERE id = ?", status, id)
	return err
}

// WAF Rule methods

func (s *Store) GetWAFRules() ([]WAFRule, error) {
	rows, err := s.db.Query("SELECT id, name, rule, enabled, mode, exclusions, route_id FROM waf_rules")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WAFRule
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var r WAFRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Rule, &r.Enabled, &r.Mode, &r.Exclusions, &r.RouteID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// GetGlobalWAFRules returns only global WAF rules (route_id IS NULL)
func (s *Store) GetGlobalWAFRules() ([]WAFRule, error) {
	rows, err := s.db.Query("SELECT id, name, rule, enabled, mode, exclusions, route_id FROM waf_rules WHERE route_id IS NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WAFRule
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var r WAFRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Rule, &r.Enabled, &r.Mode, &r.Exclusions, &r.RouteID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// GetWAFRulesForRoute returns both global rules and route-specific rules for a given route
func (s *Store) GetWAFRulesForRoute(routeID int) ([]WAFRule, error) {
	rows, err := s.db.Query("SELECT id, name, rule, enabled, mode, exclusions, route_id FROM waf_rules WHERE route_id IS NULL OR route_id = ?", routeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WAFRule
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var r WAFRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Rule, &r.Enabled, &r.Mode, &r.Exclusions, &r.RouteID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (s *Store) CreateWAFRule(r *WAFRule) error {
	result, err := s.db.Exec(
		"INSERT INTO waf_rules (name, rule, enabled, mode, exclusions, route_id) VALUES (?, ?, ?, ?, ?, ?)",
		r.Name, r.Rule, r.Enabled, r.Mode, r.Exclusions, r.RouteID,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	r.ID = int(id)
	return nil
}

func (s *Store) DeleteWAFRule(id int) error {
	_, err := s.db.Exec("DELETE FROM waf_rules WHERE id = ?", id)
	return err
}

func (s *Store) UpdateWAFRule(r *WAFRule) error {
	_, err := s.db.Exec("UPDATE waf_rules SET name = ?, rule = ?, enabled = ?, mode = ?, exclusions = ?, route_id = ? WHERE id = ?", r.Name, r.Rule, r.Enabled, r.Mode, r.Exclusions, r.RouteID, r.ID)
	return err
}

// APIKey methods

func (s *Store) GetAPIKey(keyID string) (*APIKey, error) {
	row := s.db.QueryRow("SELECT id, key_id, key_secret_hash, user_id, name, created_at, expires_at, last_used FROM api_keys WHERE key_id = ?", keyID)
	var key APIKey
	var expiresAt, lastUsed sql.NullTime
	err := row.Scan(&key.ID, &key.KeyID, &key.KeySecretHash, &key.UserID, &key.Name, &key.CreatedAt, &expiresAt, &lastUsed)
	if err != nil {
		return nil, err
	}
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if lastUsed.Valid {
		key.LastUsed = &lastUsed.Time
	}
	return &key, nil
}

func (s *Store) GetAPIKeysByUser(userID int) ([]APIKey, error) {
	rows, err := s.db.Query("SELECT id, key_id, key_secret_hash, user_id, name, created_at, expires_at, last_used FROM api_keys WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var key APIKey
		var expiresAt, lastUsed sql.NullTime
		if err := rows.Scan(&key.ID, &key.KeyID, &key.KeySecretHash, &key.UserID, &key.Name, &key.CreatedAt, &expiresAt, &lastUsed); err != nil {
			return nil, err
		}
		if expiresAt.Valid {
			key.ExpiresAt = &expiresAt.Time
		}
		if lastUsed.Valid {
			key.LastUsed = &lastUsed.Time
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (s *Store) CreateAPIKey(key *APIKey) error {
	result, err := s.db.Exec(
		"INSERT INTO api_keys (key_id, key_secret_hash, user_id, name, expires_at) VALUES (?, ?, ?, ?, ?)",
		key.KeyID, key.KeySecretHash, key.UserID, key.Name, key.ExpiresAt,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	key.ID = int(id)
	return nil
}

func (s *Store) DeleteAPIKey(keyID string) error {
	_, err := s.db.Exec("DELETE FROM api_keys WHERE key_id = ?", keyID)
	return err
}

// DeleteAPIKeyByUser atomically deletes an API key only if it belongs to the given user.
func (s *Store) DeleteAPIKeyByUser(keyID string, userID int) (bool, error) {
	result, err := s.db.Exec("DELETE FROM api_keys WHERE key_id = ? AND user_id = ?", keyID, userID)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rowsAffected > 0, nil
}

func (s *Store) UpdateAPIKeyLastUsed(keyID string) error {
	_, err := s.db.Exec("UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE key_id = ?", keyID)
	return err
}

// DeleteUserSessions deletes all sessions for a user (for security events)
func (s *Store) DeleteUserSessions(userID int) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE user_id = ?", fmt.Sprintf("%d", userID))
	return err
}

// UpdateUserPassword updates a user's password hash
func (s *Store) UpdateUserPassword(userID int, passwordHash string) error {
	_, err := s.db.Exec("UPDATE users SET password = ? WHERE id = ?", passwordHash, userID)
	return err
}

// UpdateUserRole updates a user's role
func (s *Store) UpdateUserRole(userID int, role string) error {
	_, err := s.db.Exec("UPDATE users SET role = ? WHERE id = ?", role, userID)
	return err
}

// UpdateUserEnabled updates whether a user account is enabled
func (s *Store) UpdateUserEnabled(userID int, enabled bool) error {
	_, err := s.db.Exec("UPDATE users SET enabled = ? WHERE id = ?", enabled, userID)
	return err
}

// CreatePasswordResetToken creates a password reset token
func (s *Store) CreatePasswordResetToken(userID int, tokenHash string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		"INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
		userID, tokenHash, expiresAt,
	)
	return err
}

// ValidatePasswordResetToken validates a password reset token and marks it as used
// Uses atomic UPDATE ... RETURNING to prevent race conditions and ensure the user_id
// is fetched in the same statement as the consumption.
func (s *Store) ValidatePasswordResetToken(tokenHash string) (int, error) {
	var userID int
	err := s.db.QueryRow(
		"UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ? AND datetime(expires_at) > datetime('now') AND used = 0 RETURNING user_id",
		tokenHash,
	).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, sql.ErrNoRows
		}
		return 0, err
	}
	return userID, nil
}

// CreateAdminToken stores an admin token in the database
func (s *Store) CreateAdminToken(tokenHash string, createdBy int, expiresAt time.Time) error {
	_, err := s.db.Exec(
		"INSERT INTO admin_tokens (token_hash, created_by, expires_at) VALUES (?, ?, ?)",
		tokenHash, createdBy, expiresAt,
	)
	return err
}

// ValidateAdminToken validates an admin token and marks it as used
// Uses atomic UPDATE ... RETURNING to prevent race condition where same token could be used twice.
func (s *Store) ValidateAdminToken(tokenHash string) (int, error) {
	var createdBy int
	err := s.db.QueryRow(
		"UPDATE admin_tokens SET used = 1 WHERE token_hash = ? AND datetime(expires_at) > datetime('now') AND used = 0 RETURNING created_by",
		tokenHash,
	).Scan(&createdBy)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, sql.ErrNoRows
		}
		return 0, err
	}
	return createdBy, nil
}

// FailedAttempt represents a record of failed login attempts
type FailedAttempt struct {
	Identifier   string
	AttemptCount int
	FirstAttempt time.Time
	LastAttempt  time.Time
	LockedUntil  *time.Time
}

// GetFailedAttempt retrieves failed attempt info for an identifier
func (s *Store) GetFailedAttempt(identifier string) (*FailedAttempt, error) {
	row := s.db.QueryRow(
		"SELECT identifier, attempt_count, first_attempt, last_attempt, locked_until FROM failed_attempts WHERE identifier = ?",
		identifier,
	)
	var attempt FailedAttempt
	var lockedUntil sql.NullTime
	err := row.Scan(&attempt.Identifier, &attempt.AttemptCount, &attempt.FirstAttempt, &attempt.LastAttempt, &lockedUntil)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if lockedUntil.Valid {
		attempt.LockedUntil = &lockedUntil.Time
	}
	return &attempt, nil
}

// RecordFailedAttempt records a failed login attempt
func (s *Store) RecordFailedAttempt(identifier string, maxAttempts int, lockoutDuration time.Duration) error {
	now := time.Now()
	lockedUntil := now.Add(lockoutDuration)

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Try to update existing record
	result, err := tx.Exec(
		"UPDATE failed_attempts SET attempt_count = attempt_count + 1, last_attempt = ? WHERE identifier = ?",
		now, identifier,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		// No existing record, create new one
		_, err = tx.Exec(
			"INSERT INTO failed_attempts (identifier, attempt_count, first_attempt, last_attempt) VALUES (?, 1, ?, ?)",
			identifier, now, now,
		)
		if err != nil {
			return err
		}
	}

	// Check if should be locked (within the same transaction)
	var count int
	err = tx.QueryRow("SELECT attempt_count FROM failed_attempts WHERE identifier = ?", identifier).Scan(&count)
	if err != nil {
		return err
	}

	if count >= maxAttempts {
		_, err = tx.Exec(
			"UPDATE failed_attempts SET locked_until = ? WHERE identifier = ?",
			lockedUntil, identifier,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ClearFailedAttempts clears failed attempts for an identifier (on successful login)
func (s *Store) ClearFailedAttempts(identifier string) error {
	_, err := s.db.Exec("DELETE FROM failed_attempts WHERE identifier = ?", identifier)
	return err
}

// IsLocked checks if an identifier is currently locked out
func (s *Store) IsLocked(identifier string) (bool, *time.Time, error) {
	row := s.db.QueryRow(
		"SELECT locked_until FROM failed_attempts WHERE identifier = ? AND locked_until IS NOT NULL AND datetime(locked_until) > datetime('now')",
		identifier,
	)
	var lockedUntil time.Time
	err := row.Scan(&lockedUntil)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil, nil
		}
		return false, nil, err
	}
	return true, &lockedUntil, nil
}

// GetRedirectDomains returns all allowed redirect domains
func (s *Store) GetRedirectDomains() ([]string, error) {
	rows, err := s.db.Query("SELECT domain FROM redirect_domains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

// AddRedirectDomain adds a domain to the allowlist
func (s *Store) AddRedirectDomain(domain string) error {
	_, err := s.db.Exec("INSERT INTO redirect_domains (domain) VALUES (?)", domain)
	return err
}

// RemoveRedirectDomain removes a domain from the allowlist
func (s *Store) RemoveRedirectDomain(domain string) error {
	_, err := s.db.Exec("DELETE FROM redirect_domains WHERE domain = ?", domain)
	return err
}

// Session methods for user management

// GetSessionsByUser returns all sessions for a specific user
func (s *Store) GetSessionsByUser(userID int) ([]Session, error) {
	rows, err := s.db.Query(`
		SELECT id, user_email, user_name, user_id, provider_name, created_at, expires_at
		FROM sessions WHERE user_id = ?
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserEmail, &sess.UserName, &sess.UserID, &sess.ProviderName, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// SecurityEvent methods

func (s *Store) CreateSecurityEvent(e *SecurityEvent) error {
	result, err := s.db.Exec(
		"INSERT INTO security_events (event_type, client_ip, host, uri, method, user_agent, rule_name, rule_id, route_id, action) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		e.EventType, e.ClientIP, e.Host, e.URI, e.Method, e.UserAgent, e.RuleName, e.RuleID, e.RouteID, e.Action,
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	e.ID = int(id)
	return nil
}

// SecurityEvent query methods

func (s *Store) GetSecurityEvents(limit int, offset int) ([]SecurityEvent, error) {
	rows, err := s.db.Query("SELECT id, event_type, client_ip, host, uri, method, user_agent, rule_name, rule_id, route_id, action, created_at FROM security_events ORDER BY created_at DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.ClientIP, &e.Host, &e.URI, &e.Method, &e.UserAgent, &e.RuleName, &e.RuleID, &e.RouteID, &e.Action, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

func (s *Store) GetSecurityEventCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM security_events").Scan(&count)
	return count, err
}

func (s *Store) GetBlockedSecurityEventCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM security_events WHERE action = 'blocked' OR action = 'block'").Scan(&count)
	return count, err
}

func (s *Store) GetSecurityEventsForRoute(routeID int, limit int, offset int) ([]SecurityEvent, error) {
	rows, err := s.db.Query("SELECT id, event_type, client_ip, host, uri, method, user_agent, rule_name, rule_id, route_id, action, created_at FROM security_events WHERE route_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", routeID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.ClientIP, &e.Host, &e.URI, &e.Method, &e.UserAgent, &e.RuleName, &e.RuleID, &e.RouteID, &e.Action, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

// Settings methods

func (s *Store) GetSetting(key string) (string, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP", key, value, value)
	return err
}

// GetSettingDefault returns the setting value or the default if not found
func (s *Store) GetSettingDefault(key, defaultVal string) string {
	val, err := s.GetSetting(key)
	if err != nil || val == "" {
		return defaultVal
	}
	return val
}

// ClearSettings removes all settings from the database
func (s *Store) ClearSettings() error {
	_, err := s.db.Exec("DELETE FROM settings")
	return err
}

// GetAdminCount returns the number of admin users
func (s *Store) GetAdminCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1").Scan(&count)
	return count, err
}

// UpdateOIDCProvider updates an existing OIDC provider
func (s *Store) UpdateOIDCProvider(p *OIDCProvider) error {
	// Encrypt client secret before storing
	encryptedSecret, err := crypto.Encrypt(p.ClientSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt client secret: %w", err)
	}

	_, err = s.db.Exec(
		"UPDATE oidc_providers SET name = ?, client_id = ?, client_secret = ?, discovery_url = ?, redirect_url = ? WHERE id = ?",
		p.Name, p.ClientID, encryptedSecret, p.DiscoveryURL, p.RedirectURL, p.ID,
	)
	return err
}

// Webhook methods

func (s *Store) GetWebhooks() ([]Webhook, error) {
	rows, err := s.db.Query("SELECT id, name, url, events, secret, enabled, created_at FROM webhooks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []Webhook
	for rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var w Webhook
		var enabled int
		if err := rows.Scan(&w.ID, &w.Name, &w.URL, &w.Events, &w.Secret, &enabled, &w.CreatedAt); err != nil {
			return nil, err
		}
		w.Enabled = enabled == 1
		webhooks = append(webhooks, w)
	}
	return webhooks, nil
}

func (s *Store) CreateWebhook(w *Webhook) error {
	result, err := s.db.Exec(
		"INSERT INTO webhooks (name, url, events, secret, enabled) VALUES (?, ?, ?, ?, ?)",
		w.Name, w.URL, w.Events, w.Secret, boolToInt(w.Enabled),
	)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}
	w.ID = int(id)
	return nil
}

func (s *Store) UpdateWebhook(w *Webhook) error {
	_, err := s.db.Exec(
		"UPDATE webhooks SET name = ?, url = ?, events = ?, secret = ?, enabled = ? WHERE id = ?",
		w.Name, w.URL, w.Events, w.Secret, boolToInt(w.Enabled), w.ID,
	)
	return err
}

func (s *Store) DeleteWebhook(id int) error {
	_, err := s.db.Exec("DELETE FROM webhooks WHERE id = ?", id)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
