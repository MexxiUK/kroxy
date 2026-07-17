package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kroxy/kroxy/internal/crypto"
	sqlite3 "github.com/mattn/go-sqlite3"
)

type Store struct {
	db     *sql.DB
	dbPath string
}

// Sentinel errors returned by store methods when a database constraint or
// business rule is violated. Callers (e.g. API handlers) can use errors.Is to
// translate these into actionable HTTP responses without parsing driver errors.
var (
	// ErrRouteDomainExists is returned by CreateRoute/UpdateRoute when the
	// domain violates the UNIQUE constraint on routes.domain.
	ErrRouteDomainExists = errors.New("route with this domain already exists")
)

// isUniqueConstraintError reports whether err is a SQLite UNIQUE constraint
// violation for the given table.column. It hides driver-specific details from
// the rest of the store package.
func isUniqueConstraintError(err error, table, column string) bool {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	if sqliteErr.ExtendedCode != sqlite3.ErrConstraintUnique && sqliteErr.Code != sqlite3.ErrConstraint {
		return false
	}
	// SQLite messages are deterministic and do not contain user input:
	// "UNIQUE constraint failed: <table>.<column>"
	return sqliteErr.Error() == fmt.Sprintf("UNIQUE constraint failed: %s.%s", table, column)
}

func New(path string) (*Store, error) {
	// Use connection-string pragmas so every connection gets WAL mode and busy_timeout.
	connStr := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000", path)
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return nil, err
	}

	// Use versioned migrations
	migrator := NewMigrator(db)
	if err := migrator.Up(); err != nil {
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	s := &Store{db: db, dbPath: path}

	// Migrate any webhook secrets that predate at-rest encryption.
	if err := s.migrateWebhookSecrets(); err != nil {
		return nil, fmt.Errorf("webhook secret migration failed: %w", err)
	}

	// Set database file permissions to owner read/write only (0600)
	// This prevents other users from reading sensitive data
	if err := os.Chmod(path, 0600); err != nil {
		// Log but don't fail - database is still usable
		// This can happen if running as non-root or on certain filesystems
		log.Printf("Warning: failed to set database file permissions on %s: %v", path, err)
	}
	// WAL mode creates sidecar files; restrict their permissions too
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0600); err != nil {
			log.Printf("Warning: failed to set WAL file permissions on %s%s: %v", path, suffix, err)
		}
	}

	// Require encryption key in production mode
	if err := crypto.RequireEncryptionInProduction(); err != nil {
		return nil, err
	}

	// Limit connections: SQLite with WAL supports multiple readers but only one writer.
	// SetMaxOpenConns(1) serializes all access through one connection, eliminating lock contention.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	return s, nil
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

const defaultListLimit = 1000

// GetRoutes returns all routes. It deliberately does NOT apply a LIMIT: silently
// truncating the route table would drop routes from the proxy config (no WAF /
// no proxying), health checks, backup export/import, certificate issuance, and
// the admin UI — a correctness and security bug (SEC-042). Route count is
// admin-controlled and small by nature for a reverse proxy, so an uncapped
// read is safe and correct here.
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
		var r Route
		if err := rows.Scan(&r.ID, &r.Domain, &r.Backend, &r.Enabled, &r.WAFEnabled, &r.WAFMode, &r.WAFParanoiaLevel, &r.OIDCEnabled, &r.OIDCProviderID,
			&r.RateLimit, &r.EnableGzip, &r.EnableBrotli, &r.EnableCache, &r.CustomHeaders, &r.BlockCountries, &r.AllowCountries, &r.RequireHTTPS,
			&r.IsAdminRoute, &r.BotProtection, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		routes = append(routes, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return routes, nil
}

// GetRouteByID returns the route with the given ID, or sql.ErrNoRows if no such
// route exists. This is an O(1) point lookup used by single-route operations so
// they do not depend on GetRoutes() and cannot be missed by any future list
// cap (SEC-040).
func (s *Store) GetRouteByID(id int) (*Route, error) {
	row := s.db.QueryRow(`SELECT id, domain, backend, enabled, waf_enabled, waf_mode, waf_paranoia_level, oidc_enabled, oidc_provider_id,
		rate_limit, enable_gzip, enable_brotli, enable_cache, custom_headers, block_countries, allow_countries, require_https,
		is_admin_route, bot_protection, created_at, updated_at FROM routes WHERE id = ?`, id)
	var r Route
	err := row.Scan(&r.ID, &r.Domain, &r.Backend, &r.Enabled, &r.WAFEnabled, &r.WAFMode, &r.WAFParanoiaLevel, &r.OIDCEnabled, &r.OIDCProviderID,
		&r.RateLimit, &r.EnableGzip, &r.EnableBrotli, &r.EnableCache, &r.CustomHeaders, &r.BlockCountries, &r.AllowCountries, &r.RequireHTTPS,
		&r.IsAdminRoute, &r.BotProtection, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) CreateRoute(r *Route) error {
	result, err := s.db.Exec(
		"INSERT INTO routes (domain, backend, enabled, waf_enabled, waf_mode, waf_paranoia_level, oidc_enabled, oidc_provider_id, rate_limit, enable_gzip, enable_brotli, enable_cache, custom_headers, block_countries, allow_countries, require_https, is_admin_route, bot_protection) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		r.Domain, r.Backend, r.Enabled, r.WAFEnabled, r.WAFMode, r.WAFParanoiaLevel, r.OIDCEnabled, r.OIDCProviderID, r.RateLimit, r.EnableGzip, r.EnableBrotli, r.EnableCache, r.CustomHeaders, r.BlockCountries, r.AllowCountries, r.RequireHTTPS, r.IsAdminRoute, r.BotProtection,
	)
	if err != nil {
		if isUniqueConstraintError(err, "routes", "domain") {
			return ErrRouteDomainExists
		}
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
	res, err := s.db.Exec("DELETE FROM routes WHERE id = ?", id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

func (s *Store) UpdateRoute(r *Route) error {
	res, err := s.db.Exec(
		"UPDATE routes SET domain = ?, backend = ?, enabled = ?, waf_enabled = ?, waf_mode = ?, waf_paranoia_level = ?, oidc_enabled = ?, oidc_provider_id = ?, rate_limit = ?, enable_gzip = ?, enable_brotli = ?, enable_cache = ?, custom_headers = ?, block_countries = ?, allow_countries = ?, require_https = ?, is_admin_route = ?, bot_protection = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		r.Domain, r.Backend, r.Enabled, r.WAFEnabled, r.WAFMode, r.WAFParanoiaLevel, r.OIDCEnabled, r.OIDCProviderID, r.RateLimit, r.EnableGzip, r.EnableBrotli, r.EnableCache, r.CustomHeaders, r.BlockCountries, r.AllowCountries, r.RequireHTTPS, r.IsAdminRoute, r.BotProtection, r.ID,
	)
	if err != nil {
		if isUniqueConstraintError(err, "routes", "domain") {
			return ErrRouteDomainExists
		}
		return err
	}
	return requireRowsAffected(res, 1)
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
	rows, err := s.db.Query("SELECT id, name, client_id, client_secret, discovery_url, redirect_url FROM oidc_providers LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []OIDCProvider
	for rows.Next() {
		var p OIDCProvider
		if err := rows.Scan(&p.ID, &p.Name, &p.ClientID, &p.ClientSecret, &p.DiscoveryURL, &p.RedirectURL); err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
	// Decrypt client secret
	decryptedSecret, err := crypto.Decrypt(encryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt client secret for provider %d: %w", p.ID, err)
	}
	p.ClientSecret = decryptedSecret
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
	res, err := s.db.Exec("DELETE FROM oidc_providers WHERE id = ?", id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// Session methods

func (s *Store) GetSession(id string) (*Session, error) {
	row := s.db.QueryRow("SELECT id, user_email, user_name, user_id, provider_name, client_ip, user_agent, created_at, expires_at FROM sessions WHERE id = ?", id)
	var sess Session
	err := row.Scan(&sess.ID, &sess.UserEmail, &sess.UserName, &sess.UserID, &sess.ProviderName, &sess.ClientIP, &sess.UserAgent, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Store) CreateSession(sess *Session) error {
	_, err := s.db.Exec(
		"INSERT INTO sessions (id, user_email, user_name, user_id, provider_name, client_ip, user_agent, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		sess.ID, sess.UserEmail, sess.UserName, sess.UserID, sess.ProviderName, sess.ClientIP, sess.UserAgent, sess.CreatedAt, sess.ExpiresAt,
	)
	return err
}

func (s *Store) DeleteSession(id string) error {
	res, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

func (s *Store) UpdateSessionExpiry(id string, expiresAt time.Time) error {
	res, err := s.db.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", expiresAt, id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

func (s *Store) CleanupSessions() error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE datetime(expires_at) < datetime('now')")
	return err
}

// Blacklist methods

func (s *Store) GetBlacklists() ([]Blacklist, error) {
	rows, err := s.db.Query("SELECT id, type, value, enabled, created_at FROM blacklists LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Blacklist
	for rows.Next() {
		var b Blacklist
		if err := rows.Scan(&b.ID, &b.Type, &b.Value, &b.Enabled, &b.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
	res, err := s.db.Exec("DELETE FROM blacklists WHERE id = ?", id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// Whitelist methods

func (s *Store) GetWhitelists() ([]Whitelist, error) {
	rows, err := s.db.Query("SELECT id, type, value, enabled, created_at FROM whitelists LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []Whitelist
	for rows.Next() {
		var w Whitelist
		if err := rows.Scan(&w.ID, &w.Type, &w.Value, &w.Enabled, &w.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
	res, err := s.db.Exec("DELETE FROM whitelists WHERE id = ?", id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// RateLimit methods

func (s *Store) GetRateLimits() ([]RateLimit, error) {
	rows, err := s.db.Query("SELECT id, domain, requests_per_minute, burst, enabled FROM rate_limits LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var limits []RateLimit
	for rows.Next() {
		var r RateLimit
		if err := rows.Scan(&r.ID, &r.Domain, &r.RequestsPerMinute, &r.Burst, &r.Enabled); err != nil {
			return nil, err
		}
		limits = append(limits, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
	res, err := s.db.Exec("UPDATE rate_limits SET domain = ?, requests_per_minute = ?, burst = ?, enabled = ? WHERE id = ?", r.Domain, r.RequestsPerMinute, r.Burst, r.Enabled, r.ID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

func (s *Store) DeleteRateLimit(id int) error {
	res, err := s.db.Exec("DELETE FROM rate_limits WHERE id = ?", id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// User methods

func (s *Store) GetUsers() ([]User, error) {
	rows, err := s.db.Query("SELECT id, email, name, role, enabled, totp_enabled FROM users LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.Enabled, &u.TOTPEnabled); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
	res, err := s.db.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", encryptedSecret, userID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// EnableTOTP enables TOTP verification for a user
func (s *Store) EnableTOTP(userID int) error {
	res, err := s.db.Exec("UPDATE users SET totp_enabled = 1 WHERE id = ?", userID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// DisableTOTP disables TOTP and clears the secret for a user
func (s *Store) DisableTOTP(userID int) error {
	res, err := s.db.Exec("UPDATE users SET totp_enabled = 0, totp_secret = '' WHERE id = ?", userID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

func (s *Store) DeleteUser(id int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Remove API keys first so they are not orphaned when the user is deleted.
	if _, err := tx.Exec("DELETE FROM api_keys WHERE user_id = ?", id); err != nil {
		return err
	}

	res, err := tx.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return err
	}
	if err := requireRowsAffected(res, 1); err != nil {
		return err
	}

	return tx.Commit()
}

// Certificate methods

func (s *Store) GetCertificates() ([]Certificate, error) {
	rows, err := s.db.Query("SELECT id, domain, type, issuer, cert_path, key_path, auto_renew, status, expires_at FROM certificates LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.Domain, &c.Type, &c.Issuer, &c.CertPath, &c.KeyPath, &c.AutoRenew, &c.Status, &c.ExpiresAt); err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
	res, err := s.db.Exec("DELETE FROM certificates WHERE id = ?", id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
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
	res, err := s.db.Exec("UPDATE certificates SET expires_at = ? WHERE id = ?", expiresAt, id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

func (s *Store) UpdateCertificateStatus(id int, status string) error {
	res, err := s.db.Exec("UPDATE certificates SET status = ? WHERE id = ?", status, id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// WAF Rule methods

func (s *Store) GetWAFRules() ([]WAFRule, error) {
	rows, err := s.db.Query("SELECT id, name, rule, enabled, mode, exclusions, route_id FROM waf_rules LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WAFRule
	for rows.Next() {
		var r WAFRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Rule, &r.Enabled, &r.Mode, &r.Exclusions, &r.RouteID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return rules, nil
}

// GetGlobalWAFRules returns only global WAF rules (route_id IS NULL)
func (s *Store) GetGlobalWAFRules() ([]WAFRule, error) {
	rows, err := s.db.Query("SELECT id, name, rule, enabled, mode, exclusions, route_id FROM waf_rules WHERE route_id IS NULL LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WAFRule
	for rows.Next() {
		var r WAFRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Rule, &r.Enabled, &r.Mode, &r.Exclusions, &r.RouteID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return rules, nil
}

// GetWAFRulesForRoute returns both global rules and route-specific rules for a given route
func (s *Store) GetWAFRulesForRoute(routeID int) ([]WAFRule, error) {
	rows, err := s.db.Query("SELECT id, name, rule, enabled, mode, exclusions, route_id FROM waf_rules WHERE route_id IS NULL OR route_id = ? LIMIT ?", routeID, defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WAFRule
	for rows.Next() {
		var r WAFRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Rule, &r.Enabled, &r.Mode, &r.Exclusions, &r.RouteID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
	res, err := s.db.Exec("DELETE FROM waf_rules WHERE id = ?", id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

func (s *Store) UpdateWAFRule(r *WAFRule) error {
	res, err := s.db.Exec("UPDATE waf_rules SET name = ?, rule = ?, enabled = ?, mode = ?, exclusions = ?, route_id = ? WHERE id = ?", r.Name, r.Rule, r.Enabled, r.Mode, r.Exclusions, r.RouteID, r.ID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// APIKey methods

func (s *Store) GetAPIKey(keyID string) (*APIKey, error) {
	row := s.db.QueryRow("SELECT id, key_id, key_secret_hash, key_secret_hmac, user_id, name, created_at, expires_at, last_used FROM api_keys WHERE key_id = ?", keyID)
	var key APIKey
	var expiresAt, lastUsed sql.NullTime
	err := row.Scan(&key.ID, &key.KeyID, &key.KeySecretHash, &key.KeySecretHMAC, &key.UserID, &key.Name, &key.CreatedAt, &expiresAt, &lastUsed)
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
	rows, err := s.db.Query("SELECT id, key_id, key_secret_hash, key_secret_hmac, user_id, name, created_at, expires_at, last_used FROM api_keys WHERE user_id = ? LIMIT ?", userID, defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var key APIKey
		var expiresAt, lastUsed sql.NullTime
		if err := rows.Scan(&key.ID, &key.KeyID, &key.KeySecretHash, &key.KeySecretHMAC, &key.UserID, &key.Name, &key.CreatedAt, &expiresAt, &lastUsed); err != nil {
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return keys, nil
}

func (s *Store) CreateAPIKey(key *APIKey) error {
	result, err := s.db.Exec(
		"INSERT INTO api_keys (key_id, key_secret_hash, key_secret_hmac, user_id, name, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		key.KeyID, key.KeySecretHash, key.KeySecretHMAC, key.UserID, key.Name, key.ExpiresAt,
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
	res, err := s.db.Exec("DELETE FROM api_keys WHERE key_id = ?", keyID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// DeleteAPIKeysByUser deletes every API key belonging to a user.
func (s *Store) DeleteAPIKeysByUser(userID int) error {
	res, err := s.db.Exec("DELETE FROM api_keys WHERE user_id = ?", userID)
	if err != nil {
		return err
	}
	// A user may legitimately have zero API keys; accept 0 or more.
	_, err = res.RowsAffected()
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
	res, err := s.db.Exec("UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE key_id = ?", keyID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// DeleteUserSessions deletes all sessions for a user (for security events)
func (s *Store) DeleteUserSessions(userID int) error {
	res, err := s.db.Exec("DELETE FROM sessions WHERE user_id = ?", fmt.Sprintf("%d", userID))
	if err != nil {
		return err
	}
	// User may have zero sessions; just report error from RowsAffected itself.
	_, err = res.RowsAffected()
	return err
}

// UpdateUserPassword updates a user's password hash
func (s *Store) UpdateUserPassword(userID int, passwordHash string) error {
	res, err := s.db.Exec("UPDATE users SET password = ? WHERE id = ?", passwordHash, userID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// UpdateUserRole updates a user's role
func (s *Store) UpdateUserRole(userID int, role string) error {
	res, err := s.db.Exec("UPDATE users SET role = ? WHERE id = ?", role, userID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// UpdateUserEnabled updates whether a user account is enabled
func (s *Store) UpdateUserEnabled(userID int, enabled bool) error {
	res, err := s.db.Exec("UPDATE users SET enabled = ? WHERE id = ?", enabled, userID)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
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

	var count int

	// Check for an existing record and whether a previous lockout has expired.
	// If it has, reset the attempt counter so a single failure does not
	// immediately re-lock the account (permanent lockout bug).
	var existingCount int
	var existingLockedUntil sql.NullTime
	err = tx.QueryRow(
		"SELECT attempt_count, locked_until FROM failed_attempts WHERE identifier = ?",
		identifier,
	).Scan(&existingCount, &existingLockedUntil)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if err == sql.ErrNoRows {
		// No existing record, create one.
		_, err = tx.Exec(
			"INSERT INTO failed_attempts (identifier, attempt_count, first_attempt, last_attempt) VALUES (?, 1, ?, ?)",
			identifier, now, now,
		)
		if err != nil {
			return err
		}
		count = 1
	} else if existingLockedUntil.Valid && !existingLockedUntil.Time.After(now) {
		// Previous lockout has expired; reset the counter to start fresh.
		_, err = tx.Exec(
			"UPDATE failed_attempts SET attempt_count = 1, first_attempt = ?, last_attempt = ?, locked_until = NULL WHERE identifier = ?",
			now, now, identifier,
		)
		if err != nil {
			return err
		}
		count = 1
	} else {
		// Still within an active attempt window/lockout; increment the counter.
		_, err = tx.Exec(
			"UPDATE failed_attempts SET attempt_count = attempt_count + 1, last_attempt = ? WHERE identifier = ?",
			now, identifier,
		)
		if err != nil {
			return err
		}
		count = existingCount + 1
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
	res, err := s.db.Exec("DELETE FROM failed_attempts WHERE identifier = ?", identifier)
	if err != nil {
		return err
	}
	// It's normal for no row to exist if the user had no failed attempts.
	_, err = res.RowsAffected()
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
	rows, err := s.db.Query("SELECT domain FROM redirect_domains LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
	res, err := s.db.Exec("DELETE FROM redirect_domains WHERE domain = ?", domain)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// Session methods for user management

// GetSessionsByUser returns all sessions for a specific user
func (s *Store) GetSessionsByUser(userID int) ([]Session, error) {
	rows, err := s.db.Query(`
		SELECT id, user_email, user_name, user_id, provider_name, client_ip, user_agent, created_at, expires_at
		FROM sessions WHERE user_id = ? LIMIT ?
	`, userID, defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserEmail, &sess.UserName, &sess.UserID, &sess.ProviderName, &sess.ClientIP, &sess.UserAgent, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.ClientIP, &e.Host, &e.URI, &e.Method, &e.UserAgent, &e.RuleName, &e.RuleID, &e.RouteID, &e.Action, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.ClientIP, &e.Host, &e.URI, &e.Method, &e.UserAgent, &e.RuleName, &e.RuleID, &e.RouteID, &e.Action, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
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

	res, err := s.db.Exec(
		"UPDATE oidc_providers SET name = ?, client_id = ?, client_secret = ?, discovery_url = ?, redirect_url = ? WHERE id = ?",
		p.Name, p.ClientID, encryptedSecret, p.DiscoveryURL, p.RedirectURL, p.ID,
	)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// Webhook methods

func (s *Store) GetWebhooks() ([]Webhook, error) {
	rows, err := s.db.Query("SELECT id, name, url, events, secret, enabled, created_at FROM webhooks LIMIT ?", defaultListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []Webhook
	for rows.Next() {
		var w Webhook
		var enabled int
		var encryptedSecret string
		if err := rows.Scan(&w.ID, &w.Name, &w.URL, &w.Events, &encryptedSecret, &enabled, &w.CreatedAt); err != nil {
			return nil, err
		}
		w.Enabled = enabled == 1
		if encryptedSecret != "" {
			secret, err := crypto.Decrypt(encryptedSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt webhook secret: %w", err)
			}
			w.Secret = secret
		}
		webhooks = append(webhooks, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return webhooks, nil
}

// GetWebhook returns a single webhook by ID, decrypting its stored secret.
func (s *Store) GetWebhook(id int) (*Webhook, error) {
	row := s.db.QueryRow("SELECT id, name, url, events, secret, enabled, created_at FROM webhooks WHERE id = ?", id)

	var w Webhook
	var enabled int
	var encryptedSecret string
	if err := row.Scan(&w.ID, &w.Name, &w.URL, &w.Events, &encryptedSecret, &enabled, &w.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	w.Enabled = enabled == 1
	if encryptedSecret != "" {
		secret, err := crypto.Decrypt(encryptedSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt webhook secret: %w", err)
		}
		w.Secret = secret
	}
	return &w, nil
}

func (s *Store) CreateWebhook(w *Webhook) error {
	encryptedSecret, err := crypto.Encrypt(w.Secret)
	if err != nil {
		return fmt.Errorf("failed to encrypt webhook secret: %w", err)
	}

	result, err := s.db.Exec(
		"INSERT INTO webhooks (name, url, events, secret, enabled) VALUES (?, ?, ?, ?, ?)",
		w.Name, w.URL, w.Events, encryptedSecret, boolToInt(w.Enabled),
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
	encryptedSecret, err := crypto.Encrypt(w.Secret)
	if err != nil {
		return fmt.Errorf("failed to encrypt webhook secret: %w", err)
	}

	res, err := s.db.Exec(
		"UPDATE webhooks SET name = ?, url = ?, events = ?, secret = ?, enabled = ? WHERE id = ?",
		w.Name, w.URL, w.Events, encryptedSecret, boolToInt(w.Enabled), w.ID,
	)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

func (s *Store) DeleteWebhook(id int) error {
	res, err := s.db.Exec("DELETE FROM webhooks WHERE id = ?", id)
	if err != nil {
		return err
	}
	return requireRowsAffected(res, 1)
}

// migrateWebhookSecrets re-encrypts any webhook secrets that were stored in
// plaintext before at-rest encryption was introduced. It is idempotent:
// secrets that already decrypt cleanly are left alone.
func (s *Store) migrateWebhookSecrets() error {
	rows, err := s.db.Query("SELECT id, secret FROM webhooks WHERE secret != '' AND secret IS NOT NULL")
	if err != nil {
		return fmt.Errorf("failed to query webhook secrets for migration: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var secret string
		if err := rows.Scan(&id, &secret); err != nil {
			return fmt.Errorf("failed to scan webhook secret for migration: %w", err)
		}

		// Already encrypted values decrypt cleanly.
		if _, err := crypto.Decrypt(secret); err == nil {
			continue
		}

		encrypted, err := crypto.Encrypt(secret)
		if err != nil {
			return fmt.Errorf("failed to encrypt legacy webhook secret %d: %w", id, err)
		}

		if _, err := s.db.Exec("UPDATE webhooks SET secret = ? WHERE id = ?", encrypted, id); err != nil {
			return fmt.Errorf("failed to update migrated webhook secret %d: %w", id, err)
		}
		log.Printf("Migrated plaintext webhook secret to encrypted at rest (webhook %d)", id)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("webhook secret migration iteration error: %w", err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// requireRowsAffected checks that a mutation affected exactly one row and
// returns sql.ErrNoRows when nothing was updated or deleted.
func requireRowsAffected(res sql.Result, want int64) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	if n != want {
		return fmt.Errorf("expected %d rows affected, got %d", want, n)
	}
	return nil
}
