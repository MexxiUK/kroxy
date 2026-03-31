package store

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	if err := migrate(db); err != nil {
		return nil, err
	}

	// Set database file permissions to owner read/write only (0600)
	// This prevents other users from reading sensitive data
	if err := os.Chmod(path, 0600); err != nil {
		// Log but don't fail - database is still usable
		// This can happen if running as non-root or on certain filesystems
	}

	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS routes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		backend TEXT NOT NULL,
		enabled BOOLEAN DEFAULT true,
		waf_enabled BOOLEAN DEFAULT true,
		oidc_enabled BOOLEAN DEFAULT false,
		oidc_provider_id INTEGER DEFAULT 0,
		rate_limit INTEGER DEFAULT 0,
		enable_gzip BOOLEAN DEFAULT true,
		enable_brotli BOOLEAN DEFAULT false,
		enable_cache BOOLEAN DEFAULT false,
		custom_headers TEXT DEFAULT '{}',
		block_countries TEXT DEFAULT '',
		allow_countries TEXT DEFAULT '',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS oidc_providers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		client_id TEXT NOT NULL,
		client_secret TEXT NOT NULL,
		discovery_url TEXT NOT NULL,
		redirect_url TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		cert_path TEXT,
		key_path TEXT,
		auto_renew BOOLEAN DEFAULT true,
		expires_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS waf_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		rule TEXT NOT NULL,
		enabled BOOLEAN DEFAULT true
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_email TEXT NOT NULL,
		user_name TEXT NOT NULL,
		user_id TEXT NOT NULL,
		provider_name TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS blacklists (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		enabled BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS whitelists (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type TEXT NOT NULL,
		value TEXT NOT NULL,
		enabled BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS rate_limits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		requests_per_minute INTEGER NOT NULL,
		burst INTEGER DEFAULT 10,
		enabled BOOLEAN DEFAULT true
	);

	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL,
		role TEXT DEFAULT 'viewer',
		password TEXT NOT NULL,
		enabled BOOLEAN DEFAULT true
	);

	CREATE TABLE IF NOT EXISTS backends (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		route_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		weight INTEGER DEFAULT 1,
		healthy BOOLEAN DEFAULT true,
		last_check TIMESTAMP,
		last_error TEXT,
		FOREIGN KEY (route_id) REFERENCES routes(id)
	);

	CREATE TABLE IF NOT EXISTS api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key_id TEXT NOT NULL UNIQUE,
		key_secret_hash TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP,
		last_used TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_routes_domain ON routes(domain);
	CREATE INDEX IF NOT EXISTS idx_routes_enabled ON routes(enabled);
	CREATE INDEX IF NOT EXISTS idx_sessions_id ON sessions(id);
	CREATE INDEX IF NOT EXISTS idx_blacklists_type ON blacklists(type);
	CREATE INDEX IF NOT EXISTS idx_whitelists_type ON whitelists(type);
	CREATE INDEX IF NOT EXISTS idx_api_keys_id ON api_keys(key_id);
	`

	_, err := db.Exec(schema)
	return err
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Route methods

func (s *Store) GetRoutes() ([]Route, error) {
	rows, err := s.db.Query(`SELECT id, domain, backend, enabled, waf_enabled, oidc_enabled, oidc_provider_id,
		rate_limit, enable_gzip, enable_brotli, enable_cache, custom_headers, block_countries, allow_countries,
		created_at, updated_at FROM routes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var routes []Route
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.ID, &r.Domain, &r.Backend, &r.Enabled, &r.WAFEnabled, &r.OIDCEnabled, &r.OIDCProviderID,
			&r.RateLimit, &r.EnableGzip, &r.EnableBrotli, &r.EnableCache, &r.CustomHeaders, &r.BlockCountries, &r.AllowCountries,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		routes = append(routes, r)
	}
	return routes, nil
}

func (s *Store) GetRouteByDomain(domain string) (*Route, error) {
	row := s.db.QueryRow(`SELECT id, domain, backend, enabled, waf_enabled, oidc_enabled, oidc_provider_id,
		rate_limit, enable_gzip, enable_brotli, enable_cache, custom_headers, block_countries, allow_countries,
		created_at, updated_at FROM routes WHERE domain = ?`, domain)
	var r Route
	err := row.Scan(&r.ID, &r.Domain, &r.Backend, &r.Enabled, &r.WAFEnabled, &r.OIDCEnabled, &r.OIDCProviderID,
		&r.RateLimit, &r.EnableGzip, &r.EnableBrotli, &r.EnableCache, &r.CustomHeaders, &r.BlockCountries, &r.AllowCountries,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) CreateRoute(r *Route) error {
	result, err := s.db.Exec(
		"INSERT INTO routes (domain, backend, enabled, waf_enabled, oidc_enabled) VALUES (?, ?, ?, ?, ?)",
		r.Domain, r.Backend, r.Enabled, r.WAFEnabled, r.OIDCEnabled,
	)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	r.ID = int(id)
	return nil
}

func (s *Store) DeleteRoute(id int) error {
	_, err := s.db.Exec("DELETE FROM routes WHERE id = ?", id)
	return err
}

func (s *Store) UpdateRoute(r *Route) error {
	_, err := s.db.Exec(
		"UPDATE routes SET domain = ?, backend = ?, enabled = ?, waf_enabled = ?, oidc_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		r.Domain, r.Backend, r.Enabled, r.WAFEnabled, r.OIDCEnabled, r.ID,
	)
	return err
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
	err := row.Scan(&p.ID, &p.Name, &p.ClientID, &p.ClientSecret, &p.DiscoveryURL, &p.RedirectURL)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) CreateOIDCProvider(p *OIDCProvider) error {
	result, err := s.db.Exec(
		"INSERT INTO oidc_providers (name, client_id, client_secret, discovery_url, redirect_url) VALUES (?, ?, ?, ?, ?)",
		p.Name, p.ClientID, p.ClientSecret, p.DiscoveryURL, p.RedirectURL,
	)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
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
		"INSERT OR REPLACE INTO sessions (id, user_email, user_name, user_id, provider_name, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		sess.ID, sess.UserEmail, sess.UserName, sess.UserID, sess.ProviderName, sess.CreatedAt, sess.ExpiresAt,
	)
	return err
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	return err
}

func (s *Store) CleanupSessions() error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE expires_at < datetime('now')")
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
	id, _ := result.LastInsertId()
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
	id, _ := result.LastInsertId()
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
	id, _ := result.LastInsertId()
	r.ID = int(id)
	return nil
}

func (s *Store) DeleteRateLimit(id int) error {
	_, err := s.db.Exec("DELETE FROM rate_limits WHERE id = ?", id)
	return err
}

// User methods

func (s *Store) GetUsers() ([]User, error) {
	rows, err := s.db.Query("SELECT id, email, name, role, enabled FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.Enabled); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	row := s.db.QueryRow("SELECT id, email, name, role, password, enabled FROM users WHERE email = ?", email)
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &u.Password, &u.Enabled)
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
	id, _ := result.LastInsertId()
	u.ID = int(id)
	return nil
}

func (s *Store) DeleteUser(id int) error {
	_, err := s.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// Certificate methods

func (s *Store) GetCertificates() ([]Certificate, error) {
	rows, err := s.db.Query("SELECT id, domain, cert_path, key_path, auto_renew, expires_at FROM certificates")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.Domain, &c.CertPath, &c.KeyPath, &c.AutoRenew, &c.ExpiresAt); err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func (s *Store) CreateCertificate(c *Certificate) error {
	result, err := s.db.Exec(
		"INSERT INTO certificates (domain, cert_path, key_path, auto_renew, expires_at) VALUES (?, ?, ?, ?, ?)",
		c.Domain, c.CertPath, c.KeyPath, c.AutoRenew, c.ExpiresAt,
	)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	c.ID = int(id)
	return nil
}

func (s *Store) DeleteCertificate(id int) error {
	_, err := s.db.Exec("DELETE FROM certificates WHERE id = ?", id)
	return err
}

// WAF Rule methods

func (s *Store) GetWAFRules() ([]WAFRule, error) {
	rows, err := s.db.Query("SELECT id, name, rule, enabled FROM waf_rules")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WAFRule
	for rows.Next() {
		var r WAFRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Rule, &r.Enabled); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (s *Store) CreateWAFRule(r *WAFRule) error {
	result, err := s.db.Exec(
		"INSERT INTO waf_rules (name, rule, enabled) VALUES (?, ?, ?)",
		r.Name, r.Rule, r.Enabled,
	)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	r.ID = int(id)
	return nil
}

func (s *Store) DeleteWAFRule(id int) error {
	_, err := s.db.Exec("DELETE FROM waf_rules WHERE id = ?", id)
	return err
}

// Backend methods (for load balancing)

func (s *Store) GetBackends(routeID int) ([]Backend, error) {
	rows, err := s.db.Query("SELECT id, route_id, url, weight, healthy, last_check, last_error FROM backends WHERE route_id = ?", routeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var backends []Backend
	for rows.Next() {
		var b Backend
		var lastCheck sql.NullTime
		var lastError sql.NullString
		if err := rows.Scan(&b.ID, &b.RouteID, &b.URL, &b.Weight, &b.Healthy, &lastCheck, &lastError); err != nil {
			return nil, err
		}
		if lastCheck.Valid {
			b.LastCheck = lastCheck.Time
		}
		if lastError.Valid {
			b.LastError = lastError.String
		}
		backends = append(backends, b)
	}
	return backends, nil
}

func (s *Store) CreateBackend(b *Backend) error {
	result, err := s.db.Exec(
		"INSERT INTO backends (route_id, url, weight, healthy) VALUES (?, ?, ?, ?)",
		b.RouteID, b.URL, b.Weight, b.Healthy,
	)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	b.ID = int(id)
	return nil
}

func (s *Store) DeleteBackend(id int) error {
	_, err := s.db.Exec("DELETE FROM backends WHERE id = ?", id)
	return err
}

func (s *Store) UpdateBackendHealth(id int, healthy bool, lastError string) error {
	_, err := s.db.Exec(
		"UPDATE backends SET healthy = ?, last_check = CURRENT_TIMESTAMP, last_error = ? WHERE id = ?",
		healthy, lastError, id,
	)
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
	id, _ := result.LastInsertId()
	key.ID = int(id)
	return nil
}

func (s *Store) DeleteAPIKey(keyID string) error {
	_, err := s.db.Exec("DELETE FROM api_keys WHERE key_id = ?", keyID)
	return err
}

func (s *Store) UpdateAPIKeyLastUsed(keyID string) error {
	_, err := s.db.Exec("UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE key_id = ?", keyID)
	return err
}
