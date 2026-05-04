-- Initial schema migration for Kroxy
-- This creates all base tables for the application

-- Schema version tracking table (created first)
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    name TEXT NOT NULL
);

-- Routes: Proxy routing configuration
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

-- OIDC providers: OAuth/OIDC authentication provider configuration
CREATE TABLE IF NOT EXISTS oidc_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    discovery_url TEXT NOT NULL,
    redirect_url TEXT NOT NULL
);

-- Certificates: SSL/TLS certificate metadata
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    cert_path TEXT,
    key_path TEXT,
    auto_renew BOOLEAN DEFAULT true,
    expires_at TIMESTAMP
);

-- WAF rules: Web Application Firewall rules
CREATE TABLE IF NOT EXISTS waf_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    rule TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true
);

-- Sessions: User session storage
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_email TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_id TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Blacklists: Access control deny lists
CREATE TABLE IF NOT EXISTS blacklists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Whitelists: Access control allow lists
CREATE TABLE IF NOT EXISTS whitelists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Rate limits: Per-domain rate limiting configuration
CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    requests_per_minute INTEGER NOT NULL,
    burst INTEGER DEFAULT 10,
    enabled BOOLEAN DEFAULT true
);

-- Users: Local user accounts
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'viewer',
    password TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true
);

-- Backends: Load-balanced backend servers
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

-- API keys: API key credentials for programmatic access
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

-- Password reset tokens: Password reset token tracking
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Admin tokens: One-time admin action tokens
CREATE TABLE IF NOT EXISTS admin_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    created_by INTEGER,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Failed attempts: Login attempt tracking for account lockout
CREATE TABLE IF NOT EXISTS failed_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL,
    attempt_count INTEGER DEFAULT 1,
    first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locked_until TIMESTAMP,
    UNIQUE(identifier)
);

-- Redirect domains: Allowed redirect domains for security
CREATE TABLE IF NOT EXISTS redirect_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- IP bans: Banned IP addresses with expiration
CREATE TABLE IF NOT EXISTS ip_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    error_count INTEGER DEFAULT 0,
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_routes_domain ON routes(domain);
CREATE INDEX IF NOT EXISTS idx_routes_enabled ON routes(enabled);
CREATE INDEX IF NOT EXISTS idx_sessions_id ON sessions(id);
CREATE INDEX IF NOT EXISTS idx_blacklists_type ON blacklists(type);
CREATE INDEX IF NOT EXISTS idx_whitelists_type ON whitelists(type);
CREATE INDEX IF NOT EXISTS idx_api_keys_id ON api_keys(key_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_hash ON password_reset_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_tokens_hash ON admin_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_failed_attempts_identifier ON failed_attempts(identifier);
CREATE INDEX IF NOT EXISTS idx_redirect_domains_domain ON redirect_domains(domain);
CREATE INDEX IF NOT EXISTS idx_ip_bans_ip ON ip_bans(ip);
CREATE INDEX IF NOT EXISTS idx_ip_bans_expires ON ip_bans(expires_at);