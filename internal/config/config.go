package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	AdminAddr            string `json:"admin_addr"`
	DatabasePath         string `json:"database_path"`
	ProxyAddr            string `json:"proxy_addr"` // HTTP listen address (:80 or :8080)
	HTTPSAddr            string `json:"https_addr"` // HTTPS listen address (:443)
	ProductionMode       bool   `json:"production_mode"`
	MaxRequestSize       int64  `json:"max_request_size"`       // Max request body size in bytes
	EnableMetrics        bool   `json:"enable_metrics"`         // Enable prometheus metrics
	AllowPrivateBackends bool   `json:"allow_private_backends"` // Allow private IP backends (dev only)
	TLSEnabled           bool   `json:"tls_enabled"`            // Enable HTTPS/TLS
	TLSCertPath          string `json:"tls_cert_path"`          // Path to TLS certificate PEM
	TLSKeyPath           string `json:"tls_key_path"`           // Path to TLS private key PEM
	TLSACMEEmail         string `json:"tls_acme_email"`         // Email for ACME/Let's Encrypt
	TLSAutoHTTPS         bool   `json:"tls_auto_https"`         // Enable automatic HTTPS via ACME
	TLSMinVersion        string `json:"tls_min_version"`        // Minimum TLS version (1.2 or 1.3)
	HSTSEnabled          bool   `json:"hsts_enabled"`           // Enable HSTS headers
	RedirectHTTP         bool   `json:"redirect_http"`          // Redirect HTTP to HTTPS
}

// Security defaults
const (
	DefaultMaxRequestSize = 10 * 1024 * 1024 // 10MB
)

func Load() (*Config, error) {
	productionMode := getEnvBool("KROXY_PRODUCTION", false)

	databasePath := getEnv("KROXY_DB", "./kroxy.db")

	// Fail-fast: In production mode, require explicit database path
	if productionMode {
		if databasePath == "./kroxy.db" {
			return nil, fmt.Errorf("KROXY_DB must be explicitly set in production mode (current default './kroxy.db' is not allowed)")
		}
		if !filepath.IsAbs(databasePath) {
			return nil, fmt.Errorf("KROXY_DB must be an absolute path in production mode (got: %s)", databasePath)
		}
	}

	allowPrivateBackends := getEnvBool("KROXY_ALLOW_PRIVATE_BACKENDS", false)
	if allowPrivateBackends && productionMode {
		return nil, fmt.Errorf("KROXY_ALLOW_PRIVATE_BACKENDS cannot be enabled in production mode")
	}

	tlsEnabled := getEnvBool("KROXY_TLS_ENABLED", false)
	tlsAutoHTTPS := getEnvBool("KROXY_AUTO_HTTPS", false)
	tlsACMEEmail := getEnv("KROXY_ACME_EMAIL", "")
	tlsCertPath := getEnv("KROXY_TLS_CERT", "")
	tlsKeyPath := getEnv("KROXY_TLS_KEY", "")

	// Validate TLS config
	if tlsEnabled {
		if tlsAutoHTTPS && tlsACMEEmail == "" {
			return nil, fmt.Errorf("KROXY_ACME_EMAIL is required when KROXY_AUTO_HTTPS is enabled")
		}
		if !tlsAutoHTTPS && (tlsCertPath == "" || tlsKeyPath == "") {
			return nil, fmt.Errorf("KROXY_TLS_CERT and KROXY_TLS_KEY are required when KROXY_AUTO_HTTPS is disabled")
		}
		if tlsCertPath != "" && !filepath.IsAbs(tlsCertPath) {
			return nil, fmt.Errorf("KROXY_TLS_CERT must be an absolute path")
		}
		if tlsKeyPath != "" && !filepath.IsAbs(tlsKeyPath) {
			return nil, fmt.Errorf("KROXY_TLS_KEY must be an absolute path")
		}
	}

	cfg := &Config{
		AdminAddr:            getEnv("KROXY_ADMIN", ":8081"),
		DatabasePath:         databasePath,
		ProxyAddr:            getEnv("KROXY_PROXY", ":80"),
		HTTPSAddr:            getEnv("KROXY_HTTPS_ADDR", ":443"),
		ProductionMode:       productionMode,
		MaxRequestSize:       getEnvInt64("KROXY_MAX_REQUEST_SIZE", DefaultMaxRequestSize),
		EnableMetrics:        getEnvBool("KROXY_ENABLE_METRICS", false),
		AllowPrivateBackends: allowPrivateBackends,
		TLSEnabled:           tlsEnabled,
		TLSCertPath:          tlsCertPath,
		TLSKeyPath:           tlsKeyPath,
		TLSACMEEmail:         tlsACMEEmail,
		TLSAutoHTTPS:         tlsAutoHTTPS,
		TLSMinVersion:        getEnv("KROXY_TLS_MIN_VERSION", "1.2"),
		HSTSEnabled:          getEnvBool("KROXY_HSTS_ENABLED", true),
		RedirectHTTP:         getEnvBool("KROXY_REDIRECT_HTTP", true),
	}

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return defaultVal
	}
	return b
}

func getEnvInt64(key string, defaultVal int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	i, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return defaultVal
	}
	return i
}
