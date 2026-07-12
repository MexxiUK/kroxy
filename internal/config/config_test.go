package config

import (
	"os"
	"testing"
)

var configEnvKeys = []string{
	"KROXY_PRODUCTION",
	"KROXY_TLS_ENABLED",
	"KROXY_AUTO_HTTPS",
	"KROXY_PROXY",
	"KROXY_DB",
	"KROXY_ADMIN",
	"KROXY_ALLOW_PRIVATE_BACKENDS",
	"KROXY_TLS_CERT",
	"KROXY_TLS_KEY",
}

// saveConfigEnv captures the current values of all config-related environment
// variables and returns a function that restores them. Use with defer in tests
// that mutate environment.
func saveConfigEnv() func() {
	saved := make(map[string]string, len(configEnvKeys))
	for _, k := range configEnvKeys {
		if v, ok := os.LookupEnv(k); ok {
			saved[k] = v
		}
	}
	return func() {
		for _, k := range configEnvKeys {
			if v, ok := saved[k]; ok {
				os.Setenv(k, v)
			} else {
				os.Unsetenv(k)
			}
		}
	}
}

func TestLoad_ProductionRequiresTLSOnPublicProxy(t *testing.T) {
	defer saveConfigEnv()()

	// Set a valid production DB path so that the database-path check passes.
	os.Setenv("KROXY_DB", "/data/kroxy.db")
	os.Setenv("KROXY_ADMIN", "127.0.0.1:8081")
	os.Unsetenv("KROXY_ALLOW_PRIVATE_BACKENDS")
	// Provide a dummy cert/key pair so the existing TLS path validation passes.
	os.Setenv("KROXY_TLS_CERT", "/data/cert.pem")
	os.Setenv("KROXY_TLS_KEY", "/data/key.pem")

	cases := []struct {
		name      string
		proxy     string
		tls       string
		autoHTTPS string
		wantErr   bool
	}{
		{
			name:      "public proxy without TLS fails",
			proxy:     ":80",
			tls:       "false",
			autoHTTPS: "false",
			wantErr:   true,
		},
		{
			name:      "public proxy with manual TLS succeeds",
			proxy:     ":443",
			tls:       "true",
			autoHTTPS: "false",
			wantErr:   false,
		},
		{
			name:      "public proxy with auto HTTPS succeeds",
			proxy:     ":443",
			tls:       "false",
			autoHTTPS: "true",
			wantErr:   false,
		},
		{
			name:      "localhost proxy without TLS succeeds",
			proxy:     "127.0.0.1:8080",
			tls:       "false",
			autoHTTPS: "false",
			wantErr:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv("KROXY_PRODUCTION", "true")
			os.Setenv("KROXY_PROXY", tc.proxy)
			os.Setenv("KROXY_TLS_ENABLED", tc.tls)
			os.Setenv("KROXY_AUTO_HTTPS", tc.autoHTTPS)

			_, err := Load()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestLoad_NonProductionAllowsHTTPPublicProxy(t *testing.T) {
	defer saveConfigEnv()()

	os.Setenv("KROXY_PRODUCTION", "false")
	os.Setenv("KROXY_TLS_ENABLED", "false")
	os.Setenv("KROXY_AUTO_HTTPS", "false")
	os.Setenv("KROXY_PROXY", ":80")
	os.Setenv("KROXY_DB", "./kroxy.db")
	os.Setenv("KROXY_ADMIN", "127.0.0.1:8081")
	os.Unsetenv("KROXY_ALLOW_PRIVATE_BACKENDS")
	os.Unsetenv("KROXY_TLS_CERT")
	os.Unsetenv("KROXY_TLS_KEY")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected no error in non-production mode, got %v", err)
	}
	if cfg.ProxyAddr != ":80" {
		t.Errorf("expected proxy addr :80, got %s", cfg.ProxyAddr)
	}
	if cfg.TLSEnabled {
		t.Error("expected TLS to be disabled")
	}
}
