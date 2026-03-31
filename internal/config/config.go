package config

import (
	"os"
)

type Config struct {
	ListenAddr   string `json:"listen_addr"`
	AdminAddr    string `json:"admin_addr"`
	DatabasePath string `json:"database_path"`
	ProxyAddr    string `json:"proxy_addr"` // Port for proxy (default :8080)
}

func Load() (*Config, error) {
	return &Config{
		ListenAddr:   getEnv("KROXY_LISTEN", ":443"),
		AdminAddr:    getEnv("KROXY_ADMIN", ":8080"),
		DatabasePath: getEnv("KROXY_DB", "./kroxy.db"),
		ProxyAddr:    getEnv("KROXY_PROXY", ":8080"), // Default to non-privileged for dev
	}, nil
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}