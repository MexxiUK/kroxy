package security

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// GetClientIP extracts the client IP from a request, handling proxies
// Only trusts proxy headers from trusted proxy IPs to prevent IP spoofing
func GetClientIP(r *http.Request) string {
	// Get the direct client IP (from connection)
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	// Only trust proxy headers if the request comes from a trusted proxy
	if isTrustedProxy(remoteIP) {
		// Check X-Forwarded-For — iterate from rightmost (closest to server) to
		// find the first IP that is NOT a trusted proxy. Leftmost IPs are
		// attacker-controlled and must never be used directly.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			for i := len(ips) - 1; i >= 0; i-- {
				candidate := strings.TrimSpace(ips[i])
				if candidate == "" {
					continue
				}
				// If the candidate is a trusted proxy, keep walking left;
				// otherwise we found the client IP.
				if !isTrustedProxy(candidate) {
					return candidate
				}
			}
		}

		// Check X-Real-IP (nginx)
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}

		// Check CF-Connecting-IP (Cloudflare)
		if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
			return strings.TrimSpace(cf)
		}
	}

	// Fall back to RemoteAddr (direct connection or untrusted proxy)
	return remoteIP
}

// isTrustedProxy checks if the request comes from a trusted proxy
// By default, only localhost is trusted. Additional trusted proxies
// can be configured via KROXY_TRUSTED_PROXIES environment variable
// (comma-separated list of IP addresses or CIDR ranges)
func isTrustedProxy(ip string) bool {
	// Trust localhost
	if ip == "127.0.0.1" || ip == "::1" {
		return true
	}

	// Check configured trusted proxies
	trustedProxies := getTrustedProxies()
	for _, trusted := range trustedProxies {
		if trusted == ip {
			return true
		}
		// Check CIDR range
		if strings.Contains(trusted, "/") {
			_, network, err := net.ParseCIDR(trusted)
			if err == nil && network.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}

	return false
}

// cachedTrustedProxies caches the parsed trusted proxies list
var (
	trustedProxiesOnce sync.Once
	cachedTrustedProxies []string
)

// getTrustedProxies returns the list of trusted proxy IPs/CIDRs from environment
func getTrustedProxies() []string {
	trustedProxiesOnce.Do(func() {
		env := os.Getenv("KROXY_TRUSTED_PROXIES")
		if env == "" {
			cachedTrustedProxies = []string{}
			return
		}
		proxies := strings.Split(env, ",")
		for i, p := range proxies {
			proxies[i] = strings.TrimSpace(p)
		}
		cachedTrustedProxies = proxies
	})
	return cachedTrustedProxies
}