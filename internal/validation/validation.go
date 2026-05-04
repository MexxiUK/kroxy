package validation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidURL      = errors.New("invalid URL format")
	ErrInvalidScheme    = errors.New("only http and https schemes are allowed")
	ErrInternalIP       = errors.New("internal IP addresses are not allowed")
	ErrBlockedDomain    = errors.New("domain is blocked")
	ErrInvalidDomain    = errors.New("invalid domain format")
	ErrInvalidPort      = errors.New("invalid port")
	ErrDangerousPattern = errors.New("URL contains dangerous pattern")
	ErrDNSRebind       = errors.New("DNS rebinding attack detected")
	ErrSelfReference    = errors.New("backend would create a proxy loop")
)

var allowPrivateBackends bool

// SetAllowPrivateBackends controls whether private/internal IP backends are permitted.
func SetAllowPrivateBackends(allowed bool) {
	allowPrivateBackends = allowed
}

// Precompiled regexes to avoid ReDoS and repeated compilation overhead
var (
	domainRegex      = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	emailRegex       = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	wafRuleNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\- ]+$`)
	userIDRegex      = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

	// Precompiled WAF disable patterns (avoids recompilation per rule validation)
	wafDisablePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)secruleengine\s+off`),
		regexp.MustCompile(`(?i)secruleengine\s+detectiononly`),
		regexp.MustCompile(`(?i)secdefaultaction\s+[^"]*pass`),
		regexp.MustCompile(`(?i)secdefaultaction\s+[^"]*nolog`),
		regexp.MustCompile(`(?i)secdefaultaction\s+[^"]*noauditlog`),
		regexp.MustCompile(`(?i)secaction[^"]*(?:pass|nolog|noauditlog)`),
	}
)

// DNSCache provides DNS resolution caching with TTL to prevent DNS rebinding attacks
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsCacheEntry
	ttl     time.Duration
}

type dnsCacheEntry struct {
	ips        []net.IP
	resolvedAt time.Time
	hostname   string
}

var (
	dnsCache     *DNSCache
	dnsCacheOnce sync.Once
)

// GetDNSCache returns the singleton DNS cache instance
func GetDNSCache() *DNSCache {
	dnsCacheOnce.Do(func() {
		dnsCache = &DNSCache{
			entries: make(map[string]*dnsCacheEntry),
			ttl:     5 * time.Second, // 5 second TTL to minimize DNS rebinding window
		}
	})
	return dnsCache
}

// Resolve resolves a hostname and caches the result
func (dc *DNSCache) Resolve(hostname string) ([]net.IP, error) {
	dc.mu.RLock()
	if entry, ok := dc.entries[hostname]; ok {
		if time.Since(entry.resolvedAt) < dc.ttl {
			ips := make([]net.IP, len(entry.ips))
			copy(ips, entry.ips)
			dc.mu.RUnlock()
			return ips, nil
		}
	}
	dc.mu.RUnlock()

	// Resolve DNS with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	// Cache the result
	dc.mu.Lock()
	defer dc.mu.Unlock()

	dc.entries[hostname] = &dnsCacheEntry{
		ips:        ips,
		resolvedAt: time.Now(),
		hostname:   hostname,
	}

	return ips, nil
}

// Blocked IP ranges (private/internal)
var privateIPRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",  // Link-local
	"127.0.0.0/8",      // Loopback
	"224.0.0.0/4",      // Multicast
	"240.0.0.0/4",      // Reserved
	"100.64.0.0/10",    // Carrier-grade NAT
	"192.0.0.0/24",     // IETF Protocol Assignments
	"192.0.2.0/24",     // TEST-NET-1
	"198.51.100.0/24",  // TEST-NET-2
	"203.0.113.0/24",   // TEST-NET-3
	"198.18.0.0/15",    // Network Interconnect Device Benchmark Testing
	"0.0.0.0/8",        // "This network" - can be used for SSRF
	"::1/128",          // IPv6 loopback
	"fc00::/7",         // IPv6 ULA
	"fe80::/10",        // IPv6 link-local
	"::/128",           // IPv6 unspecified address
}

// isIPv6Loopback checks if an IPv6 address is a loopback address
func isIPv6Loopback(ip net.IP) bool {
	if ip.To4() != nil {
		return false // Not IPv6
	}

	// Check for ::1 (loopback)
	if ip.Equal(net.ParseIP("::1")) {
		return true
	}

	// Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
	// IPv4-mapped IPv6 addresses have the form ::ffff:x.x.x.x
	if len(ip) == 16 && ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff {
		// This is an IPv4-mapped IPv6 address
		ip4 := net.IP(ip[12:16])
		return ip4.IsLoopback()
	}

	// Check for IPv4-compatible IPv6 addresses (::x.x.x.x)
	// Deprecated format but may still work on some systems
	if len(ip) == 16 && ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 {
		// This is an IPv4-compatible IPv6 address
		ip4 := net.IP(ip[12:16])
		return ip4.IsLoopback() || ip4.IsPrivate() || ip4.IsLinkLocalUnicast()
	}

	return false
}

// Dangerous URL patterns
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.\./`),
	regexp.MustCompile(`(?i)%2e%2e`),       // URL-encoded ..
	regexp.MustCompile(`(?i)%252e`),         // Double-encoded .
	regexp.MustCompile(`(?i)%c0%ae`),        // Overlong UTF-8 encoded .
	regexp.MustCompile(`(?i)%e0%80%ae`),     // 3-byte overlong UTF-8 .
	regexp.MustCompile(`(?i)%%32%65`),       // Mixed encoding .
	regexp.MustCompile(`(?i)\.%00`),         // Null byte after dot
	regexp.MustCompile(`(?i)file://`),
	regexp.MustCompile(`(?i)gopher://`),
	regexp.MustCompile(`(?i)data:`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)vbscript:`),
	regexp.MustCompile(`(?i)@`),
	regexp.MustCompile(`(?i):\d+@`),         // Credentials in URL
	regexp.MustCompile(`(?i)\\\.\\\.`),      // Backslash traversal
}

// ValidateBackendURL validates that a backend URL is safe to use.
// Blocks dangerous patterns, prevents proxy loops, and validates DNS resolution.
func ValidateBackendURL(backend string) error {
	if backend == "" {
		return ErrInvalidURL
	}

	// Parse URL
	u, err := url.Parse(backend)
	if err != nil {
		return ErrInvalidURL
	}

	// Only allow http/https
	if u.Scheme != "http" && u.Scheme != "https" {
		return ErrInvalidScheme
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(backend) {
			return ErrDangerousPattern
		}
	}

	// Get hostname
	hostname := u.Hostname()
	if hostname == "" {
		return ErrInvalidDomain
	}

	// Check for IP address
	ip := net.ParseIP(hostname)
	if ip != nil {
		if !allowPrivateBackends && IsPrivateIP(ip) {
			return ErrInternalIP
		}
		return nil
	}

	// Check for encoded IP representations (hex, octal, decimal)
	// that bypass standard IP checks: 0x7f000001, 0177.0.0.1, 2130706433
	encodedIP := decodeEncodedIP(hostname)
	if encodedIP != nil {
		if !allowPrivateBackends && IsPrivateIP(encodedIP) {
			return ErrInternalIP
		}
		return nil
	}

	// Use DNS cache for hostname resolution (DNS rebinding protection)
	cache := GetDNSCache()
	ips, err := cache.Resolve(hostname)
	if err != nil {
		// DNS resolution failed - could be internal domain
		return ErrInvalidDomain
	}

	// Reject private IPs resolved from DNS unless explicitly allowed
	if !allowPrivateBackends {
		for _, resolvedIP := range ips {
			if IsPrivateIP(resolvedIP) {
				return ErrInternalIP
			}
		}
	}

	// Validate port if specified
	if u.Port() != "" {
		port := u.Port()
		if !isValidPort(port) {
			return ErrInvalidPort
		}
	}

	return nil
}

// RevalidateBackendDNS re-resolves a backend URL's hostname and validates the IPs
// are still safe. This should be called at proxy time to detect DNS rebinding attacks
// where an attacker changes DNS records after initial route validation.
func RevalidateBackendDNS(backend string) error {
	u, err := url.Parse(backend)
	if err != nil {
		return ErrInvalidURL
	}

	hostname := u.Hostname()
	if hostname == "" {
		return ErrInvalidDomain
	}

	// Direct IP addresses don't need revalidation
	if ip := net.ParseIP(hostname); ip != nil {
		return nil
	}

	// Force a fresh DNS resolution (bypass cache)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		return fmt.Errorf("DNS resolution failed: %w", err)
	}

	// DNS rebinding protection: compare fresh IPs with cached IPs.
	// If the hostname previously resolved to different IPs, an attacker may have
	// changed DNS records after initial validation.
	cache := GetDNSCache()
	cache.mu.RLock()
	cached, ok := cache.entries[hostname]
	cache.mu.RUnlock()

	if ok {
		if !ipsEqual(cached.ips, ips) {
			return ErrDNSRebind
		}
	}

	// Update the DNS cache with fresh results
	cache.mu.Lock()
	cache.entries[hostname] = &dnsCacheEntry{
		ips:        ips,
		resolvedAt: time.Now(),
		hostname:   hostname,
	}
	cache.mu.Unlock()

	return nil
}

// ipsEqual checks whether two slices of net.IP contain the same addresses.
func ipsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, ip := range a {
		m[ip.String()]++
	}
	for _, ip := range b {
		if m[ip.String()] == 0 {
			return false
		}
		m[ip.String()]--
	}
	return true
}

// ValidateDomain validates a domain name
func ValidateDomain(domain string) error {
	if domain == "" {
		return ErrInvalidDomain
	}

	// Check length
	if len(domain) > 253 {
		return ErrInvalidDomain
	}

	// Check for valid characters (precompiled regex)
	if !domainRegex.MatchString(domain) {
		return ErrInvalidDomain
	}

	return nil
}

// ValidateOIDCProvider validates OIDC provider configuration
func ValidateOIDCProvider(name, discoveryURL, redirectURL string) error {
	if name == "" {
		return errors.New("provider name is required")
	}

	// Validate name format (alphanumeric, dash, underscore)
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(name) {
		return errors.New("provider name can only contain alphanumeric characters, dash, and underscore")
	}

	// Validate discovery URL with SSRF protection
	if discoveryURL != "" {
		u, err := url.Parse(discoveryURL)
		if err != nil {
			return errors.New("invalid discovery URL")
		}
		// Must use HTTPS for security
		if u.Scheme != "https" {
			return errors.New("discovery URL must use https")
		}
		// Apply full SSRF validation
		if err := ValidateBackendURL(discoveryURL); err != nil {
			return fmt.Errorf("discovery URL failed security validation: %w", err)
		}
	}

	// Validate redirect URL
	if redirectURL != "" {
		u, err := url.Parse(redirectURL)
		if err != nil {
			return errors.New("invalid redirect URL")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("redirect URL must use http or https")
		}
	}

	return nil
}

// ValidateEmail validates email format
func ValidateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}

	if !emailRegex.MatchString(email) {
		return errors.New("invalid email format")
	}

	return nil
}

// ValidatePassword validates password strength
func ValidatePassword(password string) error {
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.New("password must contain uppercase, lowercase, digit, and special character")
	}

	return nil
}

// Helper functions

// adminListenAddr is the address the Kroxy admin API listens on.
// Set via SetAdminAddr at startup. Used to prevent proxy-loop routes.
var adminListenAddr string

// SetAdminAddr sets the admin API listen address for self-reference checks.
func SetAdminAddr(addr string) {
	adminListenAddr = addr
}

// ValidateNoSelfReference checks that a backend URL does not point to
// the Kroxy admin API itself, which would create a proxy loop.
// Admin routes (isAdminRoute=true) are exempt since they intentionally proxy to self.
func ValidateNoSelfReference(backend string, isAdminRoute bool) error {
	if isAdminRoute {
		return nil
	}
	if adminListenAddr == "" {
		return nil
	}
	u, err := url.Parse(backend)
	if err != nil {
		return nil
	}
	// Parse admin addr (e.g. ":8080" or "0.0.0.0:8080")
	host := u.Hostname()
	port := u.Port()
	_, adminPort, _ := net.SplitHostPort(adminListenAddr)
	if adminPort == "" {
		adminPort = "8080"
	}
	// Check if backend port matches admin port AND host is local
	if port == adminPort {
		if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
			return ErrSelfReference
		}
		// Also check if the hostname resolves to a loopback address
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return ErrSelfReference
		}
		if encodedIP := decodeEncodedIP(host); encodedIP != nil && encodedIP.IsLoopback() {
			return ErrSelfReference
		}
	}
	return nil
}

// decodeEncodedIP attempts to decode hostname as hex, octal, decimal, or
// other non-standard IP representations. Returns the parsed IP if the
// hostname is an encoded IP address, or nil otherwise.
// Covers: hex (0x7f000001), octal (0177.0.0.1), decimal (2130706433),
// IPv4 with hex/octal octets, and dotted-decimal with mixed encodings.
var encodedIPPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^0x[0-9a-fA-F]{6,8}$`),     // 0x7f000001
	regexp.MustCompile(`^[0-9]{8,10}$`),              // 2130706433
	regexp.MustCompile(`^0[0-7]+\.[0-7]+\.[0-7]+\.`), // 0177.0.0.1
	regexp.MustCompile(`^0x[0-9a-fA-F]+\.`),           // 0x7f.0.0.1
	regexp.MustCompile(`^0[0-7]+$`),                   // octal without dots
}

func decodeEncodedIP(hostname string) net.IP {
	// Hex integer form: 0x7f000001
	if strings.HasPrefix(hostname, "0x") || strings.HasPrefix(hostname, "0X") {
		val, err := strconv.ParseUint(hostname[2:], 16, 32)
		if err == nil {
			return net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
		}
	}

	// Pure decimal integer form: 2130706433
	if matched, _ := regexp.MatchString(`^[0-9]+$`, hostname); matched {
		val, err := strconv.ParseUint(hostname, 10, 32)
		if err == nil && val > 0xFFFFFF {
			return net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
		}
	}

	// Dotted form with hex/octal octets: 0x7f.0.0.1 or 0177.0.0.1
	parts := strings.Split(hostname, ".")
	if len(parts) == 4 {
		var octets [4]uint64
		valid := true
		for i, part := range parts {
			var val uint64
			var err error
			if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") {
				val, err = strconv.ParseUint(part[2:], 16, 32)
			} else if len(part) > 1 && part[0] == '0' && !strings.Contains(part, "8") && !strings.Contains(part, "9") {
				val, err = strconv.ParseUint(part[1:], 8, 32)
			} else {
				val, err = strconv.ParseUint(part, 10, 32)
			}
			if err != nil || val > 255 {
				valid = false
				break
			}
			octets[i] = val
		}
		if valid {
			return net.IPv4(byte(octets[0]), byte(octets[1]), byte(octets[2]), byte(octets[3]))
		}
	}

	// Pure octal form: 017700000001
	if len(hostname) > 2 && hostname[0] == '0' && hostname[1] != '.' {
		val, err := strconv.ParseUint(hostname, 8, 32)
		if err == nil {
			return net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
		}
	}

	return nil
}


func IsPrivateIP(ip net.IP) bool {
	// Check for IPv4-mapped IPv6 addresses
	if ip.To4() != nil {
		// This is a pure IPv4 address
		ip = ip.To4()
	} else if len(ip) == 16 && ip[10] == 0xff && ip[11] == 0xff {
		// IPv4-mapped IPv6 address - check the embedded IPv4
		ip4 := net.IP(ip[12:16])
		ip = ip4
	}

	// Check for loopback in all forms
	if ip.IsLoopback() {
		return true
	}

	// Check IPv6 loopback variants
	if ip.To4() == nil && isIPv6Loopback(ip) {
		return true
	}

	// Check CIDR ranges
	for _, cidr := range privateIPRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isValidPort(port string) bool {
	portNum := 0
	_, err := fmt.Sscanf(port, "%d", &portNum)
	if err != nil {
		return false
	}
	return portNum >= 1 && portNum <= 65535
}

// ValidateBlacklistType validates blacklist/whitelist type
func ValidateBlacklistType(t string) error {
	validTypes := map[string]bool{
		"ip":         true,
		"domain":     true,
		"user_agent": true,
		"country":    true,
		"path":       true,
	}
	if !validTypes[t] {
		return errors.New("invalid type: must be ip, domain, user_agent, country, or path")
	}
	return nil
}

// ValidateBlacklistValue validates blacklist/whitelist value
func ValidateBlacklistValue(valueType, value string) error {
	if value == "" {
		return errors.New("value is required")
	}
	if len(value) > 500 {
		return errors.New("value too long (max 500 characters)")
	}

	switch valueType {
	case "ip":
		// Validate IP address or CIDR
		if strings.Contains(value, "/") {
			_, _, err := net.ParseCIDR(value)
			if err != nil {
				return errors.New("invalid CIDR notation")
			}
		} else {
			if net.ParseIP(value) == nil {
				return errors.New("invalid IP address")
			}
		}
	case "domain":
		if err := ValidateDomain(value); err != nil {
			return errors.New("invalid domain")
		}
	case "country":
		// Country codes should be 2 letters
		if len(value) != 2 {
			return errors.New("country must be 2-letter ISO code")
		}
	case "user_agent":
		// User agent can be any string, but limit length
		if len(value) > 1000 {
			return errors.New("user agent pattern too long")
		}
	case "path":
		// Path should start with /
		if !strings.HasPrefix(value, "/") {
			return errors.New("path must start with /")
		}
		if len(value) > 500 {
			return errors.New("path too long")
		}
		// Reject path traversal sequences
		if strings.Contains(value, "..") {
			return errors.New("path contains traversal sequence")
		}
	}

	return nil
}

// ValidateRateLimit validates rate limit configuration
func ValidateRateLimit(domain string, requestsPerMinute, burst int) error {
	if domain != "" {
		if err := ValidateDomain(domain); err != nil {
			return fmt.Errorf("invalid domain: %w", err)
		}
	}
	if requestsPerMinute < 1 || requestsPerMinute > 100000 {
		return errors.New("requests per minute must be between 1 and 100000")
	}
	if burst < 0 || burst > requestsPerMinute {
		return errors.New("burst must be between 0 and requests per minute")
	}
	return nil
}

// ValidateCertificatePath validates certificate and key file paths
func ValidateCertificatePath(certPath, keyPath string) error {
	// Check and clean each path
	for _, path := range []string{certPath, keyPath} {
		if path == "" {
			continue
		}

		// Check length first to prevent DoS via very long paths
		if len(path) > 4096 {
			return errors.New("path too long")
		}

		// Check for null bytes in raw input
		if strings.Contains(path, "\x00") {
			return errors.New("null bytes not allowed in path")
		}

		// Multi-layer URL decoding to catch double/triple encoding
		// e.g., %252e%252e -> %2e%2e -> ..
		decoded := path
		for i := 0; i < 3; i++ {
			prev := decoded
			next, err := url.QueryUnescape(decoded)
			if err != nil {
				return errors.New("invalid path encoding")
			}
			decoded = next
			if decoded == prev {
				break // No more encoding layers
			}
		}

		// Check for path traversal in all decoded forms
		if containsTraversal(path) || containsTraversal(decoded) {
			return errors.New("path traversal not allowed")
		}

		// Check for null bytes after decoding
		if strings.Contains(decoded, "\x00") {
			return errors.New("null bytes not allowed in path")
		}

		// Clean the path and verify it doesn't escape
		cleanPath := filepath.Clean(decoded)
		if containsTraversal(cleanPath) {
			return errors.New("path traversal not allowed")
		}
	}

	// Check for absolute paths or relative paths starting with ./
	if certPath != "" && !strings.HasPrefix(certPath, "/") && !strings.HasPrefix(certPath, "./") {
		return errors.New("certificate path must be absolute or relative to working directory")
	}
	if keyPath != "" && !strings.HasPrefix(keyPath, "/") && !strings.HasPrefix(keyPath, "./") {
		return errors.New("key path must be absolute or relative to working directory")
	}

	return nil
}

// containsTraversal checks for path traversal sequences including Unicode variants
func containsTraversal(path string) bool {
	if strings.Contains(path, "..") {
		return true
	}
	// Check for backslash traversal (Windows-style)
	if strings.Contains(path, `..\\`) || strings.Contains(path, `\\..`) {
		return true
	}
	// Check for Unicode fullwidth period (U+FF0E) which can bypass .. checks
	if strings.Contains(path, "\uff0e\uff0e") {
		return true
	}
	return false
}

// ValidateWAFRuleName validates a WAF rule name
func ValidateWAFRuleName(name string) error {
	if name == "" {
		return errors.New("rule name is required")
	}
	if len(name) > 255 {
		return errors.New("rule name too long (max 255 characters)")
	}
	// Allow alphanumeric, underscore, hyphen, and space (precompiled regex)
	if !wafRuleNameRegex.MatchString(name) {
		return errors.New("rule name can only contain alphanumeric characters, underscores, hyphens, and spaces")
	}
	return nil
}

// ValidateWAFRule validates a WAF rule string for safety
func ValidateWAFRule(rule string) error {
	if rule == "" {
		return errors.New("rule cannot be empty")
	}

	// Check for Unicode line separators and null bytes that could bypass validation
	// These can be used to split rules or inject content
	if strings.ContainsRune(rule, '\u0000') {
		return errors.New("rule contains null byte (forbidden character)")
	}
	if strings.ContainsRune(rule, '\u2028') {
		return errors.New("rule contains Unicode line separator (forbidden character)")
	}
	if strings.ContainsRune(rule, '\u2029') {
		return errors.New("rule contains Unicode paragraph separator (forbidden character)")
	}

	// Check length
	if len(rule) > 10000 {
		return errors.New("rule too long (max 10000 characters)")
	}

	// Normalize rule for case-insensitive matching
	normalizedRule := strings.ToLower(rule)

	// Dangerous directives that could disable or bypass security
	// These are rule-modifying/engine-configuring directives that should never be in custom rules
	// Note: "secrule" is NOT blocked because legitimate rules start with SecRule
	dangerousDirectives := []string{
		"secruleengine",          // Controls WAF engine state
		"secruleremovebyid",      // Removes rules by ID
		"secruleremovebymsg",     // Removes rules by message
		"secruleremovebytag",     // Removes rules by tag
		"secdefaultaction",       // Sets default actions (can bypass)
		"secruleupdatetargetbyid", // Modifies rule targets
		"secruleupdateactionbyid", // Modifies rule actions
		"secruleupdatebyid",      // Modifies rules by ID
	}

	for _, directive := range dangerousDirectives {
		if strings.Contains(normalizedRule, directive) {
			return fmt.Errorf("rule contains forbidden directive: %s", directive)
		}
	}

	// Block any attempt to disable or bypass rules using precompiled regex patterns
	for _, dp := range wafDisablePatterns {
		if dp.MatchString(rule) {
			return fmt.Errorf("rule contains forbidden pattern")
		}
	}

	// Validate SecRule syntax if the rule starts with SecRule
	if strings.HasPrefix(rule, "SecRule") {
		// Basic validation: ensure it has required components
		parts := strings.Fields(rule)
		if len(parts) < 3 {
			return errors.New("invalid SecRule syntax: must have at least 3 parts")
		}

		// Check for valid operators
		validOperators := []string{
			"@rx", "@streq", "@beginsWith", "@endsWith", "@contains",
			"@pm", "@pmFromFile", "@ipMatch", "@ipMatchFromFile",
			"@gt", "@lt", "@ge", "@le", "@eq",
			"@within", "@detectXSS", "@detectSQLi",
		}

		hasValidOperator := false
		for _, op := range validOperators {
			if strings.Contains(rule, op) {
				hasValidOperator = true
				break
			}
		}

		// If using direct comparison, that's also valid
		if !hasValidOperator && (strings.Contains(parts[1], "\"") || strings.HasPrefix(parts[1], "ARGS") || strings.HasPrefix(parts[1], "REQUEST") || strings.HasPrefix(parts[1], "RESPONSE") || strings.HasPrefix(parts[1], "FILES") || strings.HasPrefix(parts[1], "GEO")) {
			hasValidOperator = true
		}

		if !hasValidOperator && len(parts) >= 2 {
			// Check if second part looks like a variable
			validPrefixes := []string{"ARGS", "REQUEST", "REMOTE", "SESSION", "TX:", "USER", "RESPONSE", "FILES", "GEO", "SERVER"}
			isValidVar := false
			for _, prefix := range validPrefixes {
				if strings.HasPrefix(parts[1], prefix) {
					isValidVar = true
					break
				}
			}
			if !isValidVar {
				return errors.New("invalid SecRule syntax: unrecognized operator")
			}
		}

		// Validate that the rule has an action (third part should have parentheses or be an action)
		if len(parts) >= 3 {
			action := parts[2]
			// Common actions: id, msg,deny,block,pass,log,chain
			if !strings.Contains(action, "id:") &&
				!strings.Contains(action, "msg:") &&
				!strings.Contains(action, "deny") &&
				!strings.Contains(action, "block") &&
				!strings.Contains(action, "pass") &&
				!strings.Contains(action, "log") &&
				!strings.Contains(action, "chain") &&
				!strings.HasPrefix(action, "\"") {
				// Might still be valid, but log a warning
				// Allow continuation on next line or chained rules
			}
		}
	}

	return nil
}

// ValidateWhitelist validates a whitelist entry
func ValidateWhitelist(whitelistType, value string) error {
	// Validate type
	validTypes := map[string]bool{
		"ip":       true,
		"domain":   true,
		"email":    true,
		"user":     true,
		"useragent": true,
	}
	if !validTypes[whitelistType] {
		return errors.New("invalid whitelist type: must be one of ip, domain, email, user, useragent")
	}

	// Validate value based on type
	if value == "" {
		return errors.New("value is required")
	}

	switch whitelistType {
	case "ip":
		// Validate IP address or CIDR
		if strings.Contains(value, "/") {
			_, _, err := net.ParseCIDR(value)
			if err != nil {
				return errors.New("invalid CIDR notation")
			}
		} else {
			if net.ParseIP(value) == nil {
				return errors.New("invalid IP address")
			}
		}
		if len(value) > 45 {
			return errors.New("IP address too long")
		}
	case "domain":
		if err := ValidateDomain(value); err != nil {
			return fmt.Errorf("invalid domain: %w", err)
		}
	case "email":
		if err := ValidateEmail(value); err != nil {
			return fmt.Errorf("invalid email: %w", err)
		}
	case "user":
		if len(value) > 255 {
			return errors.New("user identifier too long (max 255 characters)")
		}
		// Allow alphanumeric, dash, underscore, dot (precompiled regex)
		if !userIDRegex.MatchString(value) {
			return errors.New("user identifier can only contain alphanumeric characters, dash, underscore, and dot")
		}
	case "useragent":
		if len(value) > 1000 {
			return errors.New("user agent pattern too long (max 1000 characters)")
		}
		// Sanitize: no control characters
		for _, r := range value {
			if r < 32 && r != '\t' {
				return errors.New("user agent pattern contains invalid control characters")
			}
		}
	}

	return nil
}
