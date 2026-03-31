package validation

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	ErrInvalidURL      = errors.New("invalid URL format")
	ErrInvalidScheme    = errors.New("only http and https schemes are allowed")
	ErrInternalIP       = errors.New("internal IP addresses are not allowed")
	ErrBlockedDomain    = errors.New("domain is blocked")
	ErrInvalidDomain    = errors.New("invalid domain format")
	ErrInvalidPort      = errors.New("invalid port")
	ErrDangerousPattern = errors.New("URL contains dangerous pattern")
)

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
	"::1/128",          // IPv6 loopback
	"fc00::/7",         // IPv6 ULA
	"fe80::/10",        // IPv6 link-local
}

// Blocked domains
var blockedDomains = []string{
	"localhost",
	"local",
	"localdomain",
	"*.local",
	"*.internal",
	"*.localdomain",
}

// Dangerous URL patterns
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.\./`),
	regexp.MustCompile(`(?i)%2e%2e`),
	regexp.MustCompile(`(?i)%252e`),
	regexp.MustCompile(`(?i)file://`),
	regexp.MustCompile(`(?i)gopher://`),
	regexp.MustCompile(`(?i)data:`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)vbscript:`),
	regexp.MustCompile(`(?i)@`),
	regexp.MustCompile(`(?i):\d+@`), // Credentials in URL
}

// ValidateBackendURL validates that a backend URL is safe to use
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

	// Check blocked domains
	for _, blocked := range blockedDomains {
		if strings.HasSuffix(hostname, blocked) || hostname == blocked {
			return ErrBlockedDomain
		}
	}

	// Check for IP address
	ip := net.ParseIP(hostname)
	if ip != nil {
		if isPrivateIP(ip) {
			return ErrInternalIP
		}
		return nil
	}

	// Resolve hostname and check IP
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// DNS resolution failed - could be internal domain
		return ErrInvalidDomain
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return ErrInternalIP
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

// ValidateDomain validates a domain name
func ValidateDomain(domain string) error {
	if domain == "" {
		return ErrInvalidDomain
	}

	// Check length
	if len(domain) > 253 {
		return ErrInvalidDomain
	}

	// Check for valid characters
	matched, _ := regexp.MatchString(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`, domain)
	if !matched {
		return ErrInvalidDomain
	}

	// Check for blocked domains
	for _, blocked := range blockedDomains {
		if strings.HasSuffix(domain, "."+blocked) || domain == blocked {
			return ErrBlockedDomain
		}
	}

	return nil
}

// ValidateOIDCProvider validates OIDC provider configuration
func ValidateOIDCProvider(name, discoveryURL, redirectURL string) error {
	if name == "" {
		return errors.New("provider name is required")
	}

	// Validate discovery URL
	if discoveryURL != "" {
		if _, err := url.Parse(discoveryURL); err != nil {
			return errors.New("invalid discovery URL")
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

	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, email)
	if !matched {
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

func isPrivateIP(ip net.IP) bool {
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