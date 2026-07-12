package validation

import (
	"net"
	"testing"
	"time"
)

func TestValidateBackendURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://example.com", false},
		{"valid http", "http://example.com:8080", false},
		{"empty", "", true},
		{"no scheme", "example.com", true},
		{"ftp scheme", "ftp://example.com", true},
		{"localhost", "http://localhost:3000", true},
		{"127.0.0.1", "http://127.0.0.1:3000", true},
		{"0.0.0.0", "http://0.0.0.0:3000", true},
		{"169.254.169.254", "http://169.254.169.254/", true},
		{"IPv6 loopback", "http://[::1]:3000", true},
		{"hex encoded IP", "http://0x7f000001", true},
		{"decimal encoded IP", "http://2130706433", true},
		{"octal encoded IP", "http://0177.0.0.1", true},
		{"mixed encoded IP", "http://0x7f.0.0.1", true},
		{"path traversal", "http://example.com/../etc/passwd", true},
		{"file scheme", "file:///etc/passwd", true},
		{"gopher scheme", "gopher://example.com", true},
		{"data scheme", "data:text/plain,hello", true},
		{"javascript scheme", "javascript:alert(1)", true},
		{"at sign", "http://user@example.com", true},
		{"backslash traversal", "http://example.com/..\\../", true},
		{"double encoded dot", "http://example.com/%252e%252e/", true},
		{"overlong utf8 dot", "http://example.com/%c0%ae/", true},
		{"3-byte overlong utf8", "http://example.com/%e0%80%ae/", true},
		{"null byte after dot", "http://example.com/.%00", true},
		{"mixed encoding", "http://example.com/%%32%65", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBackendURL(tt.url)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateBackendURL(%q) expected error, got nil", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateBackendURL(%q) unexpected error: %v", tt.url, err)
			}
		})
	}
}

func TestValidateBackendURL_DNSRebinding(t *testing.T) {
	// Simulate DNS rebinding: force the cache to have a private IP for a public hostname.
	// In practice this is covered by RevalidateBackendDNS at proxy time.
	cache := GetDNSCache()
	cache.mu.Lock()
	cache.entries["evil-rebind.test"] = &dnsCacheEntry{
		ips:        []net.IP{net.ParseIP("127.0.0.1")},
		resolvedAt: time.Now(),
		hostname:   "evil-rebind.test",
	}
	cache.mu.Unlock()

	if err := ValidateBackendURL("http://evil-rebind.test"); err != ErrInternalIP {
		t.Fatalf("expected ErrInternalIP for DNS rebinding, got: %v", err)
	}

	// Clean up
	cache.mu.Lock()
	delete(cache.entries, "evil-rebind.test")
	cache.mu.Unlock()
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"valid", "example.com", false},
		{"valid subdomain", "sub.example.com", false},
		{"single char label", "a.example.com", false},
		{"empty", "", true},
		{"no dot", "example", true},
		{"starts with dash", "-example.com", true},
		{"ends with dash", "example-.com", true},
		{"too long", string(make([]byte, 254)) + ".com", true},
		{"punycode", "xn--nxasmq5a.com", false},
		{"IDN homograph", "xn--pple-43d.com", false}, // punycode is accepted
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateDomain(%q) expected error, got nil", tt.domain)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateDomain(%q) unexpected error: %v", tt.domain, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{"too short", "Short1!", true},
		{"no upper", "lowercase1!", true},
		{"no lower", "UPPERCASE1!", true},
		{"no digit", "NoDigits!!", true},
		{"no special", "NoSpecial1", true},
		{"valid", "ValidPass1!123", false},
		{"valid long", "VeryLongPassword123!@#", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.pw)
			if tt.wantErr && err == nil {
				t.Errorf("ValidatePassword(%q) expected error, got nil", tt.pw)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidatePassword(%q) unexpected error: %v", tt.pw, err)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid", "user@example.com", false},
		{"valid with dots", "first.last@sub.example.com", false},
		{"valid with plus", "user+tag@example.com", false},
		{"empty", "", true},
		{"no at", "userexample.com", true},
		{"no domain", "user@", true},
		{"no local", "@example.com", true},
		{"spaces", "user name@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateEmail(%q) expected error, got nil", tt.email)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateEmail(%q) unexpected error: %v", tt.email, err)
			}
		})
	}
}

func TestValidateBlacklistValue(t *testing.T) {
	tests := []struct {
		name    string
		vtype   string
		value   string
		wantErr bool
	}{
		{"path valid", "path", "/api/admin", false},
		{"path traversal", "path", "/../etc/passwd", true},
		{"path no leading slash", "path", "api/admin", true},
		{"ip valid", "ip", "192.0.2.1", false},
		{"cidr valid", "ip", "192.0.2.0/24", false},
		{"ip invalid", "ip", "999.999.999.999", true},
		{"cidr invalid", "ip", "192.0.2.0/33", true},
		{"domain valid", "domain", "evil.com", false},
		{"country valid", "country", "US", false},
		{"country too long", "country", "USA", true},
		{"user agent valid", "user_agent", "BadBot/1.0", false},
		{"empty", "ip", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBlacklistValue(tt.vtype, tt.value)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateBlacklistValue(%q, %q) expected error, got nil", tt.vtype, tt.value)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateBlacklistValue(%q, %q) unexpected error: %v", tt.vtype, tt.value, err)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"public", "1.1.1.1", false},
		{"private 10.x", "10.0.0.1", true},
		{"private 172.16", "172.16.0.1", true},
		{"private 192.168", "192.168.1.1", true},
		{"loopback", "127.0.0.1", true},
		{"link local", "169.254.1.1", true},
		{"IPv6 loopback", "::1", true},
		{"IPv6 ULA", "fc00::1", true},
		{"IPv6 link local", "fe80::1", true},
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", true},
		{"carrier grade NAT", "100.64.0.1", true},
		{"multicast", "224.0.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid IP: %q", tt.ip)
			}
			got := IsPrivateIP(ip)
			if got != tt.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestValidateNoSelfReference(t *testing.T) {
	// Save and restore global state
	oldAddrs := selfReferenceAddrs
	defer func() { selfReferenceAddrs = oldAddrs }()
	selfReferenceAddrs = nil

	SetAdminAddr("127.0.0.1:8081")
	SetProxyAddrs(":80", ":443")

	tests := []struct {
		name         string
		backend      string
		isAdminRoute bool
		wantErr      bool
	}{
		{"external backend", "http://example.com:8080/foo", false, false},
		{"admin route to self exempt", "http://127.0.0.1:8081/admin", true, false},
		{"admin port loopback", "http://127.0.0.1:8081/api", false, true},
		{"admin port localhost", "http://localhost:8081/api", false, true},
		{"proxy port loopback", "http://127.0.0.1:80/api", false, true},
		{"proxy port 0.0.0.0", "http://0.0.0.0:80/api", false, true},
		{"proxy port bare", "http://:80/api", false, true},
		{"different port on same host", "http://127.0.0.1:8080/api", false, false},
		{"https proxy port", "https://127.0.0.1:443/api", false, true},
		{"encoded loopback", "http://0x7f000001:80/api", false, true},
		{"default http port loopback", "http://127.0.0.1/api", false, true},
		{"default https port loopback", "https://127.0.0.1/api", false, true},
		{"default http port localhost", "http://localhost/api", false, true},
		{"default http port 0.0.0.0", "http://0.0.0.0/api", false, true},
		{"default http port different listener", "http://127.0.0.1:8080", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNoSelfReference(tt.backend, tt.isAdminRoute)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateNoSelfReference(%q) expected error, got nil", tt.backend)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateNoSelfReference(%q) unexpected error: %v", tt.backend, err)
			}
		})
	}
}

func TestValidateWAFRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    string
		wantErr bool
	}{
		{"valid SecRule", `SecRule ARGS "@rx foo" "id:1,phase:2,deny,status:403"`, false},
		{"empty rule", "", true},
		{"null byte", "SecRule ARGS \x00", true},
		{"newline", "SecRule ARGS\n", true},
		{"engine off directive", "SecRuleEngine Off", true},
		{"ctl disable", `SecRule ARGS "@rx foo" "id:1,phase:2,ctl:ruleEngine=Off"`, true},
		{"ctl disable with space before colon", `SecRule ARGS "@rx foo" "id:1,phase:2,ctl :ruleEngine=Off"`, true},
		{"ctl disable uppercase", `SecRule ARGS "@rx foo" "id:1,phase:2,CTL:ruleEngine=Off"`, true},
		{"secdefaultaction pass", `SecDefaultAction "phase:1,pass,nolog"`, true},
		{"secaction pass nolog", `SecAction "id:2,phase:1,pass,nolog"`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWAFRule(tt.rule)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateWAFRule(%q) expected error, got nil", tt.rule)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateWAFRule(%q) unexpected error: %v", tt.rule, err)
			}
		})
	}
}

func TestValidateSessionDuration(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid hours", "24h", false},
		{"valid minutes", "30m", false},
		{"valid max", "720h", false},
		{"empty", "", true},
		{"invalid format", "tomorrow", true},
		{"zero", "0s", true},
		{"negative", "-1h", true},
		{"too short", "30s", true},
		{"too long", "721h", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSessionDuration(tt.value)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateSessionDuration(%q) expected error, got nil", tt.value)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateSessionDuration(%q) unexpected error: %v", tt.value, err)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid low", "1", false},
		{"valid high", "65535", false},
		{"valid http", "80", false},
		{"empty", "", true},
		{"not a number", "abc", true},
		{"zero", "0", true},
		{"negative", "-1", true},
		{"too high", "65536", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePort(tt.value, "listen_port")
			if tt.wantErr && err == nil {
				t.Errorf("ValidatePort(%q) expected error, got nil", tt.value)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidatePort(%q) unexpected error: %v", tt.value, err)
			}
		})
	}
}

func TestValidateMaxConnections(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"valid low", 1, false},
		{"valid default", 1000, false},
		{"valid high", 1_000_000, false},
		{"zero", 0, true},
		{"negative", -1, true},
		{"too high", 1_000_001, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMaxConnections(tt.value)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateMaxConnections(%d) expected error, got nil", tt.value)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateMaxConnections(%d) unexpected error: %v", tt.value, err)
			}
		})
	}
}

func TestValidateRequestTimeout(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid seconds", "30s", false},
		{"valid minutes", "5m", false},
		{"valid max", "1h", false},
		{"empty", "", true},
		{"invalid format", "fast", true},
		{"zero", "0s", true},
		{"negative", "-1s", true},
		{"too short", "500ms", true},
		{"too long", "1h1s", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRequestTimeout(tt.value)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateRequestTimeout(%q) expected error, got nil", tt.value)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateRequestTimeout(%q) unexpected error: %v", tt.value, err)
			}
		})
	}
}
