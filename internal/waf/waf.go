package waf

import (
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	corazacrs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/crypto"
	"github.com/kroxy/kroxy/internal/security"
	"github.com/kroxy/kroxy/internal/store"
)

// MaxRequestBodySize limits the maximum request body size to prevent memory exhaustion
const MaxRequestBodySize = 10 * 1024 * 1024 // 10MB

// WAF wraps the Coraza Web Application Firewall
type WAF struct {
	secEngine  coraza.WAF
	enabled    bool
	mode       string // "block" or "detect"
	routeID    int    // 0 = global
	store      *store.Store
	audit      *audit.Logger
	signingKey []byte // HMAC signing key for WAF verification headers
}

// Config holds WAF configuration
type Config struct {
	Enabled       bool
	Mode          string // "block" or "detect"
	Ruleset       string // "owasp-crs" or "custom"
	CustomRules   []string
	ParanoiaLevel int    // 1 (conservative), 2 (balanced), 3 (aggressive)
	SigningKey    []byte // HMAC signing key for WAF verification headers
}

// New creates a new WAF instance with OWASP Core Rule Set.
// If routeID is nil, only global rules are loaded.
// If routeID is set, global rules plus that route's specific rules are loaded.
// mode controls the WAF behavior: "block" blocks requests, "detect" logs without blocking.
func New(s *store.Store, cfg Config, auditLogger *audit.Logger, routeID *int, mode string) (*WAF, error) {
	secEngine, err := createWAFEngine(cfg, s, routeID)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF engine: %w", err)
	}

	resolvedRouteID := 0
	if routeID != nil {
		resolvedRouteID = *routeID
	}

	waf := &WAF{
		secEngine:  secEngine,
		enabled:    cfg.Enabled,
		mode:       mode,
		routeID:    resolvedRouteID,
		store:      s,
		audit:      auditLogger,
		signingKey: cfg.SigningKey,
	}

	scope := "global"
	if routeID != nil {
		scope = fmt.Sprintf("route:%d", *routeID)
	}
	log.Printf("WAF initialized (scope: %s, mode: %s)", scope, mode)
	return waf, nil
}

// hppSQLPatterns matches SQL keywords that attackers split across duplicate params.
// e.g. ?a=UNION&a=SELECT concatenates to "UNION SELECT"
var hppSQLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bUNION\s+(?:ALL\s+)?SELECT\b`),
	regexp.MustCompile(`(?i)\bINSERT\s+INTO\b`),
	regexp.MustCompile(`(?i)\bUPDATE\s+\w+\s+SET\b`),
	regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`),
	regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`),
	regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`),
	regexp.MustCompile(`(?i)\bEXEC\s*\(`),
	regexp.MustCompile(`(?i)\bEXECUTE\s*\(`),
}

// hppXSSPatterns matches XSS payloads that attackers split across duplicate params.
var hppXSSPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[\s>]`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)\bon(?:error|load|click|mouseover|focus|blur)\s*=`),
}

// checkHPP concatenates all query parameter values and checks for SQL/XSS patterns
// that were split across duplicate parameters to bypass per-value WAF inspection.
// Also normalizes each value for encoding bypasses and checks for base64 payloads.
func checkHPP(query url.Values) (matched bool, category string) {
	var allValues strings.Builder
	for _, vals := range query {
		for _, v := range vals {
			allValues.WriteString(v)
			allValues.WriteString(" ")

			// Check each value after normalization for encoding bypasses
			if found, reason := checkEncodedInjection(v); found {
				return true, reason
			}
		}
	}
	concatenated := allValues.String()

	// Also normalize the concatenated string for fullwidth/unicode detection
	normalizedConcat := normalizeEncoding(concatenated)
	for _, pat := range hppSQLPatterns {
		if pat.MatchString(normalizedConcat) {
			return true, "HPP: SQL keyword pattern in concatenated query params"
		}
	}
	for _, pat := range hppXSSPatterns {
		if pat.MatchString(normalizedConcat) {
			return true, "HPP: XSS pattern in concatenated query params"
		}
	}
	return false, ""
}

// checkRawQueryBase64 scans the raw query string for base64-encoded values.
// url.ParseQuery corrupts base64 '+' to space, so we must check the raw form.
func checkRawQueryBase64(rawQuery string) (matched bool, category string) {
	for _, pair := range strings.Split(rawQuery, "&") {
		idx := strings.Index(pair, "=")
		if idx < 0 {
			continue
		}
		value := pair[idx+1:]
		if base64Pattern.MatchString(value) {
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err == nil {
				decodedStr := string(decoded)
				for _, pat := range injectionPatterns {
					if pat.MatchString(decodedStr) {
						return true, "Base64-encoded injection pattern in query param"
					}
				}
				suspiciousChars := []string{"'", "\"", "<", ">", "<!DOCTYPE", "<!ENTITY"}
				for _, ch := range suspiciousChars {
					if strings.Contains(decodedStr, ch) {
						return true, "Base64-encoded suspicious content: " + ch
					}
				}
			}
		}
	}
	return false, ""
}

// normalizeEncoding applies multiple decode passes to catch double/triple encoding
// and decodes IIS-style %uXXXX unicode and overlong UTF-8 sequences.
func normalizeEncoding(s string) string {
	// Pass 1: Decode %uXXXX (IIS-style unicode) to percent-encoded form
	// so that subsequent URL decoding handles them.
	s = decodeIISUnicode(s)

	// Pass 2: Normalize overlong UTF-8 byte sequences in the raw percent-encoded string.
	// This catches %c0%a7 (overlong ') before URL decoding converts it to replacement chars.
	s = normalizeOverlongPercentEncoded(s)

	// Pass 3: URL-decode repeatedly until stable (catches double/triple encoding)
	prev := s
	for i := 0; i < 3; i++ {
		decoded, err := url.QueryUnescape(prev)
		if err != nil || decoded == prev {
			break
		}
		prev = decoded
	}
	s = prev

	// Pass 4: Normalize overlong UTF-8 sequences that survived URL decoding
	s = normalizeOverlongUTF8(s)

	// Pass 5: Normalize unicode variants (fullwidth chars) to ASCII equivalents
	s = normalizeUnicode(s)

	return s
}

// decodeIISUnicode converts %uXXXX sequences (IIS-style unicode) to percent-encoded form
// so subsequent URL decoding handles them correctly.
// e.g. %u0027 → %27
func decodeIISUnicode(s string) string {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if i+5 < len(s) && (s[i:i+2] == "%u" || s[i:i+2] == "%U") {
			codePoint, err := strconv.ParseInt(s[i+2:i+6], 16, 32)
			if err == nil {
				// Convert to percent-encoded UTF-8 bytes
				utf8Bytes := []byte(string(rune(codePoint)))
				for _, b := range utf8Bytes {
					result.WriteString(fmt.Sprintf("%%%02X", b))
				}
				i += 6
				continue
			}
		}
		result.WriteByte(s[i])
		i++
	}
	return result.String()
}

// normalizeOverlongPercentEncoded detects overlong UTF-8 sequences in percent-encoded form
// and replaces them with the canonical percent-encoded equivalent.
// e.g. %C0%A7 (two-byte overlong encoding of 0x27 = ') → %27
func normalizeOverlongPercentEncoded(s string) string {
	// Scan for two-byte overlong UTF-8 sequences: %C0-%C1 followed by %80-%BF
	// These encode codepoints 0x00-0x7F (which should be single bytes).
	var result strings.Builder
	i := 0
	for i < len(s) {
		// Check for %C0 or %C1 followed by %XX
		if i+6 <= len(s) && s[i] == '%' &&
			(s[i+1] == 'C' || s[i+1] == 'c') &&
			(s[i+2] == '0' || s[i+2] == '1') &&
			s[i+3] == '%' {
			// Parse the two-byte overlong sequence
			b1, err1 := strconv.ParseInt(s[i+1:i+3], 16, 8)
			// Find the next percent-encoded byte
			j := i + 3
			if j+2 <= len(s) && s[j] == '%' {
				b2, err2 := strconv.ParseInt(s[j+1:j+3], 16, 8)
				if err1 == nil && err2 == nil && b1 >= 0xC0 && b1 <= 0xC1 && b2 >= 0x80 && b2 <= 0xBF {
					// Decode: codepoint = ((b1 & 0x1F) << 6) | (b2 & 0x3F)
					codepoint := uint16(b1&0x1F)<<6 | uint16(b2&0x3F)
					result.WriteString(fmt.Sprintf("%%%02X", codepoint))
					i = j + 3
					continue
				}
			}
		}
		result.WriteByte(s[i])
		i++
	}
	if result.Len() == 0 {
		return s
	}
	return result.String()
}

// normalizeOverlongUTF8 replaces overlong UTF-8 byte sequences with their canonical equivalents.
// e.g. %c0%a7 (two-byte overlong encoding of ') → '
func normalizeOverlongUTF8(s string) string {
	// URL-decoded bytes may contain overlong sequences.
	// We decode the string as UTF-8, which rejects overlong sequences,
	// so we need to handle this at the byte level.
	result := make([]byte, 0, len(s))
	i := 0
	for i < len(s) {
		// Check for 2-byte overlong encoding (0xC0-0xC1 prefix)
		if i+1 < len(s) && (s[i] == 0xC0 || s[i] == 0xC1) {
			// Overlong: the real codepoint is < 0x80
			// Decode: codepoint = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
			codepoint := (uint16(s[i]&0x1F) << 6) | uint16(s[i+1]&0x3F)
			result = append(result, byte(codepoint))
			i += 2
			continue
		}
		result = append(result, s[i])
		i++
	}
	return string(result)
}

// normalizeUnicode converts unicode variant characters (fullwidth, compatibility forms)
// to their ASCII equivalents for pattern matching.
func normalizeUnicode(s string) string {
	var result strings.Builder
	for _, r := range s {
		// Map fullwidth ASCII variants to their ASCII equivalents
		// Fullwidth digits: U+FF10-U+FF19 → '0'-'9'
		// Fullwidth uppercase: U+FF21-U+FF3A → 'A'-'Z'
		// Fullwidth lowercase: U+FF41-U+FF5A → 'a'-'z'
		// Fullwidth apostrophe: U+FF07 → '\''
		// Fullwidth quote: U+FF02 → '"'
		switch {
		case r >= '\uFF10' && r <= '\uFF19': // fullwidth digits
			result.WriteByte(byte(r - 0xFEE0))
		case r >= '\uFF21' && r <= '\uFF3A': // fullwidth uppercase
			result.WriteByte(byte(r - 0xFEE0))
		case r >= '\uFF41' && r <= '\uFF5A': // fullwidth lowercase
			result.WriteByte(byte(r - 0xFEE0))
		case r == '\uFF07': // fullwidth apostrophe
			result.WriteByte('\'')
		case r == '\uFF02': // fullwidth quote
			result.WriteByte('"')
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// injectionPatterns matches SQL injection and XSS patterns in decoded input.
var injectionPatterns = []*regexp.Regexp{
	// SQL injection patterns
	regexp.MustCompile(`(?i)\bUNION\s+(?:ALL\s+)?SELECT\b`),
	regexp.MustCompile(`(?i)\bINSERT\s+INTO\b`),
	regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`),
	regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`),
	regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`),
	regexp.MustCompile(`(?i)\bEXEC\s*\(`),
	regexp.MustCompile(`(?i)'\s*OR\s+'[^']*'\s*=`),
	regexp.MustCompile(`(?i)'\s*OR\s+\d+\s*=\s*\d+`),
	regexp.MustCompile(`(?i)\bOR\s+1\s*=\s*1\b`),
	regexp.MustCompile(`(?i)\bAND\s+\d+\s*=\s*\d+`),
	regexp.MustCompile(`(?i);\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER)\b`),
	regexp.MustCompile(`(?i)\bSLEEP\s*\(`),
	regexp.MustCompile(`(?i)\bBENCHMARK\s*\(`),
	// Single/double quote in query context (common in SQLi)
	regexp.MustCompile(`(?i)'\s*(?:OR|AND|UNION|;|--)`),
	// Standalone SQL keywords that are dangerous even without compound context
	regexp.MustCompile(`(?i)\bSELECT\b.*\bFROM\b`),
	regexp.MustCompile(`(?i)\bDROP\s+(?:TABLE|DATABASE)\b`),
	regexp.MustCompile(`(?i)\bUPDATE\s+\w+\s+SET\b`),
	regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`),
	regexp.MustCompile(`(?i)\bEXEC\s*\(.+\)\s*;`),
	regexp.MustCompile(`(?i)\bEXECUTE\s+\w+`),
	// XSS patterns
	regexp.MustCompile(`(?i)<script[\s>]`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)\bon(?:error|load|click|mouseover|focus|blur)\s*=`),
	regexp.MustCompile(`(?i)<img[^>]+onerror`),
	regexp.MustCompile(`(?i)<svg[^>]+onload`),
	regexp.MustCompile(`(?i)<!\s*(?:DOCTYPE|ENTITY)\s`),
}

// base64Pattern detects base64-encoded strings that might contain hidden payloads.
var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]{8,}={0,2}$`)

// checkEncodedInjection normalizes encoding in a string and checks for SQL/XSS patterns.
// If normalization changes the string (indicating encoding tricks), the result is checked
// for suspicious characters even if no full injection pattern matches.
func checkEncodedInjection(input string) (matched bool, category string) {
	normalized := normalizeEncoding(input)
	for _, pat := range injectionPatterns {
		if pat.MatchString(normalized) {
			return true, "Encoded injection pattern detected"
		}
	}
	// If normalization changed the string, check for suspicious characters
	// that emerged from decoding (quotes, angle brackets, etc.)
	if normalized != input {
		suspiciousChars := []string{"'", "\"", "<", ">", ";", "--", "/*", "*/"}
		for _, ch := range suspiciousChars {
			if strings.Contains(normalized, ch) && !strings.Contains(input, ch) {
				return true, "Suspicious encoding bypass detected: decoded to " + ch
			}
		}
	}
	// Check for base64-encoded payloads
	if base64Pattern.MatchString(input) {
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err == nil {
			decodedStr := string(decoded)
			for _, pat := range injectionPatterns {
				if pat.MatchString(decodedStr) {
					return true, "Base64-encoded injection pattern detected"
				}
			}
			// Also check decoded content for suspicious characters
			suspiciousChars := []string{"'", "\"", "<", ">"}
			for _, ch := range suspiciousChars {
				if strings.Contains(decodedStr, ch) {
					return true, "Base64-encoded suspicious content detected"
				}
			}
		}
	}
	return false, ""
}

// headersToSkip lists headers that should NOT be checked for injection patterns
// because they are standard headers with expected values that could cause false positives.
var headersToSkip = map[string]bool{
	"Host":            true,
	"Accept":          true,
	"Accept-Encoding": true,
	"Connection":      true,
	"Content-Length":  true,
	"Content-Type":    true,
}

// checkHeaderInjection inspects all request headers for SQL/XSS injection patterns,
// skipping only standard headers that would cause false positives.
func checkHeaderInjection(r *http.Request) (matched bool, category string) {
	for name, values := range r.Header {
		if headersToSkip[name] {
			continue
		}
		for _, value := range values {
			if found, reason := checkEncodedInjection(value); found {
				return true, reason + " (in " + name + " header)"
			}
		}
	}
	return false, ""
}

// denyPattern matches "deny" as a whole word in SecRule actions.
// Handles "deny,log,...", "log,deny", bare "deny", and "deny,status:403".
var denyPattern = regexp.MustCompile(`\bdeny\b`)

// convertRuleToLogOnly replaces deny actions with pass (log only) in a SecRule directive.
func convertRuleToLogOnly(rule string) string {
	return denyPattern.ReplaceAllString(rule, "pass")
}

// crsFiles is the ordered list of OWASP CRS v4 rule files to load.
// Order matters: 901 must come first (checks crs_setup_version),
// 949/959 are blocking evaluation, 980 is final correlation.
var crsFiles = []string{
	"REQUEST-901-INITIALIZATION.conf",
	"REQUEST-905-COMMON-EXCEPTIONS.conf",
	"REQUEST-911-METHOD-ENFORCEMENT.conf",
	"REQUEST-913-SCANNER-DETECTION.conf",
	"REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
	"REQUEST-921-PROTOCOL-ATTACK.conf",
	"REQUEST-922-MULTIPART-ATTACK.conf",
	"REQUEST-930-APPLICATION-ATTACK-LFI.conf",
	"REQUEST-931-APPLICATION-ATTACK-RFI.conf",
	"REQUEST-932-APPLICATION-ATTACK-RCE.conf",
	"REQUEST-933-APPLICATION-ATTACK-PHP.conf",
	"REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
	"REQUEST-941-APPLICATION-ATTACK-XSS.conf",
	"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	"REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
	"REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
	"REQUEST-949-BLOCKING-EVALUATION.conf",
	"REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf",
	"RESPONSE-950-DATA-LEAKAGES.conf",
	"RESPONSE-951-DATA-LEAKAGES-SQL.conf",
	"RESPONSE-952-DATA-LEAKAGES-JAVA.conf",
	"RESPONSE-953-DATA-LEAKAGES-PHP.conf",
	"RESPONSE-954-DATA-LEAKAGES-IIS.conf",
	"RESPONSE-955-WEB-SHELLS.conf",
	"RESPONSE-956-DATA-LEAKAGES-RUBY.conf",
	"RESPONSE-959-BLOCKING-EVALUATION.conf",
	"RESPONSE-980-CORRELATION.conf",
}

func createWAFEngine(cfg Config, s *store.Store, routeID *int) (coraza.WAF, error) {
	wafConfig := coraza.NewWAFConfig()

	wafConfig = wafConfig.
		WithRequestBodyAccess().
		WithRequestBodyLimit(13107200).
		WithRequestBodyInMemoryLimit(1048576).
		WithResponseBodyAccess().
		WithResponseBodyLimit(524288)

	wafConfig = wafConfig.WithRootFS(corazacrs.FS)

	var directives strings.Builder

	// 1. Load Coraza recommended config (body access, audit logging, etc.)
	directives.WriteString("Include @coraza.conf-recommended\n")
	// 2. Load CRS setup (sets crs_setup_version, anomaly thresholds, paranoia level)
	directives.WriteString("Include @crs-setup.conf.example\n")

	// 2b. Override paranoia level if configured above PL1
	if cfg.ParanoiaLevel > 1 {
		directives.WriteString(fmt.Sprintf(
			"SecAction \"id:900000,phase:1,pass,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d\"\n",
			cfg.ParanoiaLevel, cfg.ParanoiaLevel))
	}

	// 2c. Raise inbound anomaly threshold to reduce false positives from
	// benign request characteristics (scanner UA detection, missing Accept, etc.)
	directives.WriteString("SecAction \"id:900001,phase:1,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=10\"\n")

	// 3. Load CRS rule files in correct order
	for _, f := range crsFiles {
		directives.WriteString("Include @owasp_crs/" + f + "\n")
	}

	// 4. Override engine mode — must come AFTER includes since
	// @coraza.conf-recommended sets SecRuleEngine DetectionOnly
	if cfg.Mode == "block" {
		directives.WriteString("SecRuleEngine On\n")
	} else {
		directives.WriteString("SecRuleEngine DetectionOnly\n")
	}


		// 4b. Custom Kroxy WAF rules to close bypass gaps
		kroxyRules := []string{
			// HPP: inspect raw query for SQL keywords split across duplicate params
			`SecRule REQUEST_HEADERS:X-Kroxy-Raw-Query "@rx (?i)(?:union\s+(?:all\s+)?select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|alter\s+table|exec\s*\(|execute\s*\()" "id:990100,phase:1,deny,status:403,msg:'Kroxy HPP: SQL keyword pattern in concatenated query',t:lowercase"`,
			// HPP: XSS patterns in raw query
			`SecRule REQUEST_HEADERS:X-Kroxy-Raw-Query "@rx (?i)(?:<script|javascript:|on(?:error|load|click|mouseover|focus|blur)\s*=|<img[^>]+onerror|<svg[^>]+onload)" "id:990110,phase:1,deny,status:403,msg:'Kroxy HPP: XSS pattern in concatenated query',t:lowercase"`,
			// Hex-encoded quote bypass: 0x27 (single quote) and 0x22 (double quote)
			`SecRule ARGS "@rx 0x[2722]" "id:990120,phase:2,deny,status:403,msg:'Kroxy: Hex-encoded quote detected',t:lowercase"`,
			`SecRule REQUEST_HEADERS:X-Kroxy-Raw-Query "@rx 0x[2722]" "id:990121,phase:1,deny,status:403,msg:'Kroxy HPP: Hex-encoded quote in query',t:lowercase"`,
			// Inline comment bypass in SQL keywords (e.g., S/**/LEEP)
			`SecRule ARGS "@rx (?i)\b\w+/\*\*/\w+" "id:990130,phase:2,deny,status:403,msg:'Kroxy: SQL inline comment obfuscation detected'"`,
			// XXE detection in request body
			`SecRule REQUEST_BODY "@rx (?i)<!\s*(?:DOCTYPE|ENTITY)\s+" "id:990140,phase:2,deny,status:403,msg:'Kroxy: XXE payload detected'"`,
			// SSRF: encoded IPs in query params (hex, octal, decimal, dotted octal)
			`SecRule ARGS "@rx (?i)(?:0x[0-9a-f]{6,8}|(?:https?://)?[0-9]{8,10}(?:/|$)|0[0-7]{8,11}|0[0-7]{1,3}\.[0-7]{1,3}\.[0-7]{1,3}\.[0-7]{1,3})" "id:990150,phase:2,deny,status:403,msg:'Kroxy: Encoded IP in query param (potential SSRF)'"`,
			// SSRF: common internal/metadata hostnames in query params
			`SecRule ARGS "@rx (?i)(?:169\.254\.169\.254|metadata\.google\.internal|\.sslip\.io|\.nip\.io)" "id:990160,phase:2,deny,status:403,msg:'Kroxy: Internal/metadata hostname in query param (SSRF)'"`,
		}
		for _, rule := range kroxyRules {
			directives.WriteString(rule + "\n")
		}

	// 5. Custom rules from config (rarely used)
	for _, rule := range cfg.CustomRules {
		directives.WriteString(rule)
		directives.WriteString("\n")
	}

	// 6. Custom rules from database
	if s != nil {
		var rules []store.WAFRule
		var err error
		if routeID != nil {
			rules, err = s.GetWAFRulesForRoute(*routeID)
		} else {
			rules, err = s.GetGlobalWAFRules()
		}
		if err != nil {
			log.Printf("Warning: failed to load WAF rules from database: %v", err)
		} else {
			for _, rule := range rules {
				// Emit rule exclusions before the rule itself
				if rule.Exclusions != "" {
					for _, ruleID := range strings.Split(rule.Exclusions, ",") {
						ruleID = strings.TrimSpace(ruleID)
						if ruleID != "" {
							directives.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", ruleID))
						}
					}
				}
				if rule.Enabled {
					ruleText := rule.Rule
					if rule.Mode == "log_only" {
						ruleText = convertRuleToLogOnly(ruleText)
						log.Printf("Loaded WAF rule (log_only): %s", rule.Name)
					} else {
						log.Printf("Loaded WAF rule: %s", rule.Name)
					}
					directives.WriteString(ruleText)
					directives.WriteString("\n")
				}
			}
		}
	}

	wafConfig = wafConfig.WithDirectives(directives.String())
	return coraza.NewWAF(wafConfig)
}

// requestServerPort extracts the server port from the request, defaulting to 80
// for HTTP and 443 for HTTPS when no port is present in the Host header.
func requestServerPort(r *http.Request) int {
	_, port, err := net.SplitHostPort(r.Host)
	if err == nil && port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			return p
		}
	}
	if r.TLS != nil {
		return 443
	}
	return 80
}

// InspectRequest checks a request against WAF rules. Returns (allowed, reason).
// If allowed is false, the caller should block the request with the given reason.
// If allowed is true and the request passed inspection, the signed WAF header
// is added to the request.
func (w *WAF) InspectRequest(rw http.ResponseWriter, r *http.Request) (allowed bool, reason string) {
	if !w.enabled {
		return true, ""
	}

	clientIP := security.GetClientIP(r)

	// Check for HTTP Parameter Pollution: concatenate all param values
	// and check for SQL/XSS patterns split across duplicate params.
	if r.URL.RawQuery != "" {
		if query, err := url.ParseQuery(r.URL.RawQuery); err == nil {
			if matched, hppReason := checkHPP(query); matched {
				if w.mode == "detect" {
					w.logDetection(clientIP, r, hppReason)
				} else {
					w.storeSecurityEvent(clientIP, r, "blocked")
					return false, hppReason
				}
			}
		}
	}

	// Check raw query string for base64-encoded payloads.
	// url.ParseQuery corrupts base64 + to space, so we check the raw form.
	if r.URL.RawQuery != "" {
		if matched, reason := checkRawQueryBase64(r.URL.RawQuery); matched {
			if w.mode == "detect" {
				w.logDetection(clientIP, r, reason)
			} else {
				w.storeSecurityEvent(clientIP, r, "blocked")
				return false, reason
			}
		}
	}
	// Check for encoded injection patterns in the raw query string.
	// Normalizes double-encoding, %uXXXX unicode, overlong UTF-8,
	// and fullwidth character variants before pattern matching.
	if r.URL.RawQuery != "" {
		if matched, reason := checkEncodedInjection(r.URL.RawQuery); matched {
			if w.mode == "detect" {
				w.logDetection(clientIP, r, reason)
			} else {
				w.storeSecurityEvent(clientIP, r, "blocked")
				return false, reason
			}
		}
	}

	// Check for injection patterns in common HTTP headers.
	// Headers like X-Forwarded-For can carry SQL injection payloads
	// that bypass query/body inspection.
	if matched, reason := checkHeaderInjection(r); matched {
		if w.mode == "detect" {
			w.logDetection(clientIP, r, reason)
		} else {
			w.storeSecurityEvent(clientIP, r, "blocked")
			return false, reason
		}
	}

	wafDetected := false

	tx := w.secEngine.NewTransaction()
	defer tx.ProcessLogging()

	serverPort := requestServerPort(r)
	tx.ProcessConnection(clientIP, serverPort, clientIP, serverPort)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)

	// Add the raw query string as a synthetic header so CRS evaluates
	// the full concatenated query, preventing HPP bypass where SQL keywords
	// are split across duplicate parameter names.
	if r.URL.RawQuery != "" {
		tx.AddRequestHeader("X-Kroxy-Raw-Query", r.URL.RawQuery)
	}

	for name, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}

	if intervention := tx.ProcessRequestHeaders(); intervention != nil {
		if w.mode == "detect" {
			wafDetected = true
			w.logDetection(clientIP, r, "Request headers triggered WAF rule")
		} else {
			w.storeSecurityEvent(clientIP, r, "blocked")
			return false, "Request headers blocked"
		}
	}

	// Read and process request body with size limit to prevent memory exhaustion.
	// Inspect body for any method that carries one — including OPTIONS.
	if r.Body != nil && r.ContentLength != 0 {
		limitedBody := http.MaxBytesReader(rw, r.Body, MaxRequestBodySize)
		body, err := io.ReadAll(limitedBody)
		if err != nil {
			if err.Error() == "http: request body too large" {
				w.storeSecurityEvent(clientIP, r, "blocked")
				return false, "Request body too large (max 10MB)"
			}
			log.Printf("WAF: Error reading request body: %v", err)
			r.Body = io.NopCloser(strings.NewReader(""))
			return false, "Error reading request body"
		}
		if _, _, err := tx.WriteRequestBody(body); err != nil {
			log.Printf("WAF: Error writing request body: %v", err)
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}

	if intervention, _ := tx.ProcessRequestBody(); intervention != nil {
		if w.mode == "detect" {
			wafDetected = true
			w.logDetection(clientIP, r, "Request body triggered WAF rule")
		} else {
			w.storeSecurityEvent(clientIP, r, "blocked")
			return false, "Request body blocked"
		}
	}

	// Add WAF verification header for requests that passed inspection
	if !wafDetected && len(w.signingKey) > 0 {
		signedValue, err := crypto.SignWAFHeader(r.Host, r.Method, r.URL.RequestURI(), w.routeID)
		if err != nil {
			log.Printf("WAF: failed to sign verification header: %v", err)
		} else {
			r.Header.Set(crypto.WAFHeaderName, signedValue)
		}
	}

	return true, ""
}
// logDetection logs a WAF detection event

// logDetection logs a WAF detection event in detect mode without blocking the request.
func (w *WAF) logDetection(clientIP string, r *http.Request, reason string) {
	log.Printf("WAF detect: %s - %s %s%s (route: %d)", clientIP, r.Method, r.Host, r.URL.RequestURI(), w.routeID)

	if w.audit != nil {
		w.audit.Log(audit.Event{
			Type:     audit.EventTypeWAFBlock,
			IP:       clientIP,
			Resource: "waf",
			Action:   "detect",
			Success:  false,
			Details: map[string]interface{}{
				"domain": r.Host,
				"uri":    r.URL.RequestURI(),
				"reason": reason,
				"mode":   "detect",
			},
		})
	}

	w.storeSecurityEvent(clientIP, r, "detected")
}

// storeSecurityEvent persists a security event to the database.
func (w *WAF) storeSecurityEvent(clientIP string, r *http.Request, action string) {
	if w.store == nil {
		return
	}

	err := w.store.CreateSecurityEvent(&store.SecurityEvent{
		EventType: "waf",
		ClientIP:  clientIP,
		Host:      r.Host,
		URI:       r.URL.RequestURI(),
		Method:    r.Method,
		UserAgent: r.Header.Get("User-Agent"),
		RuleName:  "",
		Action:    action,
		RouteID:   w.routeID,
	})
	if err != nil {
		log.Printf("WAF: failed to store security event: %v", err)
	}
}

// BlockRequest writes a 403 response for a blocked request.
func (w *WAF) BlockRequest(rw http.ResponseWriter, r *http.Request, reason string) {
	clientIP := security.GetClientIP(r)

	if w.audit != nil {
		w.audit.LogWAFBlock(clientIP, r.Host, "waf-rule", reason)
	}

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusForbidden)
	escapedReason := html.EscapeString(reason)
	rw.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>Forbidden</h1>
<p>Your request was blocked by the Web Application Firewall.</p>
<p>Reason: ` + escapedReason + `</p>
</body>
</html>`))
}

// IsEnabled returns whether WAF is enabled
func (w *WAF) IsEnabled() bool {
	return w.enabled
}

// Mode returns the WAF mode ("block" or "detect")
func (w *WAF) Mode() string {
	return w.mode
}

// TestResult holds the result of a single WAF test payload
type TestResult struct {
	Name             string            `json:"name"`
	Payload          string            `json:"payload"`
	Blocked          bool              `json:"blocked"`
	Method           string            `json:"method,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	URI              string            `json:"uri,omitempty"`
	IsResponse       bool              `json:"is_response,omitempty"`
	RespHeaders      map[string]string `json:"resp_headers,omitempty"`
	RuleID           int               `json:"rule_id,omitempty"`
	RuleMsg          string            `json:"rule_msg,omitempty"`
	SuggestedAction  string            `json:"suggested_action,omitempty"`
}

// TestCategory holds results for a category of test payloads
type TestCategory struct {
	Category string       `json:"category"`
	Tests    []TestResult `json:"tests"`
	Passed   int          `json:"passed"`
	Failed   int          `json:"failed"`
}

// TestSuiteResult holds the full test suite results
type TestSuiteResult struct {
	Engine   string         `json:"engine"`
	Mode     string         `json:"mode"`
	Results  []TestCategory `json:"results"`
	Summary  TestSummary    `json:"summary"`
}

// TestSummary holds aggregated test results
type TestSummary struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

// TestPayloadResult holds the outcome of a single test including matched rules.
type TestPayloadResult struct {
	Blocked         bool
	RuleID          int
	RuleMsg         string
	MatchedRules    []types.MatchedRule
}

// TestPayload runs a single test payload through the WAF engine and returns the result.
func (w *WAF) TestPayload(method, uri, body string, headers map[string]string) TestPayloadResult {
	tx := w.secEngine.NewTransaction()
	defer tx.ProcessLogging()

	tx.ProcessConnection("127.0.0.1", 80, "127.0.0.1", 80)
	parsedURI, err := url.Parse(uri)
	if err != nil {
		parsedURI = &url.URL{Path: uri}
	}
	tx.ProcessURI(uri, method, "HTTP/1.1")

	// Feed GET arguments so CRS evaluates ARGS (not just RAW_QUERY)
	if parsedURI.RawQuery != "" {
		values, err := url.ParseQuery(parsedURI.RawQuery)
		if err == nil {
			for key, vals := range values {
				for _, v := range vals {
					tx.AddGetRequestArgument(key, v)
				}
			}
		}
	}

	// Add Host header if not provided (CRS requires it)
	hasHost := false
	for k, v := range headers {
		tx.AddRequestHeader(k, v)
		if strings.EqualFold(k, "Host") {
			hasHost = true
		}
	}
	if !hasHost {
		tx.AddRequestHeader("Host", "test.example.com")
	}

	// Phase 1: request headers
	if intervention := tx.ProcessRequestHeaders(); intervention != nil {
		return buildTestResult(tx, intervention)
	}

	// Phase 2: request body
	if body != "" {
		if _, _, err := tx.WriteRequestBody([]byte(body)); err != nil {
			log.Printf("WAF test: error writing request body: %v", err)
		}
	}
	if intervention, _ := tx.ProcessRequestBody(); intervention != nil {
		return buildTestResult(tx, intervention)
	}

	// Phase 3-4: response headers/body — anomaly scoring evaluation happens here
	tx.AddResponseHeader("Content-Type", "text/html")
	if intervention := tx.ProcessResponseHeaders(200, "HTTP/1.1"); intervention != nil {
		return buildTestResult(tx, intervention)
	}
	if intervention, _ := tx.ProcessResponseBody(); intervention != nil {
		return buildTestResult(tx, intervention)
	}

	// Final check: anomaly-score blocks may not trigger an intervention
	// until after all phases complete
	if tx.IsInterrupted() {
		return buildTestResult(tx, tx.Interruption())
	}

	return TestPayloadResult{Blocked: false}
}

func buildTestResult(tx types.Transaction, intervention *types.Interruption) TestPayloadResult {
	res := TestPayloadResult{Blocked: true}
	if intervention != nil {
		res.RuleID = intervention.RuleID
		res.RuleMsg = intervention.Data
	}
	// Collect matched rules for display
	for _, mr := range tx.MatchedRules() {
		if mr.Disruptive() {
			res.MatchedRules = append(res.MatchedRules, mr)
			if res.RuleID == 0 {
				res.RuleID = mr.Rule().ID()
				res.RuleMsg = mr.Message()
			}
		}
	}
	return res
}

// TestResponsePayload tests response-phase WAF rules by simulating a request
// that returns a response with the given status, headers, and body.
func (w *WAF) TestResponsePayload(statusCode int, body string, respHeaders map[string]string) TestPayloadResult {
	tx := w.secEngine.NewTransaction()
	defer tx.ProcessLogging()

	// Send a clean request through first
	tx.ProcessConnection("127.0.0.1", 80, "127.0.0.1", 80)
	tx.ProcessURI("/test", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "test.example.com")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (WAF Test Suite)")

	if intervention := tx.ProcessRequestHeaders(); intervention != nil {
		return TestPayloadResult{Blocked: false} // request blocked, not what we're testing
	}
	if intervention, _ := tx.ProcessRequestBody(); intervention != nil {
		return TestPayloadResult{Blocked: false}
	}

	// Feed the response headers
	for k, v := range respHeaders {
		tx.AddResponseHeader(k, v)
	}
	if intervention := tx.ProcessResponseHeaders(statusCode, "HTTP/1.1"); intervention != nil {
		return buildTestResult(tx, intervention)
	}

	// Feed the response body
	if body != "" {
		if _, _, err := tx.WriteResponseBody([]byte(body)); err != nil {
			log.Printf("WAF test: error writing response body: %v", err)
		}
	}
	if intervention, _ := tx.ProcessResponseBody(); intervention != nil {
		return buildTestResult(tx, intervention)
	}

	if tx.IsInterrupted() {
		return buildTestResult(tx, tx.Interruption())
	}

	return TestPayloadResult{Blocked: false}
}