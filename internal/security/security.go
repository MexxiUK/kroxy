package security

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kroxy/kroxy/internal/store"
)

// Antibot provides bot detection and challenge mechanisms
type Antibot struct {
	store      *store.Store
	challenges sync.Map // session_id -> challenge
}

type Challenge struct {
	ID         string
	Type       string // "cookie", "javascript", "captcha"
	Question   string
	Answer     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Completed  bool
}

// NewAntibot creates a new antibot handler
func NewAntibot(s *store.Store) *Antibot {
	return &Antibot{store: s}
}

// Middleware returns middleware for bot detection
func (ab *Antibot) Middleware(enabled map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if route has antibot enabled
			if !enabled[r.Host] {
				next.ServeHTTP(w, r)
				return
			}

			// Check for known good bots
			if ab.isKnownGoodBot(r.UserAgent()) {
				next.ServeHTTP(w, r)
				return
			}

			// Check if session already passed challenge
			cookie, err := r.Cookie("kroxy_antibot")
			if err == nil && ab.validateChallenge(cookie.Value) {
				next.ServeHTTP(w, r)
				return
			}

			// Issue challenge
			ab.issueChallenge(w, r)
		})
	}
}

func (ab *Antibot) isKnownGoodBot(userAgent string) bool {
	knownBots := []string{
		"Googlebot",
		"Bingbot",
		"Slurp",
		"DuckDuckBot",
		"Baiduspider",
		"YandexBot",
		"facebookexternalhit",
		"Twitterbot",
		"LinkedInBot",
		"Applebot",
	}

	for _, bot := range knownBots {
		if strings.Contains(userAgent, bot) {
			return true
		}
	}
	return false
}

func (ab *Antibot) validateChallenge(sessionID string) bool {
	value, ok := ab.challenges.Load(sessionID)
	if !ok {
		return false
	}

	challenge := value.(*Challenge)
	return challenge.Completed && time.Now().Before(challenge.ExpiresAt)
}

func (ab *Antibot) issueChallenge(w http.ResponseWriter, r *http.Request) {
	// Generate challenge ID
	challengeID := generateChallengeID()

	// Create JavaScript challenge (simplest)
	challenge := &Challenge{
		ID:        challengeID,
		Type:      "javascript",
		Question:  "Please enable JavaScript",
		Answer:    challengeID, // Answer is the challenge ID itself
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	ab.challenges.Store(challengeID, challenge)

	// Return JavaScript challenge page
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(generateJSChallengeHTML(challengeID)))
}

func generateJSChallengeHTML(challengeID string) string {
	return `<!DOCTYPE html>
<html>
<head>
    <title>Checking your browser...</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #3498db; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <h2>Checking your browser...</h2>
    <div class="spinner"></div>
    <p>This process is automatic. Your browser will redirect shortly.</p>
    <script>
        setTimeout(function() {
            document.cookie = "kroxy_antibot=` + challengeID + `; path=/; max-age=86400";
            location.reload();
        }, 2000);
    </script>
</body>
</html>`
}

func generateChallengeID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// AuthBasic provides HTTP Basic Authentication
type AuthBasic struct {
	store *store.Store
	users sync.Map // username -> password hash
}

// NewAuthBasic creates a new basic auth handler
func NewAuthBasic(s *store.Store) *AuthBasic {
	return &AuthBasic{store: s}
}

// Middleware returns middleware for basic authentication
func (ab *AuthBasic) Middleware(protected map[string]struct{ username, password string }) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if route requires basic auth
			creds, ok := protected[r.Host]
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			username, password, ok := r.BasicAuth()
			if !ok || username != creds.username || password != creds.password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Kroxy"`)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized\n"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// BadBehavior tracks and blocks IPs with suspicious behavior
type BadBehavior struct {
	store         *store.Store
	ipTracker     sync.Map // IP -> *IPRecord
	threshold     int
	banDuration   time.Duration
	windowDuration time.Duration
}

type IPRecord struct {
	IP         string
	Errors     int
	LastError  time.Time
	BannedUntil time.Time
	mu         sync.Mutex
}

// NewBadBehavior creates a new bad behavior tracker
func NewBadBehavior(s *store.Store, threshold int, banDuration time.Duration) *BadBehavior {
	return &BadBehavior{
		store:       s,
		threshold:   threshold,
		banDuration: banDuration,
	}
}

// Middleware returns middleware for bad behavior detection
func (bb *BadBehavior) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := GetClientIP(r)

			// Check if IP is banned
			if bb.isBanned(ip) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Access denied due to suspicious activity\n"))
				return
			}

			// Wrap response writer to track status codes
			wrapped := &responseWriter{ResponseWriter: w, ip: ip, bb: bb}
			next.ServeHTTP(wrapped, r)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	ip     string
	bb     *BadBehavior
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)

	// Track 4xx and 5xx errors
	if status >= 400 {
		rw.bb.recordError(rw.ip)
	}
}

func (bb *BadBehavior) isBanned(ip string) bool {
	value, ok := bb.ipTracker.Load(ip)
	if !ok {
		return false
	}

	record := value.(*IPRecord)
	record.mu.Lock()
	defer record.mu.Unlock()

	return time.Now().Before(record.BannedUntil)
}

func (bb *BadBehavior) recordError(ip string) {
	value, _ := bb.ipTracker.LoadOrStore(ip, &IPRecord{IP: ip})

	record := value.(*IPRecord)
	record.mu.Lock()
	defer record.mu.Unlock()

	record.Errors++
	record.LastError = time.Now()

	if record.Errors >= bb.threshold {
		record.BannedUntil = time.Now().Add(bb.banDuration)
	}
}

func (bb *BadBehavior) Unban(ip string) {
	bb.ipTracker.Delete(ip)
}

// IPFilter handles blacklists and whitelists
type IPFilter struct {
	store      *store.Store
	blacklists sync.Map // IP/network -> bool
	whitelists sync.Map  // IP/network -> bool
}

// NewIPFilter creates a new IP filter
func NewIPFilter(s *store.Store) *IPFilter {
	return &IPFilter{store: s}
}

// Middleware returns middleware for IP filtering
func (f *IPFilter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := GetClientIP(r)

			// Check whitelist first
			if f.isWhitelisted(ip) {
				next.ServeHTTP(w, r)
				return
			}

			// Check blacklist
			if f.isBlacklisted(ip) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Access denied\n"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (f *IPFilter) isWhitelisted(ip string) bool {
	_, ok := f.whitelists.Load(ip)
	return ok
}

func (f *IPFilter) isBlacklisted(ip string) bool {
	_, ok := f.blacklists.Load(ip)
	return ok
}

func (f *IPFilter) AddToBlacklist(ip string) {
	f.blacklists.Store(ip, true)
}

func (f *IPFilter) AddToWhitelist(ip string) {
	f.whitelists.Store(ip, true)
}

func (f *IPFilter) RemoveFromBlacklist(ip string) {
	f.blacklists.Delete(ip)
}

func (f *IPFilter) RemoveFromWhitelist(ip string) {
	f.whitelists.Delete(ip)
}

// CountryBlock handles geo-blocking
type CountryBlock struct {
	store       *store.Store
	blocked    sync.Map // country code -> bool
	allowed    sync.Map // country code -> bool
	geoService GeoService
}

type GeoService interface {
	GetCountry(ip string) (string, error)
}

// NewCountryBlock creates a new country blocker
func NewCountryBlock(s *store.Store, geoService GeoService) *CountryBlock {
	return &CountryBlock{
		store:       s,
		geoService: geoService,
	}
}

// Middleware returns middleware for country blocking
func (cb *CountryBlock) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no countries are configured, allow all
			blockedCount := 0
			allowedCount := 0
			cb.blocked.Range(func(_, _ interface{}) bool { blockedCount++; return true })
			cb.allowed.Range(func(_, _ interface{}) bool { allowedCount++; return true })

			if blockedCount == 0 && allowedCount == 0 {
				next.ServeHTTP(w, r)
				return
			}

			ip := GetClientIP(r)

			// Get country for IP
			country, err := cb.geoService.GetCountry(ip)
			if err != nil {
				// On error, default to allow
				next.ServeHTTP(w, r)
				return
			}

			// If whitelist mode, only allow listed countries
			if allowedCount > 0 {
				_, ok := cb.allowed.Load(country)
				if !ok {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte("Access denied from your country\n"))
					return
				}
			}

			// If blacklist mode, block listed countries
			if blockedCount > 0 {
				_, ok := cb.blocked.Load(country)
				if ok {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte("Access denied from your country\n"))
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (cb *CountryBlock) BlockCountry(country string) {
	cb.blocked.Store(country, true)
}

func (cb *CountryBlock) AllowCountry(country string) {
	cb.allowed.Store(country, true)
}

func (cb *CountryBlock) UnblockCountry(country string) {
	cb.blocked.Delete(country)
}

func (cb *CountryBlock) DisallowCountry(country string) {
	cb.allowed.Delete(country)
}

// GetClientIP extracts the client IP from a request, handling proxies
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Check CF-Connecting-IP (Cloudflare)
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}