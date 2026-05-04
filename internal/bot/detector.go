package bot

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Score thresholds
const (
	ScoreBlock    = 0.8
	ScoreChallenge = 0.4
)

// Detector holds state for passive bot detection.
type Detector struct {
	mu          sync.RWMutex
	knownBotUAs map[string]bool
	knownGoodUAs map[string]bool
}

// NewDetector creates a bot detector with default signatures.
func NewDetector() *Detector {
	d := &Detector{
		knownBotUAs:  make(map[string]bool),
		knownGoodUAs: make(map[string]bool),
	}
	// Known bot / tool signatures
	for _, ua := range []string{
		"curl", "wget", "python-requests", "axios", "node-fetch",
		"scrapy", "headlesschrome", "phantomjs", "selenium",
		"httpclient", "java", "libwww", " mechanize",
		"Go-http-client", "fasthttp", "postman",
	} {
		d.knownBotUAs[ua] = true
	}
	// Known good browser signatures
	for _, ua := range []string{
		"Mozilla/5.0", "AppleWebKit", "Chrome", "Safari",
		"Firefox", "Edg", "Opera",
	} {
		d.knownGoodUAs[ua] = true
	}
	return d
}

// Score returns a bot-likelihood score between 0.0 (human) and 1.0 (bot).
func (d *Detector) Score(r *http.Request) float64 {
	score := 0.0
	ua := strings.ToLower(r.UserAgent())

	// User-Agent analysis (0.0–0.4)
	score += d.scoreUserAgent(ua)

	// Header analysis (0.0–0.3)
	score += d.scoreHeaders(r.Header)

	// Request behavior (0.0–0.2)
	score += d.scoreBehavior(r)

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// realisticBrowserUA matches common browser UAs with version numbers,
// rejecting trivial substring injection like "Chrome/1.0" appended to a bot UA.
var realisticBrowserUA = regexp.MustCompile(`(?i)^(Mozilla\/5\.0\s+\().*(Chrome\/\d+|Firefox\/\d+|Safari\/\d+|Edge\/\d+)`)

func (d *Detector) scoreUserAgent(ua string) float64 {
	if ua == "" {
		return 0.35 // Empty UA is suspicious
	}

	// Check known bot signatures
	for bot := range d.knownBotUAs {
		if strings.Contains(ua, bot) {
			return 0.9
		}
	}

	// Require a realistic browser UA structure, not just a substring match
	if !realisticBrowserUA.MatchString(ua) {
		return 0.25
	}

	return 0.0
}

func (d *Detector) scoreHeaders(h http.Header) float64 {
	score := 0.0

	// Accept-Language missing
	if h.Get("Accept-Language") == "" {
		score += 0.15
	}

	// Accept header missing or generic
	accept := h.Get("Accept")
	if accept == "" || accept == "*/*" {
		score += 0.1
	}

	// No Accept-Encoding (real browsers always send this)
	if h.Get("Accept-Encoding") == "" {
		score += 0.1
	}

	// Referer missing is normal for first request, less suspicious

	// Connection header missing
	if h.Get("Connection") == "" {
		score += 0.05
	}

	return score
}

func (d *Detector) scoreBehavior(r *http.Request) float64 {
	score := 0.0

	// HEAD requests from non-bots are rare for page loads
	if r.Method == "HEAD" {
		score += 0.15
	}

	// TRACE/CONNECT are almost never legitimate
	if r.Method == "TRACE" || r.Method == "CONNECT" {
		score += 0.2
	}

	// No cookies on a second+ request would be weird, but we can't tell here

	return score
}

// ShouldBlock returns true if the score exceeds the block threshold.
func ShouldBlock(score float64) bool {
	return score >= ScoreBlock
}

// ShouldChallenge returns true if the score falls in the challenge range.
func ShouldChallenge(score float64) bool {
	return score >= ScoreChallenge && score < ScoreBlock
}

// cacheEntry tracks challenge state for an IP.
type cacheEntry struct {
	passed      bool
	passExpires time.Time
	lastSeen    time.Time
	score       float64
}

// IPChallengeCache holds bot scores and challenge results per IP.
type IPChallengeCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

// NewIPChallengeCache creates an LRU-like cache for bot decisions.
func NewIPChallengeCache() *IPChallengeCache {
	c := &IPChallengeCache{
		entries: make(map[string]*cacheEntry),
		ttl:     24 * time.Hour,
	}
	go c.cleanupLoop()
	return c
}

func (c *IPChallengeCache) Get(ip string) *cacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if e, ok := c.entries[ip]; ok {
		if time.Now().Before(e.passExpires) || time.Now().Before(e.lastSeen.Add(c.ttl)) {
			return e
		}
	}
	return nil
}

func (c *IPChallengeCache) Set(ip string, score float64, passed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[ip] = &cacheEntry{
		passed:      passed,
		passExpires: time.Now().Add(c.ttl),
		lastSeen:    time.Now(),
		score:       score,
	}
}

func (c *IPChallengeCache) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for ip, e := range c.entries {
			if now.After(e.passExpires) && now.After(e.lastSeen.Add(c.ttl)) {
				delete(c.entries, ip)
			}
		}
		c.mu.Unlock()
	}
}
