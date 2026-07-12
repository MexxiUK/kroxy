package bot

import (
	"net/http"
	"regexp"
	"strings"
)

// Score threshold for blocking.
const ScoreBlock = 0.8

// Detector holds state for passive bot detection.
type Detector struct {
	knownBotUAs map[string]bool
}

// NewDetector creates a bot detector with default signatures.
func NewDetector() *Detector {
	d := &Detector{
		knownBotUAs: make(map[string]bool),
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
	return d
}

// Score returns a bot-likelihood score between 0.0 (human) and 1.0 (bot).
func (d *Detector) Score(r *http.Request) float64 {
	score := 0.0
	ua := strings.ToLower(r.UserAgent())

	// User-Agent analysis
	score += d.scoreUserAgent(ua)

	// Header analysis
	score += d.scoreHeaders(r.Header)

	// Request behavior
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

	return score
}

// ShouldBlock returns true if the score exceeds the block threshold.
func ShouldBlock(score float64) bool {
	return score >= ScoreBlock
}
