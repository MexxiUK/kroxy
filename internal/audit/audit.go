package audit

import (
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// EventType represents the type of audit event
type EventType string

const (
	EventTypeAuthLogin        EventType = "auth.login"
	EventTypeAuthLogout       EventType = "auth.logout"
	EventTypeAuthFailure      EventType = "auth.failure"
	EventTypeAuthAPIKeyCreate EventType = "auth.apikey.create"
	EventTypeAuthAPIKeyDelete EventType = "auth.apikey.delete"

	EventTypeWAFBlock EventType = "waf.block"

	EventTypeRateLimitTrigger EventType = "rate_limit.trigger"
	EventTypeIPBlocked        EventType = "ip.blocked"

	EventTypeAdminAction EventType = "admin.action"

	EventTypeSecurityAlert EventType = "security.alert"

	EventTypeSessionCreate EventType = "session.create"
)

// Event represents an audit log event
type Event struct {
	Timestamp  time.Time   `json:"timestamp"`
	Type       EventType   `json:"type"`
	UserID     int         `json:"user_id,omitempty"`
	UserEmail  string      `json:"user_email,omitempty"`
	IP         string      `json:"ip"`
	UserAgent  string      `json:"user_agent,omitempty"`
	Resource   string      `json:"resource,omitempty"`
	ResourceID int         `json:"resource_id,omitempty"`
	Action     string      `json:"action,omitempty"`
	Details    interface{} `json:"details,omitempty"`
	Success    bool        `json:"success"`
	Error      string      `json:"error,omitempty"`
	RequestID  string      `json:"request_id,omitempty"`
	SessionID  string      `json:"session_id,omitempty"`
	Signature  string      `json:"signature,omitempty"` // HMAC signature for tamper detection
}

// Logger handles audit logging with rotation and external forwarding
type Logger struct {
	mu            sync.Mutex
	logFile       *os.File
	logPath       string
	maxSize       int64 // Max size in bytes before rotation
	maxBackups    int   // Max number of rotated files to keep
	currentSize   int64 // Current file size
	enabled       bool
	signingKey    []byte // HMAC signing key for log integrity
	webhookURL    string // External webhook URL for log forwarding
	webhookClient *http.Client
	alertHandler  *AlertHandler // Real-time alerting
}

const (
	defaultMaxSize    = 100 * 1024 * 1024 // 100MB
	defaultMaxBackups = 5
)

var (
	instance *Logger
	once     sync.Once
)

// Init initializes the audit logger
func Init(logPath string) error {
	var err error
	once.Do(func() {
		// Get signing key from environment or generate one
		signingKey := os.Getenv("KROXY_AUDIT_SIGNING_KEY")
		if signingKey == "" {
			// In production mode, require a signing key for log verification
			if os.Getenv("KROXY_PRODUCTION") == "true" {
				err = errors.New("KROXY_AUDIT_SIGNING_KEY must be set in production mode for log verification")
				return
			}
			// Generate a secure random key for this session (dev mode only)
			keyBytes := make([]byte, 32)
			if _, randErr := cryptoRand.Read(keyBytes); randErr != nil {
				log.Fatalf("audit: failed to generate signing key: %v", randErr)
			}
			signingKey = base64.StdEncoding.EncodeToString(keyBytes)
			log.Println("WARNING: Using random audit signing key (not persistent across restarts)")
		}

		webhookURL := os.Getenv("KROXY_AUDIT_WEBHOOK_URL")

		instance = &Logger{
			enabled:    true,
			signingKey: []byte(signingKey),
			logPath:    logPath,
			maxSize:    defaultMaxSize,
			maxBackups: defaultMaxBackups,
			webhookURL: webhookURL,
		}

		if webhookURL != "" {
			instance.webhookClient = &http.Client{Timeout: 5 * time.Second}
			log.Printf("Audit log forwarding enabled to: %s", webhookURL)
		}

		instance.alertHandler = NewAlertHandler()
		if logPath != "" {
			instance.logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
			if err == nil {
				// Get current file size for rotation tracking
				if info, statErr := instance.logFile.Stat(); statErr == nil {
					instance.currentSize = info.Size()
				}
			}
		}
	})
	return err
}

// GetLogger returns the singleton logger instance
func GetLogger() *Logger {
	if instance == nil {
		instance = &Logger{enabled: true}
	}
	return instance
}

// signEvent generates an HMAC signature for the event
func (l *Logger) signEvent(data []byte) string {
	if len(l.signingKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, l.signingKey)
	mac.Write(data)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Log writes an audit event
func (l *Logger) Log(event Event) {
	if !l.enabled {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Convert to JSON
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("audit: failed to marshal event: %v", err)
		return
	}

	// Sign the event for integrity
	signature := l.signEvent(data)

	// Add signature to the event
	event.Signature = signature

	// Re-marshal with signature
	data, err = json.Marshal(event)
	if err != nil {
		log.Printf("audit: failed to marshal signed event: %v", err)
		return
	}

	// Write to file if configured
	if l.logFile != nil {
		n, _ := l.logFile.Write(append(data, '\n'))
		l.currentSize += int64(n)

		// Rotate if file exceeds max size
		if l.currentSize >= l.maxSize {
			l.rotate()
		}
	}

	// Sanitize log output to prevent log injection
	// Remove newlines, control characters, and Unicode line separators that could corrupt logs
	sanitizedData := strings.ReplaceAll(string(data), "\n", "\\n")
	sanitizedData = strings.ReplaceAll(sanitizedData, "\r", "\\r")
	sanitizedData = strings.ReplaceAll(sanitizedData, "\t", "\\t")
	sanitizedData = strings.ReplaceAll(sanitizedData, "\u2028", "\\u2028") // Unicode Line Separator
	sanitizedData = strings.ReplaceAll(sanitizedData, "\u2029", "\\u2029") // Unicode Paragraph Separator
	sanitizedData = strings.ReplaceAll(sanitizedData, "\u0085", "\\u0085") // Unicode Next Line

	// Also log to stdout for container environments
	log.Printf("AUDIT: %s", sanitizedData)

	// Forward to external webhook (async, non-blocking)
	if l.webhookURL != "" && l.webhookClient != nil {
		go l.forwardToWebhook(data)
	}

	// Check alerting thresholds
	if l.alertHandler != nil {
		l.alertHandler.Check(event)
	}
}

// LogWAFBlock logs a WAF block
func (l *Logger) LogWAFBlock(ip, domain, ruleID, reason string) {
	l.Log(Event{
		Type:     EventTypeWAFBlock,
		IP:       ip,
		Resource: "waf",
		Action:   "block",
		Success:  true,
		Details: map[string]interface{}{
			"domain": domain,
			"rule":   ruleID,
			"reason": reason,
		},
	})
}

// LogSecurityAlert logs a security alert
func (l *Logger) LogSecurityAlert(alertType, ip, details string) {
	l.Log(Event{
		Type:    EventTypeSecurityAlert,
		IP:      ip,
		Action:  alertType,
		Success: false,
		Error:   details,
	})
}

// LogRateLimitTrigger logs rate limit being triggered
func (l *Logger) LogRateLimitTrigger(ip, domain string, requestsPerMinute int) {
	l.Log(Event{
		Type:     EventTypeRateLimitTrigger,
		IP:       ip,
		Resource: "rate_limit",
		Action:   "trigger",
		Success:  false,
		Details: map[string]interface{}{
			"domain":           domain,
			"requests_per_min": requestsPerMinute,
		},
	})
}

// forwardToWebhook sends an audit event to the configured webhook URL
func (l *Logger) forwardToWebhook(data []byte) {
	resp, err := l.webhookClient.Post(l.webhookURL, "application/json", strings.NewReader(string(data)))
	if err != nil {
		log.Printf("audit: webhook forwarding failed: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("audit: webhook returned status %d", resp.StatusCode)
	}
}

// AlertHandler monitors security events and triggers alerts when thresholds are exceeded
type AlertHandler struct {
	mu            sync.Mutex
	failedLogins  map[string]*alertCounter // IP -> counter
	wafBlocks     map[string]*alertCounter // IP -> counter
	alertCallback func(alertType, message string)
}

type alertCounter struct {
	count     int
	firstSeen time.Time
}

const (
	alertWindowDuration  = 5 * time.Minute
	failedLoginThreshold = 10
	wafBlockThreshold    = 50
)

// NewAlertHandler creates a new alert handler with default log-based alerting
func NewAlertHandler() *AlertHandler {
	return &AlertHandler{
		failedLogins: make(map[string]*alertCounter),
		wafBlocks:    make(map[string]*alertCounter),
		alertCallback: func(alertType, message string) {
			log.Printf("SECURITY ALERT [%s]: %s", alertType, message)
		},
	}
}

// Check evaluates an audit event against alerting thresholds
func (ah *AlertHandler) Check(event Event) {
	ah.mu.Lock()
	defer ah.mu.Unlock()

	now := time.Now()

	switch event.Type {
	case EventTypeAuthFailure:
		ip := event.IP
		if ip == "" {
			return
		}
		counter, ok := ah.failedLogins[ip]
		if !ok || now.Sub(counter.firstSeen) > alertWindowDuration {
			ah.failedLogins[ip] = &alertCounter{count: 1, firstSeen: now}
			return
		}
		counter.count++
		if counter.count == failedLoginThreshold {
			ah.alertCallback("brute_force",
				fmt.Sprintf("%d failed login attempts from IP %s in %v", counter.count, ip, alertWindowDuration))
		}

	case EventTypeWAFBlock:
		ip := event.IP
		if ip == "" {
			return
		}
		counter, ok := ah.wafBlocks[ip]
		if !ok || now.Sub(counter.firstSeen) > alertWindowDuration {
			ah.wafBlocks[ip] = &alertCounter{count: 1, firstSeen: now}
			return
		}
		counter.count++
		if counter.count == wafBlockThreshold {
			ah.alertCallback("waf_flood",
				fmt.Sprintf("%d WAF blocks from IP %s in %v", counter.count, ip, alertWindowDuration))
		}

	case EventTypeIPBlocked:
		ah.alertCallback("ip_banned",
			fmt.Sprintf("IP %s was banned: %s", event.IP, event.Error))

	case EventTypeAdminAction:
		if event.Action == "admin_token_created" {
			ah.alertCallback("admin_token",
				fmt.Sprintf("New admin token created by user %d from IP %s", event.UserID, event.IP))
		}
	}
}

// rotate performs log file rotation. Must be called with l.mu held.
func (l *Logger) rotate() {
	if l.logFile == nil || l.logPath == "" {
		return
	}

	l.logFile.Close()

	// Shift existing backups: .4 -> .5, .3 -> .4, etc.
	for i := l.maxBackups - 1; i > 0; i-- {
		src := fmt.Sprintf("%s.%d", l.logPath, i)
		dst := fmt.Sprintf("%s.%d", l.logPath, i+1)
		os.Rename(src, dst)
	}

	// Rename current log to .1
	os.Rename(l.logPath, l.logPath+".1")

	// Remove oldest backup if over limit
	oldest := fmt.Sprintf("%s.%d", l.logPath, l.maxBackups+1)
	os.Remove(oldest)

	// Open new log file
	var err error
	l.logFile, err = os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("audit: failed to open new log file after rotation: %v", err)
		l.logFile = nil
	}
	l.currentSize = 0
}
