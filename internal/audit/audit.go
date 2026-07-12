package audit

import (
	"encoding/json"
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
	EventTypeAuthAPIKeyCreate EventType = "auth.apikey.create" // #nosec G101 — event type constant, not a credential
	EventTypeAuthAPIKeyDelete EventType = "auth.apikey.delete" // #nosec G101 — event type constant, not a credential

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
	webhookURL    string // External webhook URL for log forwarding
	webhookClient *http.Client
	alertHandler  *AlertHandler // Real-time alerting
	webhookCh     chan []byte   // Buffered channel for async webhook forwarding
	webhookOnce   sync.Once     // Ensures webhook worker starts once
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
		webhookURL := os.Getenv("KROXY_AUDIT_WEBHOOK_URL")

		instance = &Logger{
			enabled:    true,
			logPath:    logPath,
			maxSize:    defaultMaxSize,
			maxBackups: defaultMaxBackups,
			webhookURL: webhookURL,
			webhookCh:  make(chan []byte, 100),
		}

		if webhookURL != "" {
			instance.webhookClient = &http.Client{Timeout: 5 * time.Second}
			log.Printf("Audit log forwarding enabled to: %s", webhookURL) // #nosec G706 — webhookURL is from server-side configuration
		}

		instance.alertHandler = NewAlertHandler()
		if logPath != "" {
			instance.logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 — logPath is from server-side configuration
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

// sensitiveFieldNames contains substrings that indicate a field should be redacted
// from stdout logging to avoid leaking credentials into container logs.
var sensitiveFieldNames = []string{"password", "secret", "token", "key", "seed", "credential", "cookie"}

// redactDetails returns a copy of the event with known sensitive fields in Details masked.
func redactDetails(event Event) Event {
	if event.Details == nil {
		return event
	}
	details, ok := event.Details.(map[string]interface{})
	if !ok {
		return event
	}
	redacted := make(map[string]interface{}, len(details))
	for k, v := range details {
		lower := strings.ToLower(k)
		mask := false
		for _, s := range sensitiveFieldNames {
			if strings.Contains(lower, s) {
				mask = true
				break
			}
		}
		if mask {
			redacted[k] = "[REDACTED]"
		} else {
			redacted[k] = v
		}
	}
	event.Details = redacted
	return event
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

	// Full event written to the append-only log file and forwarded to webhooks
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("audit: failed to marshal event: %v", err)
		return
	}

	// Write to file if configured
	if l.logFile != nil {
		n, err := l.logFile.Write(append(data, '\n'))
		if err != nil {
			log.Printf("audit: failed to write audit log: %v", err)
			// Continue to stdout/webhook fallback below; do not return so the
			// event still reaches other sinks.
		} else {
			l.currentSize += int64(n)
			// Rotate if file exceeds max size
			if l.currentSize >= l.maxSize {
				if rotErr := l.rotate(); rotErr != nil {
					log.Printf("audit: failed to rotate audit log: %v", rotErr)
				}
			}
		}
	}

	// Redact sensitive fields before emitting to stdout (container logs)
	safeEvent := redactDetails(event)
	safeData, err := json.Marshal(safeEvent)
	if err != nil {
		log.Printf("audit: failed to marshal safe event: %v", err)
		return
	}

	// Sanitize log output to prevent log injection
	// Remove newlines, control characters, and Unicode line separators that could corrupt logs
	sanitizedData := strings.ReplaceAll(string(safeData), "\n", "\\n")
	sanitizedData = strings.ReplaceAll(sanitizedData, "\r", "\\r")
	sanitizedData = strings.ReplaceAll(sanitizedData, "\t", "\\t")
	sanitizedData = strings.ReplaceAll(sanitizedData, "\u2028", "\\u2028") // Unicode Line Separator
	sanitizedData = strings.ReplaceAll(sanitizedData, "\u2029", "\\u2029") // Unicode Paragraph Separator
	sanitizedData = strings.ReplaceAll(sanitizedData, "\u0085", "\\u0085") // Unicode Next Line

	// Also log to stdout for container environments
	log.Printf("AUDIT: %s", sanitizedData)

	// Forward to external webhook (async, non-blocking)
	if l.webhookURL != "" && l.webhookClient != nil {
		l.enqueueWebhook(data)
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

// enqueueWebhook drops events into a buffered channel; if full, new events are dropped.
func (l *Logger) enqueueWebhook(data []byte) {
	l.webhookOnce.Do(l.startWebhookWorker)
	select {
	case l.webhookCh <- data:
	default:
		log.Println("audit: webhook buffer full, dropping event")
	}
}

func (l *Logger) startWebhookWorker() {
	go l.webhookWorker()
}

func (l *Logger) webhookWorker() {
	for data := range l.webhookCh {
		l.forwardToWebhook(data)
	}
}

// forwardToWebhook sends an audit event to the configured webhook URL
func (l *Logger) forwardToWebhook(data []byte) {
	resp, err := l.webhookClient.Post(l.webhookURL, "application/json", strings.NewReader(string(data)))
	if err != nil {
		log.Printf("audit: webhook forwarding failed: %v", err)
		return
	}
	// #nosec G104 — best-effort close of webhook response body.
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
	ah := &AlertHandler{
		failedLogins: make(map[string]*alertCounter),
		wafBlocks:    make(map[string]*alertCounter),
		alertCallback: func(alertType, message string) {
			log.Printf("SECURITY ALERT [%s]: %s", alertType, message)
		},
	}
	go ah.cleanupLoop()
	return ah
}

// cleanupLoop periodically evicts stale per-IP counters to prevent
// unbounded memory growth from distributed attackers.
func (ah *AlertHandler) cleanupLoop() {
	ticker := time.NewTicker(alertWindowDuration)
	defer ticker.Stop()
	for range ticker.C {
		ah.evictStaleCounters()
	}
}

func (ah *AlertHandler) evictStaleCounters() {
	ah.mu.Lock()
	defer ah.mu.Unlock()

	cutoff := time.Now().Add(-alertWindowDuration)
	for ip, c := range ah.failedLogins {
		if c.firstSeen.Before(cutoff) {
			delete(ah.failedLogins, ip)
		}
	}
	for ip, c := range ah.wafBlocks {
		if c.firstSeen.Before(cutoff) {
			delete(ah.wafBlocks, ip)
		}
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
// Returns the first error encountered; the caller logs it and continues.
func (l *Logger) rotate() error {
	if l.logFile == nil || l.logPath == "" {
		return nil
	}

	var firstErr error

	if err := l.logFile.Close(); err != nil {
		firstErr = fmt.Errorf("failed to close audit log for rotation: %w", err)
	}

	// Shift existing backups: .4 -> .5, .3 -> .4, etc.
	for i := l.maxBackups - 1; i > 0; i-- {
		src := fmt.Sprintf("%s.%d", l.logPath, i)
		dst := fmt.Sprintf("%s.%d", l.logPath, i+1)
		if err := os.Rename(src, dst); err != nil && firstErr == nil && !os.IsNotExist(err) {
			firstErr = fmt.Errorf("failed to shift backup %s: %w", src, err)
		}
	}

	// Rename current log to .1
	if err := os.Rename(l.logPath, l.logPath+".1"); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("failed to rotate audit log: %w", err)
	}

	// Remove oldest backup if over limit
	oldest := fmt.Sprintf("%s.%d", l.logPath, l.maxBackups+1)
	// #nosec G104 — best-effort cleanup of rotated audit log backup.
	os.Remove(oldest)

	// Open new log file
	f, err := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 — logPath is from server-side configuration
	if err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("failed to open new audit log: %w", err)
		}
		l.logFile = nil
	} else {
		l.logFile = f
	}
	l.currentSize = 0
	return firstErr
}
