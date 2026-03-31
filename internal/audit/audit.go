package audit

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

// EventType represents the type of audit event
type EventType string

const (
	EventTypeAuthLogin       EventType = "auth.login"
	EventTypeAuthLogout      EventType = "auth.logout"
	EventTypeAuthFailure     EventType = "auth.failure"
	EventTypeAuthAPIKeyCreate EventType = "auth.apikey.create"
	EventTypeAuthAPIKeyDelete EventType = "auth.apikey.delete"

	EventTypeRouteCreate  EventType = "route.create"
	EventTypeRouteUpdate  EventType = "route.update"
	EventTypeRouteDelete  EventType = "route.delete"

	EventTypeOIDCProviderCreate EventType = "oidc.provider.create"
	EventTypeOIDCProviderDelete EventType = "oidc.provider.delete"

	EventTypeWAFBlock     EventType = "waf.block"
	EventTypeWAFRuleAdd  EventType = "waf.rule.add"
	EventTypeWAFRuleDel  EventType = "waf.rule.delete"

	EventTypeRateLimitTrigger EventType = "rate_limit.trigger"
	EventTypeIPBlocked        EventType = "ip.blocked"
	EventTypeIPUnblocked      EventType = "ip.unblocked"

	EventTypeConfigChange EventType = "config.change"
	EventTypeAdminAction  EventType = "admin.action"

	EventTypeSecurityAlert EventType = "security.alert"
)

// Event represents an audit log event
type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	Type        EventType              `json:"type"`
	UserID      int                    `json:"user_id,omitempty"`
	UserEmail   string                 `json:"user_email,omitempty"`
	IP          string                 `json:"ip"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Resource    string                 `json:"resource,omitempty"`
	ResourceID  int                    `json:"resource_id,omitempty"`
	Action      string                 `json:"action,omitempty"`
	Details interface{} `json:"details,omitempty"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
}

// Logger handles audit logging
type Logger struct {
	mu      sync.Mutex
	logFile *os.File
	enabled bool
}

var (
	instance *Logger
	once     sync.Once
)

// Init initializes the audit logger
func Init(logPath string) error {
	var err error
	once.Do(func() {
		instance = &Logger{enabled: true}
		if logPath != "" {
			instance.logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
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

	// Write to file if configured
	if l.logFile != nil {
		l.logFile.Write(append(data, '\n'))
	}

	// Also log to stdout for container environments
	log.Printf("AUDIT: %s", string(data))
}

// LogAuthLogin logs a successful login
func (l *Logger) LogAuthLogin(userID int, email, ip, userAgent, sessionID string) {
	l.Log(Event{
		Type:      EventTypeAuthLogin,
		UserID:    userID,
		UserEmail: email,
		IP:        ip,
		UserAgent: userAgent,
		SessionID: sessionID,
		Action:    "login",
		Success:   true,
	})
}

// LogAuthFailure logs a failed login attempt
func (l *Logger) LogAuthFailure(email, ip, userAgent, reason string) {
	l.Log(Event{
		Type:      EventTypeAuthFailure,
		UserEmail: email,
		IP:        ip,
		UserAgent: userAgent,
		Action:    "login",
		Success:   false,
		Error:     reason,
	})
}

// LogAuthLogout logs a logout
func (l *Logger) LogAuthLogout(userID int, email, ip, sessionID string) {
	l.Log(Event{
		Type:      EventTypeAuthLogout,
		UserID:    userID,
		UserEmail: email,
		IP:        ip,
		SessionID: sessionID,
		Action:    "logout",
		Success:   true,
	})
}

// LogRouteCreate logs route creation
func (l *Logger) LogRouteCreate(userID int, ip, domain, backend string) {
	l.Log(Event{
		Type:       EventTypeRouteCreate,
		UserID:     userID,
		IP:         ip,
		Resource:   "route",
		Action:     "create",
		Success:    true,
		Details: map[string]interface{}{
			"domain":  domain,
			"backend": backend,
		},
	})
}

// LogRouteDelete logs route deletion
func (l *Logger) LogRouteDelete(userID int, ip, domain string, routeID int) {
	l.Log(Event{
		Type:       EventTypeRouteDelete,
		UserID:     userID,
		IP:         ip,
		Resource:   "route",
		ResourceID: routeID,
		Action:     "delete",
		Success:    true,
		Details: map[string]interface{}{
			"domain": domain,
		},
	})
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
		Type:      EventTypeSecurityAlert,
		IP:        ip,
		Action:    alertType,
		Success:   false,
		Error:     details,
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
			"domain":            domain,
			"requests_per_min": requestsPerMinute,
		},
	})
}

// LogConfigChange logs configuration changes
func (l *Logger) LogConfigChange(userID int, ip, resource, action string, changes map[string]interface{}) {
	l.Log(Event{
		Type:     EventTypeConfigChange,
		UserID:   userID,
		IP:       ip,
		Resource: resource,
		Action:   action,
		Success:  true,
		Details:  changes,
	})
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// Enabled returns whether audit logging is enabled
func (l *Logger) Enabled() bool {
	return l.enabled
}

// SetEnabled enables or disables audit logging
func (l *Logger) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}