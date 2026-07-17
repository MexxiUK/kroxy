package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

// capturingLogger is a test-only Logger variant that records every Event passed
// to Log instead of writing to disk/network.
type capturingLogger struct {
	Logger
	events []Event
}

func (l *capturingLogger) Log(event Event) {
	l.events = append(l.events, event)
}

func TestAuditEvent_SuccessFlagDefaultsToFalse(t *testing.T) {
	l := &capturingLogger{}

	l.Log(Event{
		Type: "test_event",
		IP:   "127.0.0.1",
	})

	if len(l.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(l.events))
	}
	if l.events[0].Success {
		t.Fatalf("zero value Success should be false")
	}
}

func TestAuditEvent_MarshalsSuccess(t *testing.T) {
	e := Event{
		Type:    "test_event",
		IP:      "127.0.0.1",
		Success: true,
	}

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"success":true`) {
		t.Fatalf("expected success:true in JSON, got %s", string(b))
	}
}
