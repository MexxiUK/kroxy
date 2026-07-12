package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewLogStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "access.log")
	ls, err := NewLogStore(logPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	defer ls.Close()

	if ls.logFile == nil {
		t.Error("expected log file to be open")
	}
	if len(ls.entries) != 0 {
		t.Error("expected empty entries")
	}
	if ls.maxSize != maxLogEntries {
		t.Errorf("expected maxSize %d, got %d", maxLogEntries, ls.maxSize)
	}
}

func TestNewLogStore_CreateDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	nestedPath := filepath.Join(tmpDir, "nested", "deep", "access.log")
	ls, err := NewLogStore(nestedPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	// #nosec G104 — test cleanup.
	ls.Close()

	if _, err := os.Stat(filepath.Dir(nestedPath)); err != nil {
		t.Errorf("expected nested dir to exist: %v", err)
	}
}

func TestLogStore_Log(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "access.log")
	ls, err := NewLogStore(logPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	defer ls.Close()

	entry := AccessLogEntry{
		Timestamp:  time.Now(),
		Method:     "GET",
		Host:       "example.com",
		URI:        "/test",
		RemoteAddr: "127.0.0.1",
		StatusCode: 200,
		Duration:   42,
	}
	ls.Log(entry)

	if len(ls.entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(ls.entries))
	}

	// Verify file was written
	// #nosec G304 — logPath is a fixed temporary path created by this test.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	var fileEntry AccessLogEntry
	if err := json.Unmarshal(data, &fileEntry); err != nil {
		t.Fatalf("unmarshal log line: %v", err)
	}
	if fileEntry.Method != "GET" {
		t.Errorf("expected GET, got %s", fileEntry.Method)
	}
}

func TestLogStore_Log_Rotation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "access.log")
	ls, err := NewLogStore(logPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	defer ls.Close()

	// Fill beyond max
	for i := 0; i < maxLogEntries+10; i++ {
		ls.Log(AccessLogEntry{Timestamp: time.Now(), Method: "GET", StatusCode: 200})
	}

	if len(ls.entries) != maxLogEntries {
		t.Errorf("expected entries capped at %d, got %d", maxLogEntries, len(ls.entries))
	}
}

func TestLogStore_Query(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "access.log")
	ls, err := NewLogStore(logPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	defer ls.Close()

	now := time.Now()
	ls.Log(AccessLogEntry{Timestamp: now, Method: "GET", Host: "a.com", StatusCode: 200})
	ls.Log(AccessLogEntry{Timestamp: now.Add(-time.Hour), Method: "POST", Host: "b.com", StatusCode: 201})
	ls.Log(AccessLogEntry{Timestamp: now, Method: "GET", Host: "b.com", StatusCode: 404})

	// Query all, newest first
	result := ls.Query(10, "", "", time.Time{})
	if len(result) != 3 {
		t.Errorf("expected 3 results, got %d", len(result))
	}
	// Newest first
	if result[0].StatusCode != 404 {
		t.Errorf("expected newest (404), got %d", result[0].StatusCode)
	}

	// Filter by host
	result = ls.Query(10, "a.com", "", time.Time{})
	if len(result) != 1 {
		t.Errorf("expected 1 result for a.com, got %d", len(result))
	}

	// Filter by method
	result = ls.Query(10, "", "POST", time.Time{})
	if len(result) != 1 {
		t.Errorf("expected 1 POST result, got %d", len(result))
	}

	// Filter by since
	result = ls.Query(10, "", "", now.Add(-30*time.Minute))
	if len(result) != 2 {
		t.Errorf("expected 2 results since 30m ago, got %d", len(result))
	}

	// Limit
	result = ls.Query(2, "", "", time.Time{})
	if len(result) != 2 {
		t.Errorf("expected 2 results with limit=2, got %d", len(result))
	}
}

func TestLogStore_Query_LimitBounds(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "access.log")
	ls, err := NewLogStore(logPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	defer ls.Close()

	for i := 0; i < 200; i++ {
		ls.Log(AccessLogEntry{Timestamp: time.Now(), Method: "GET", StatusCode: 200})
	}

	// limit <= 0 should default to 100
	result := ls.Query(0, "", "", time.Time{})
	if len(result) != 100 {
		t.Errorf("expected default limit 100, got %d", len(result))
	}

	// limit > 1000 should cap at 100
	result = ls.Query(2000, "", "", time.Time{})
	if len(result) != 100 {
		t.Errorf("expected cap at 100, got %d", len(result))
	}
}

func TestLogStore_Stats(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "access.log")
	ls, err := NewLogStore(logPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	defer ls.Close()

	now := time.Now()
	ls.Log(AccessLogEntry{Timestamp: now, Method: "GET", Host: "a.com", StatusCode: 200, Duration: 100, WAFAction: "blocked"})
	ls.Log(AccessLogEntry{Timestamp: now, Method: "GET", Host: "a.com", StatusCode: 200, Duration: 200})
	ls.Log(AccessLogEntry{Timestamp: now.Add(-time.Hour), Method: "POST", Host: "b.com", StatusCode: 500, Duration: 50})

	stats := ls.Stats(time.Time{})
	if stats.TotalRequests != 3 {
		t.Errorf("expected 3 total requests, got %d", stats.TotalRequests)
	}
	if stats.WAFBlocks != 1 {
		t.Errorf("expected 1 WAF block, got %d", stats.WAFBlocks)
	}
	if stats.AvgDuration != 116 {
		t.Errorf("expected avg duration 116, got %d", stats.AvgDuration)
	}
	if stats.MaxDuration != 200 {
		t.Errorf("expected max duration 200, got %d", stats.MaxDuration)
	}
	if stats.StatusCodes[200] != 2 {
		t.Errorf("expected 2x 200, got %d", stats.StatusCodes[200])
	}
	if stats.StatusCodes[500] != 1 {
		t.Errorf("expected 1x 500, got %d", stats.StatusCodes[500])
	}
	if len(stats.TopHosts) != 2 {
		t.Errorf("expected 2 top hosts, got %d", len(stats.TopHosts))
	}
	if stats.TopHosts[0].Host != "a.com" || stats.TopHosts[0].Count != 2 {
		t.Errorf("expected a.com first with count 2, got %v", stats.TopHosts[0])
	}

	// Stats with since filter
	stats = ls.Stats(now.Add(-30 * time.Minute))
	if stats.TotalRequests != 2 {
		t.Errorf("expected 2 requests since 30m ago, got %d", stats.TotalRequests)
	}
}

func TestLogStore_Stats_Empty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "access.log")
	ls, err := NewLogStore(logPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	defer ls.Close()

	stats := ls.Stats(time.Time{})
	if stats.TotalRequests != 0 {
		t.Errorf("expected 0 requests, got %d", stats.TotalRequests)
	}
	if stats.AvgDuration != 0 {
		t.Errorf("expected 0 avg duration, got %d", stats.AvgDuration)
	}
	if len(stats.TopHosts) != 0 {
		t.Errorf("expected 0 top hosts, got %d", len(stats.TopHosts))
	}
}

func TestLogStore_Close(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "access.log")
	ls, err := NewLogStore(logPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}

	if err := ls.Close(); err != nil {
		t.Errorf("expected no error closing, got %v", err)
	}

	// Second close should not panic (may return error because file already closed)
	_ = ls.Close()
}

func TestGlobalLogStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "accesslog-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "access.log")
	ls, err := NewLogStore(logPath)
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	defer ls.Close()

	SetGlobalLogStore(ls)
	defer SetGlobalLogStore(nil)

	if GetGlobalLogStore() != ls {
		t.Error("expected global log store to match")
	}

	// LogAccess should write to global store
	LogAccess(AccessLogEntry{Method: "GET", StatusCode: 200})
	if len(ls.entries) != 1 {
		t.Errorf("expected 1 entry after LogAccess, got %d", len(ls.entries))
	}

	// LogAccess with nil global should not panic
	SetGlobalLogStore(nil)
	LogAccess(AccessLogEntry{Method: "GET", StatusCode: 200})
}
