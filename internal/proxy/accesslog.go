package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AccessLogEntry represents a single access log entry.
type AccessLogEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	Method       string    `json:"method"`
	Host         string    `json:"host"`
	URI          string    `json:"uri"`
	RemoteAddr   string    `json:"remote_addr"`
	UserAgent    string    `json:"user_agent"`
	StatusCode   int       `json:"status_code"`
	ResponseSize int64     `json:"response_size"`
	Duration     int64     `json:"duration_ms"`
	RouteID      int       `json:"route_id,omitempty"`
	WAFAction    string    `json:"waf_action,omitempty"`
	BotScore     float64   `json:"bot_score,omitempty"`
}

// LogStore holds recent access logs in memory with rotation.
type LogStore struct {
	mu       sync.RWMutex
	entries  []AccessLogEntry
	maxSize  int
	logFile  *os.File
}

const maxLogEntries = 10000

// NewLogStore creates an access log store.
func NewLogStore(logPath string) (*LogStore, error) {
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create log dir: %w", err)
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("failed to open access log: %w", err)
	}

	return &LogStore{
		entries: make([]AccessLogEntry, 0, maxLogEntries),
		maxSize: maxLogEntries,
		logFile: f,
	}, nil
}

// Log records an access log entry.
func (ls *LogStore) Log(entry AccessLogEntry) {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	// Add to in-memory buffer
	ls.entries = append(ls.entries, entry)
	if len(ls.entries) > ls.maxSize {
		ls.entries = ls.entries[len(ls.entries)-ls.maxSize:]
	}

	// Write to file
	if ls.logFile != nil {
		line, _ := json.Marshal(entry)
		ls.logFile.Write(line)
		ls.logFile.Write([]byte("\n"))
	}
}

// Query returns log entries matching filters.
func (ls *LogStore) Query(limit int, host, method string, since time.Time) []AccessLogEntry {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var result []AccessLogEntry
	// Iterate in reverse (newest first)
	for i := len(ls.entries) - 1; i >= 0 && len(result) < limit; i-- {
		e := ls.entries[i]
		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		if host != "" && !strings.Contains(e.Host, host) {
			continue
		}
		if method != "" && e.Method != method {
			continue
		}
		result = append(result, e)
	}
	return result
}

// Stats returns aggregate stats for a time period.
func (ls *LogStore) Stats(since time.Time) LogStats {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	stats := LogStats{
		StatusCodes: make(map[int]int),
		Hosts:       make(map[string]int),
	}

	for _, e := range ls.entries {
		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		stats.TotalRequests++
		stats.StatusCodes[e.StatusCode]++
		stats.Hosts[e.Host]++
		if e.WAFAction == "blocked" {
			stats.WAFBlocks++
		}
		if e.Duration > stats.MaxDuration {
			stats.MaxDuration = e.Duration
		}
		stats.TotalDuration += e.Duration
	}

	if stats.TotalRequests > 0 {
		stats.AvgDuration = stats.TotalDuration / int64(stats.TotalRequests)
	}

	// Top hosts
	var hostList []HostCount
	for h, c := range stats.Hosts {
		hostList = append(hostList, HostCount{Host: h, Count: c})
	}
	sort.Slice(hostList, func(i, j int) bool {
		return hostList[i].Count > hostList[j].Count
	})
	if len(hostList) > 10 {
		hostList = hostList[:10]
	}
	stats.TopHosts = hostList

	return stats
}

// HostCount represents a host and its request count.
type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// LogStats holds aggregated log statistics.
type LogStats struct {
	TotalRequests int64         `json:"total_requests"`
	WAFBlocks     int64         `json:"waf_blocks"`
	AvgDuration   int64         `json:"avg_duration_ms"`
	MaxDuration   int64         `json:"max_duration_ms"`
	TotalDuration int64         `json:"total_duration_ms"`
	StatusCodes   map[int]int   `json:"status_codes"`
	Hosts         map[string]int `json:"hosts,omitempty"`
	TopHosts      []HostCount   `json:"top_hosts,omitempty"`
}

// Close closes the log file.
func (ls *LogStore) Close() error {
	if ls.logFile != nil {
		return ls.logFile.Close()
	}
	return nil
}

var globalLogStore *LogStore

// SetGlobalLogStore sets the global access log store.
func SetGlobalLogStore(ls *LogStore) {
	globalLogStore = ls
}

// GetGlobalLogStore returns the global access log store.
func GetGlobalLogStore() *LogStore {
	return globalLogStore
}

// LogAccess is a convenience function to log an access entry.
func LogAccess(entry AccessLogEntry) {
	if globalLogStore != nil {
		globalLogStore.Log(entry)
	}
}