package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/kroxy/kroxy/internal/alerts"
	"github.com/kroxy/kroxy/internal/store"
)

// HealthChecker monitors backend health for all routes.
type HealthChecker struct {
	store    *store.Store
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.RWMutex
	statuses map[int]HealthStatus // routeID -> status
	interval time.Duration
	client   *http.Client
}

// HealthStatus represents the health of a backend.
type HealthStatus struct {
	RouteID      int       `json:"route_id"`
	Domain       string    `json:"domain"`
	Backend      string    `json:"backend"`
	Healthy      bool      `json:"healthy"`
	LastChecked  time.Time `json:"last_checked"`
	LastSuccess  time.Time `json:"last_success,omitempty"`
	FailCount    int       `json:"fail_count"`
	ResponseTime int64     `json:"response_time_ms"`
	Error        string    `json:"error,omitempty"`
}

const healthCheckInterval = 30 * time.Second
const healthCheckTimeout = 10 * time.Second

// NewHealthChecker creates a health checker.
func NewHealthChecker(s *store.Store) *HealthChecker {
	return &HealthChecker{
		store:    s,
		statuses: make(map[int]HealthStatus),
		interval: healthCheckInterval,
		client: &http.Client{
			Timeout: healthCheckTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Start begins health checking in the background.
func (hc *HealthChecker) Start(ctx context.Context) {
	// Cancel any existing context to prevent goroutine leaks on restart
	if hc.cancel != nil {
		hc.cancel()
	}
	ctx, cancel := context.WithCancel(ctx)
	hc.cancel = cancel

	// Initial check
	hc.checkAll()

	hc.wg.Add(1)
	go func() {
		defer hc.wg.Done()
		ticker := time.NewTicker(hc.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				hc.checkAll()
			}
		}
	}()
}

// Stop halts health checking.
func (hc *HealthChecker) Stop() {
	if hc.cancel != nil {
		hc.cancel()
	}
	hc.wg.Wait()
}

// GetStatus returns the health status for a route.
func (hc *HealthChecker) GetStatus(routeID int) (HealthStatus, bool) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	s, ok := hc.statuses[routeID]
	return s, ok
}

// GetAllStatuses returns all health statuses.
func (hc *HealthChecker) GetAllStatuses() []HealthStatus {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	result := make([]HealthStatus, 0, len(hc.statuses))
	for _, s := range hc.statuses {
		result = append(result, s)
	}
	return result
}

func (hc *HealthChecker) checkAll() {
	routes, err := hc.store.GetRoutes()
	if err != nil {
		log.Printf("HealthChecker: failed to get routes: %v", err)
		return
	}

	var wg sync.WaitGroup
	for _, route := range routes {
		if !route.Enabled || route.IsAdminRoute {
			continue
		}
		wg.Add(1)
		go func(r store.Route) {
			defer wg.Done()
			hc.checkRoute(r)
		}(route)
	}
	wg.Wait()
}

func (hc *HealthChecker) checkRoute(route store.Route) {
	start := time.Now()
	status := HealthStatus{
		RouteID:     route.ID,
		Domain:      route.Domain,
		Backend:     route.Backend,
		LastChecked: start,
	}

	req, err := http.NewRequest("GET", route.Backend, nil)
	if err != nil {
		status.Error = fmt.Sprintf("invalid backend URL: %v", err)
		hc.setStatusWithFailCount(&status)
		return
	}
	req.Header.Set("User-Agent", "Kroxy-HealthCheck/1.0")
	req.Header.Set("X-Kroxy-Health-Check", "true")

	resp, err := hc.client.Do(req)
	status.ResponseTime = time.Since(start).Milliseconds()
	if err != nil {
		status.Error = fmt.Sprintf("connection failed: %v", err)
		hc.setStatusWithFailCount(&status)
		return
	}
	defer resp.Body.Close()

	// Consider 2xx and 3xx as healthy, 401/403 as healthy (reachable, needs auth)
	// All other 4xx/5xx as unhealthy
	if resp.StatusCode >= 200 && resp.StatusCode < 500 && resp.StatusCode != 404 {
		status.Healthy = true
		status.LastSuccess = time.Now()
		status.FailCount = 0
	} else {
		status.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		hc.setStatusWithFailCount(&status)
		return
	}

	hc.setStatus(status)
}

// setStatus writes a health status atomically.
func (hc *HealthChecker) setStatus(status HealthStatus) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.statuses[status.RouteID] = status
}

// setStatusWithFailCount atomically increments the fail count and stores the
// new status under a single lock, preventing the race between increment and write.
func (hc *HealthChecker) setStatusWithFailCount(status *HealthStatus) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if s, ok := hc.statuses[status.RouteID]; ok {
		status.FailCount = s.FailCount + 1
	} else {
		status.FailCount = 1
	}
	hc.statuses[status.RouteID] = *status

	// Alert on backend down after 2 consecutive failures
	if !status.Healthy && status.FailCount >= 2 {
		if am := alerts.GetGlobalManager(); am != nil {
			am.BackendDown(status.RouteID, status.Domain, status.Backend, fmt.Errorf("%s", status.Error))
		}
	}
}

var globalHealthChecker *HealthChecker

// SetGlobalHealthChecker sets the global health checker instance.
func SetGlobalHealthChecker(hc *HealthChecker) {
	globalHealthChecker = hc
}

// GetGlobalHealthChecker returns the global health checker.
func GetGlobalHealthChecker() *HealthChecker {
	return globalHealthChecker
}
