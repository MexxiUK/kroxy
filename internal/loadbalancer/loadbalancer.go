package loadbalancer

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// LoadBalancer manages multiple backend servers with health checking
type LoadBalancer struct {
	backends sync.Map // map[int]*BackendPool
}

// BackendPool represents a pool of backends for a single route
type BackendPool struct {
	mu       sync.RWMutex
	backends []*Backend
	current  uint64 // round-robin counter
}

// Backend represents a single backend server
type Backend struct {
	URL        string
	Healthy    bool
	LastCheck  time.Time
	LastError  error
}

// HealthCheckConfig holds health check configuration
type HealthCheckConfig struct {
	Enabled  bool
	Interval time.Duration
	Timeout  time.Duration
	Path     string
	Expected int // expected status code
}

// New creates a new LoadBalancer
func New() *LoadBalancer {
	return &LoadBalancer{}
}

// AddBackend adds a backend to a route's pool
func (lb *LoadBalancer) AddBackend(routeID int, url string) error {
	pool := lb.getPool(routeID)
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pool.backends = append(pool.backends, &Backend{
		URL:     url,
		Healthy: true, // assume healthy until check
	})

	return nil
}

// RemoveBackend removes a backend from a route's pool
func (lb *LoadBalancer) RemoveBackend(routeID int, url string) error {
	pool := lb.getPool(routeID)
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for i, b := range pool.backends {
		if b.URL == url {
			pool.backends = append(pool.backends[:i], pool.backends[i+1:]...)
			break
		}
	}

	return nil
}

// NextBackend returns the next healthy backend (round-robin)
func (lb *LoadBalancer) NextBackend(routeID int) (*Backend, error) {
	pool := lb.getPool(routeID)
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	if len(pool.backends) == 0 {
		return nil, fmt.Errorf("no backends configured for route %d", routeID)
	}

	// Get healthy backends
	var healthy []*Backend
	for _, b := range pool.backends {
		if b.Healthy {
			healthy = append(healthy, b)
		}
	}

	if len(healthy) == 0 {
		return nil, fmt.Errorf("no healthy backends for route %d", routeID)
	}

	// Round-robin selection
	idx := atomic.AddUint64(&pool.current, 1) - 1
	return healthy[idx%uint64(len(healthy))], nil
}

// StartHealthChecks starts periodic health checks for all backends
func (lb *LoadBalancer) StartHealthChecks(ctx context.Context, cfg HealthCheckConfig) {
	if !cfg.Enabled {
		return
	}

	go func() {
		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lb.checkAllBackends(cfg)
			}
		}
	}()
}

func (lb *LoadBalancer) checkAllBackends(cfg HealthCheckConfig) {
	lb.backends.Range(func(key, value interface{}) bool {
		pool := value.(*BackendPool)

		var wg sync.WaitGroup
		pool.mu.Lock()
		for _, backend := range pool.backends {
			wg.Add(1)
			go func(b *Backend) {
				defer wg.Done()
				lb.checkBackend(b, cfg)
			}(backend)
		}
		pool.mu.Unlock()
		wg.Wait()

		return true
	})
}

func (lb *LoadBalancer) checkBackend(backend *Backend, cfg HealthCheckConfig) {
	client := &http.Client{
		Timeout: cfg.Timeout,
	}

	url := backend.URL + cfg.Path
	resp, err := client.Get(url)

	backend.LastCheck = time.Now()

	if err != nil {
		backend.Healthy = false
		backend.LastError = err
		log.Printf("Backend %s health check failed: %v", backend.URL, err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		backend.Healthy = false
		backend.LastError = fmt.Errorf("status code %d", resp.StatusCode)
		log.Printf("Backend %s unhealthy: status %d", backend.URL, resp.StatusCode)
		return
	}

	backend.Healthy = true
	backend.LastError = nil
	log.Printf("Backend %s healthy", backend.URL)
}

func (lb *LoadBalancer) getPool(routeID int) *BackendPool {
	value, _ := lb.backends.LoadOrStore(routeID, &BackendPool{})
	return value.(*BackendPool)
}

// GetBackends returns all backends for a route
func (lb *LoadBalancer) GetBackends(routeID int) []*Backend {
	pool := lb.getPool(routeID)
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	result := make([]*Backend, len(pool.backends))
	copy(result, pool.backends)
	return result
}

// GetHealthyBackends returns only healthy backends for a route
func (lb *LoadBalancer) GetHealthyBackends(routeID int) []*Backend {
	pool := lb.getPool(routeID)
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	var healthy []*Backend
	for _, b := range pool.backends {
		if b.Healthy {
			healthy = append(healthy, b)
		}
	}
	return healthy
}

// SetBackendHealth manually sets a backend's health status
func (lb *LoadBalancer) SetBackendHealth(routeID int, url string, healthy bool) error {
	pool := lb.getPool(routeID)
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, b := range pool.backends {
		if b.URL == url {
			b.Healthy = healthy
			b.LastCheck = time.Now()
			return nil
		}
	}

	return fmt.Errorf("backend not found: %s", url)
}

// Stats returns health statistics for all backends
func (lb *LoadBalancer) Stats() map[int]BackendStats {
	stats := make(map[int]BackendStats)

	lb.backends.Range(func(key, value interface{}) bool {
		routeID := key.(int)
		pool := value.(*BackendPool)
		pool.mu.RLock()

		var healthy, unhealthy int
		for _, b := range pool.backends {
			if b.Healthy {
				healthy++
			} else {
				unhealthy++
			}
		}

		stats[routeID] = BackendStats{
			Total:     len(pool.backends),
			Healthy:   healthy,
			Unhealthy: unhealthy,
		}

		pool.mu.RUnlock()
		return true
	})

	return stats
}

// BackendStats holds statistics for a backend pool
type BackendStats struct {
	Total     int
	Healthy   int
	Unhealthy int
}

// DefaultHealthCheckConfig returns sensible defaults for health checks
func DefaultHealthCheckConfig() HealthCheckConfig {
	return HealthCheckConfig{
		Enabled:  true,
		Interval: 30 * time.Second,
		Timeout:  5 * time.Second,
		Path:     "/health",
		Expected: 200,
	}
}