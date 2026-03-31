package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kroxy/kroxy/internal/store"
)

// Metrics holds Prometheus metrics
type Metrics struct {
	store *store.Store

	// Counters
	requestsTotal      atomic.Int64
	requestsErrors     atomic.Int64
	requestsBlocked    atomic.Int64
	bytesIn           atomic.Int64
	bytesOut          atomic.Int64

	// Gauges
	routesTotal       atomic.Int32
	routesEnabled     atomic.Int32
	oidcProviders     atomic.Int32
	wafRules          atomic.Int32
	blacklists        atomic.Int32
	whitelists        atomic.Int32

	// Histograms (simplified as counts)
	requestLatency     *histogram

	// Per-route metrics
	routeMetrics      sync.Map // map[string]*RouteMetrics

	mu sync.RWMutex
}

type RouteMetrics struct {
	Requests     atomic.Int64
	Errors       atomic.Int64
	Latency      *histogram
	BytesIn      atomic.Int64
	BytesOut     atomic.Int64
	LastAccess   time.Time
}

type histogram struct {
	buckets []float64
	counts  []atomic.Int64
	sum     atomic.Int64
	count   atomic.Int64
}

func newHistogram() *histogram {
	buckets := []float64{0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	return &histogram{
		buckets: buckets,
		counts:  make([]atomic.Int64, len(buckets)),
	}
}

func (h *histogram) observe(duration float64) {
	h.sum.Add(int64(duration * 1000000)) // microseconds
	h.count.Add(1)

	for i, b := range h.buckets {
		if duration <= b {
			h.counts[i].Add(1)
		}
	}
}

// New creates a new Metrics instance
func New(s *store.Store) *Metrics {
	m := &Metrics{
		store:           s,
		requestLatency:  newHistogram(),
	}

	// Update gauges from store
	m.UpdateGauges()

	return m
}

// UpdateGauges updates gauge metrics from database
func (m *Metrics) UpdateGauges() {
	routes, _ := m.store.GetRoutes()
	enabled := 0
	for _, r := range routes {
		if r.Enabled {
			enabled++
		}
	}
	m.routesTotal.Store(int32(len(routes)))
	m.routesEnabled.Store(int32(enabled))

	providers, _ := m.store.GetOIDCProviders()
	m.oidcProviders.Store(int32(len(providers)))

	rules, _ := m.store.GetWAFRules()
	m.wafRules.Store(int32(len(rules)))

	blacklists, _ := m.store.GetBlacklists()
	m.blacklists.Store(int32(len(blacklists)))

	whitelists, _ := m.store.GetWhitelists()
	m.whitelists.Store(int32(len(whitelists)))
}

// RecordRequest records a processed request
func (m *Metrics) RecordRequest(domain string, statusCode int, bytesIn, bytesOut int64, duration time.Duration) {
	m.requestsTotal.Add(1)

	if statusCode >= 400 {
		m.requestsErrors.Add(1)
	}

	m.bytesIn.Add(bytesIn)
	m.bytesOut.Add(bytesOut)

	// Record per-route metrics
	if domain != "" {
		if rm, ok := m.routeMetrics.Load(domain); ok {
			rm.(*RouteMetrics).Requests.Add(1)
			rm.(*RouteMetrics).BytesIn.Add(bytesIn)
			rm.(*RouteMetrics).BytesOut.Add(bytesOut)
			rm.(*RouteMetrics).Latency.observe(duration.Seconds())
		}
	}

	// Record latency
	m.requestLatency.observe(duration.Seconds())
}

// RecordBlocked records a blocked request (WAF, rate limit, etc.)
func (m *Metrics) RecordBlocked(domain string, reason string) {
	m.requestsBlocked.Add(1)
}

// InitRouteMetrics initializes metrics for a route
func (m *Metrics) InitRouteMetrics(domain string) {
	m.routeMetrics.Store(domain, &RouteMetrics{
		Latency: newHistogram(),
	})
}

// RemoveRouteMetrics removes metrics for a route
func (m *Metrics) RemoveRouteMetrics(domain string) {
	m.routeMetrics.Delete(domain)
}

// Handler returns HTTP handler for Prometheus metrics
func (m *Metrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.UpdateGauges()

		var output strings.Builder

		// Help and type declarations
		output.WriteString("# HELP kroxy_requests_total Total number of requests processed\n")
		output.WriteString("# TYPE kroxy_requests_total counter\n")
		output.WriteString("kroxy_requests_total " + strconv.FormatInt(m.requestsTotal.Load(), 10) + "\n\n")

		output.WriteString("# HELP kroxy_requests_errors Total number of request errors\n")
		output.WriteString("# TYPE kroxy_requests_errors counter\n")
		output.WriteString("kroxy_requests_errors " + strconv.FormatInt(m.requestsErrors.Load(), 10) + "\n\n")

		output.WriteString("# HELP kroxy_requests_blocked Total number of blocked requests\n")
		output.WriteString("# TYPE kroxy_requests_blocked counter\n")
		output.WriteString("kroxy_requests_blocked " + strconv.FormatInt(m.requestsBlocked.Load(), 10) + "\n\n")

		output.WriteString("# HELP kroxy_bytes_total Total bytes transferred\n")
		output.WriteString("# TYPE kroxy_bytes_total counter\n")
		output.WriteString("kroxy_bytes_in_total " + strconv.FormatInt(m.bytesIn.Load(), 10) + "\n")
		output.WriteString("kroxy_bytes_out_total " + strconv.FormatInt(m.bytesOut.Load(), 10) + "\n\n")

		output.WriteString("# HELP kroxy_routes_total Total number of routes\n")
		output.WriteString("# TYPE kroxy_routes_total gauge\n")
		output.WriteString("kroxy_routes_total " + strconv.FormatInt(int64(m.routesTotal.Load()), 10) + "\n\n")

		output.WriteString("# HELP kroxy_routes_enabled Number of enabled routes\n")
		output.WriteString("# TYPE kroxy_routes_enabled gauge\n")
		output.WriteString("kroxy_routes_enabled " + strconv.FormatInt(int64(m.routesEnabled.Load()), 10) + "\n\n")

		output.WriteString("# HELP kroxy_oidc_providers Number of OIDC providers\n")
		output.WriteString("# TYPE kroxy_oidc_providers gauge\n")
		output.WriteString("kroxy_oidc_providers " + strconv.FormatInt(int64(m.oidcProviders.Load()), 10) + "\n\n")

		output.WriteString("# HELP kroxy_waf_rules Number of WAF rules\n")
		output.WriteString("# TYPE kroxy_waf_rules gauge\n")
		output.WriteString("kroxy_waf_rules " + strconv.FormatInt(int64(m.wafRules.Load()), 10) + "\n\n")

		output.WriteString("# HELP kroxy_blacklists Number of blacklist entries\n")
		output.WriteString("# TYPE kroxy_blacklists gauge\n")
		output.WriteString("kroxy_blacklists " + strconv.FormatInt(int64(m.blacklists.Load()), 10) + "\n\n")

		output.WriteString("# HELP kroxy_whitelists Number of whitelist entries\n")
		output.WriteString("# TYPE kroxy_whitelists gauge\n")
		output.WriteString("kroxy_whitelists " + strconv.FormatInt(int64(m.whitelists.Load()), 10) + "\n\n")

		// Per-route metrics
		output.WriteString("# HELP kroxy_route_requests_total Total requests per route\n")
		output.WriteString("# TYPE kroxy_route_requests_total counter\n")
		m.routeMetrics.Range(func(key, value interface{}) bool {
			domain := key.(string)
			rm := value.(*RouteMetrics)
			output.WriteString("kroxy_route_requests_total{domain=\"" + domain + "\"} " + strconv.FormatInt(rm.Requests.Load(), 10) + "\n")
			return true
		})

		output.WriteString("\n# HELP kroxy_route_errors_total Total errors per route\n")
		output.WriteString("# TYPE kroxy_route_errors_total counter\n")
		m.routeMetrics.Range(func(key, value interface{}) bool {
			domain := key.(string)
			rm := value.(*RouteMetrics)
			output.WriteString("kroxy_route_errors_total{domain=\"" + domain + "\"} " + strconv.FormatInt(rm.Errors.Load(), 10) + "\n")
			return true
		})

		output.WriteString("\n# HELP kroxy_route_bytes_total Total bytes per route\n")
		output.WriteString("# TYPE kroxy_route_bytes_total counter\n")
		m.routeMetrics.Range(func(key, value interface{}) bool {
			domain := key.(string)
			rm := value.(*RouteMetrics)
			output.WriteString("kroxy_route_bytes_in_total{domain=\"" + domain + "\"} " + strconv.FormatInt(rm.BytesIn.Load(), 10) + "\n")
			output.WriteString("kroxy_route_bytes_out_total{domain=\"" + domain + "\"} " + strconv.FormatInt(rm.BytesOut.Load(), 10) + "\n")
			return true
		})

		// Latency histogram (simplified)
		output.WriteString("\n# HELP kroxy_request_duration_seconds Request duration\n")
		output.WriteString("# TYPE kroxy_request_duration_seconds summary\n")
		count := m.requestLatency.count.Load()
		sum := m.requestLatency.sum.Load()
		output.WriteString("kroxy_request_duration_seconds_sum " + strconv.FormatFloat(float64(sum)/1000000, 'f', -1, 64) + "\n")
		output.WriteString("kroxy_request_duration_seconds_count " + strconv.FormatInt(count, 10) + "\n")

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Write([]byte(output.String()))
	}
}