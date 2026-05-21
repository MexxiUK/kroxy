package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/kroxy/kroxy/internal/api/dto"
	"github.com/kroxy/kroxy/internal/audit"
	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/internal/proxy"
	"github.com/kroxy/kroxy/internal/security"
)

func (a *API) getHealthStatus(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	hc := proxy.GetGlobalHealthChecker()
	if hc == nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"status": "not_initialized",
		})
		return
	}

	statuses := hc.GetAllStatuses()
	safeStatuses := make([]dto.HealthStatusResponse, len(statuses))
	for i, s := range statuses {
		safeStatuses[i] = dto.HealthStatusResponse{
			RouteID:      s.RouteID,
			Domain:       s.Domain,
			Healthy:      s.Healthy,
			LastChecked:  s.LastChecked,
			LastSuccess:  s.LastSuccess,
			FailCount:    s.FailCount,
			ResponseTime: s.ResponseTime,
			Error:        s.Error,
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"count":    len(safeStatuses),
		"backends": safeStatuses,
	})

	a.audit.Log(audit.Event{
		Type:      "health_checked",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
	})
}

func (a *API) getAccessLogs(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	ls := proxy.GetGlobalLogStore()
	if ls == nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"logs":  []dto.AccessLogEntryResponse{},
			"total": 0,
		})
		return
	}

	// Parse query params
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	host := r.URL.Query().Get("host")
	method := r.URL.Query().Get("method")

	since := time.Time{}
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	logs := ls.Query(limit, host, method, since)

	// Mask PII before returning to API consumers
	safeLogs := make([]dto.AccessLogEntryResponse, len(logs))
	for i, e := range logs {
		safeLogs[i] = dto.AccessLogEntryResponse{
			Timestamp:    e.Timestamp,
			Method:       e.Method,
			Host:         e.Host,
			URI:          e.URI,
			RemoteAddr:   dto.MaskIP(e.RemoteAddr),
			UserAgent:    "", // User-Agent is PII; never expose
			StatusCode:   e.StatusCode,
			ResponseSize: e.ResponseSize,
			Duration:     e.Duration,
			RouteID:      e.RouteID,
			WAFAction:    e.WAFAction,
			BotScore:     e.BotScore,
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"logs":  safeLogs,
		"total": len(safeLogs),
	})

	a.audit.Log(audit.Event{
		Type:      "logs_viewed",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
	})
}

func (a *API) getLogStats(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())

	ls := proxy.GetGlobalLogStore()
	if ls == nil {
		respondJSON(w, http.StatusOK, proxy.LogStats{})
		return
	}

	// Parse time period
	period := r.URL.Query().Get("period")
	since := time.Now().Add(-1 * time.Hour)
	switch period {
	case "24h":
		since = time.Now().Add(-24 * time.Hour)
	case "7d":
		since = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		since = time.Now().Add(-30 * 24 * time.Hour)
	}

	stats := ls.Stats(since)
	respondJSON(w, http.StatusOK, stats)

	a.audit.Log(audit.Event{
		Type:      "log_stats_viewed",
		UserID:    user.ID,
		UserEmail: user.Email,
		IP:        security.GetClientIP(r),
	})
}
