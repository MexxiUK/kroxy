package api

import (
	"net/http"
	"strconv"
	"time"

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
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"count":    len(statuses),
		"backends": statuses,
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
			"logs":  []proxy.AccessLogEntry{},
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

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"logs":  logs,
		"total": len(logs),
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
