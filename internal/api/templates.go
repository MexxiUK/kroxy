package api

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/kroxy/kroxy/internal/auth"
	"github.com/kroxy/kroxy/web"
)

// TemplateData holds data passed to templates
type TemplateData struct {
	Title         string
	Page          string
	Content       template.HTML
	User          *TemplateUser
	CSRFToken     string
	Settings      *AppSettings
	Route         *RouteInfo
	OIDCProviders []OIDCProviderInfo
	Routes        []RouteInfo
	Users         []UserInfo
	WAFPresetJS   template.JS
}

// TemplateUser represents user data for templates
type TemplateUser struct {
	ID    int
	Email string
	Name  string
	Role  string
}

// RouteInfo represents route data for templates
type RouteInfo struct {
	ID             int64
	Domain         string
	Backend        string
	Enabled        bool
	WAFEnabled     bool
	WAFMode        string
	OIDCEnabled    bool
	OIDCProviderID int64
	RateLimit      int
	AuthType       string
	Status         string
	BlockCountries string
	AllowCountries string
}

// OIDCProviderInfo represents OIDC provider data for templates
type OIDCProviderInfo struct {
	ID   int64
	Name string
}

// UserInfo represents user data for user management
type UserInfo struct {
	ID        int64
	Email     string
	Name      string
	Role      string
	CreatedAt string
	LastLogin string
}

// AppSettings represents application settings for templates
type AppSettings struct {
	AppName         string
	AdminEmail      string
	LogLevel        string
	SessionDuration string
	Require2FA      bool
	AuditLogging    bool
	ListenPort      int
	MaxConnections  int
	Timeout         int
}

// TemplateHandler handles HTML template rendering
type TemplateHandler struct {
	templates *template.Template
}

// NewTemplateHandler creates a new template handler
func NewTemplateHandler() (*TemplateHandler, error) {
	// Create template with functions (include nonce as placeholder - will be set per-request)
	tmpl := template.New("").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"nonce": func() template.HTMLAttr { return "" }, // Placeholder, actual nonce set per-request
	})

	// Parse base layout
	baseContent, err := web.TemplatesFS.ReadFile("templates/layouts/base.html")
	if err != nil {
		return nil, err
	}
	tmpl, err = tmpl.Parse(string(baseContent))
	if err != nil {
		return nil, err
	}

	// Parse auth layout
	authContent, err := web.TemplatesFS.ReadFile("templates/layouts/auth.html")
	if err != nil {
		return nil, err
	}
	tmpl, err = tmpl.Parse(string(authContent))
	if err != nil {
		return nil, err
	}

	// Parse auth shared CSS template
	authSharedContent, err := web.TemplatesFS.ReadFile("templates/layouts/auth-shared.html")
	if err != nil {
		return nil, err
	}
	tmpl, err = tmpl.Parse(string(authSharedContent))
	if err != nil {
		return nil, err
	}

	// Parse all page templates (standalone pages like login, setup)
	pages := []string{"login", "setup", "2fa"}
	for _, page := range pages {
		content, err := web.TemplatesFS.ReadFile("templates/" + page + ".html")
		if err != nil {
			return nil, err
		}
		tmpl, err = tmpl.Parse(string(content))
		if err != nil {
			return nil, err
		}
	}

	// Parse all authenticated page templates
	authPages := []string{
		"dashboard",
		"routes",
		"route-form",
		"waf",
		"ip-lists",
		"rate-limits",
		"security-events",
		"users",
		"api-keys",
		"oidc",
		"settings",
		"ssl",
		"profile",
	}
	for _, page := range authPages {
		content, err := web.TemplatesFS.ReadFile("templates/pages/" + page + ".html")
		if err != nil {
			return nil, err
		}
		tmpl, err = tmpl.Parse(string(content))
		if err != nil {
			return nil, err
		}
	}

	return &TemplateHandler{templates: tmpl}, nil
}

// renderTemplate renders a template with data
func (a *API) renderTemplate(w http.ResponseWriter, r *http.Request, name string, data *TemplateData) {
	// Prevent browser caching of admin pages so template updates are visible immediately
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// Check if templates are available
	if a.templates == nil {
		http.Error(w, "Templates not initialized", http.StatusInternalServerError)
		return
	}

	// Get CSP nonce from context
	nonce := ""
	if nonceVal := r.Context().Value(cspNonceKey); nonceVal != nil {
		nonce = nonceVal.(string)
	}

	// Create a new template copy with nonce function
	tmpl := a.templates.templates.Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"nonce": func() template.HTMLAttr { return template.HTMLAttr(nonce) },
	})

	// Set defaults
	if data.Title == "" {
		data.Title = strings.Title(name)
	}

	// Determine which template to execute
	// For standalone pages (login, setup), use their specific template name
	// For authenticated pages, pre-render page content then execute root template
	templateName := name
	if name == "dashboard" || name == "routes" || name == "route-form" ||
		name == "waf" || name == "ip-lists" || name == "rate-limits" ||
		name == "security-events" ||
		name == "users" || name == "api-keys" || name == "oidc" ||
		name == "settings" || name == "ssl" || name == "profile" {
		// Pre-render the page content template into data.Content
		// This avoids using dynamic template names ({{ template .Page . }})
		// which are not supported by Go's html/template package
		var contentBuf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&contentBuf, name, data); err != nil {
			log.Printf("Template execution error for %s: %v", name, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		data.Content = template.HTML(contentBuf.String())
		templateName = "root"
	}

	// Set CSRF cookie so API requests from this page can pass CSRF validation
	if data.CSRFToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    data.CSRFToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   os.Getenv("KROXY_PRODUCTION") == "true",
			SameSite: http.SameSiteStrictMode,
			MaxAge:   3600,
		})
	}

	// Execute template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, templateName, data); err != nil {
		log.Printf("Template execution error for %s (final): %v", templateName, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// getTemplateUser extracts user info from context for templates
func getTemplateUser(r *http.Request) *TemplateUser {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		return nil
	}
	return &TemplateUser{
		ID:    user.ID,
		Email: user.Email,
		Name:  user.Name,
		Role:  user.Role,
	}
}

// RegisterPageRoutes registers routes for serving HTML pages
func (a *API) RegisterPageRoutes() {
	// Public pages
	a.router.Get("/", a.serveIndex)
	a.router.Get("/login", a.serveLogin)
	a.router.Get("/2fa", a.serve2FA)
	a.router.Get("/setup", a.serveSetup)

	// Protected pages (require authentication)
	// For page routes, redirect to login instead of returning JSON 401
	authPageMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check session
			session, err := a.auth.ValidateSession(r)
			if err == nil && session != nil {
				ctx := context.WithValue(r.Context(), "user", session)
				ctx = context.WithValue(ctx, "session", session)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// Not authenticated, redirect to login
			http.Redirect(w, r, "/login", http.StatusFound)
		})
	}

	a.router.With(authPageMiddleware).Get("/dashboard", a.serveDashboard)
	a.router.With(authPageMiddleware).Get("/routes", a.serveRoutes)
	a.router.With(authPageMiddleware).Get("/routes/new", a.serveRouteForm)
	a.router.With(authPageMiddleware).Get("/routes/{id}", a.serveRouteForm)
	a.router.With(authPageMiddleware).Get("/security/waf", a.serveWAF)
	a.router.With(authPageMiddleware).Get("/security/ip-lists", a.serveIPLists)
	a.router.With(authPageMiddleware).Get("/security/rate-limits", a.serveRateLimits)
	a.router.With(authPageMiddleware).Get("/security/events", a.serveSecurityEvents)
	a.router.With(authPageMiddleware).Get("/users", a.serveUsers)
	a.router.With(authPageMiddleware).Get("/users/api-keys", a.serveAPIKeys)
	a.router.With(authPageMiddleware).Get("/users/oidc", a.serveOIDC)
	a.router.With(authPageMiddleware).Get("/settings", a.serveSettings)
	a.router.With(authPageMiddleware).Get("/settings/ssl", a.serveSSLSettings)
	a.router.With(authPageMiddleware).Get("/profile", a.serveProfile)
	a.router.With(authPageMiddleware).Get("/health", a.serveHealth)
	a.router.With(authPageMiddleware).Get("/logs", a.serveLogs)
	a.router.With(authPageMiddleware).Get("/backup", a.serveBackup)
}

// Page handlers

func (a *API) serveIndex(w http.ResponseWriter, r *http.Request) {
	// Check if setup is needed
	users, err := a.store.GetUsers()
	if err == nil && len(users) == 0 {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	// Check if logged in via session cookie
	cookie, err := r.Cookie("kroxy_session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Simple session check - just verify the cookie exists
	// The RequireAuth middleware does the full validation for protected pages
	if cookie.Value != "" {
		// Has a session cookie, redirect to dashboard
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *API) serveLogin(w http.ResponseWriter, r *http.Request) {
	// Check if setup is needed
	users, err := a.store.GetUsers()
	if err == nil && len(users) == 0 {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:         "Login",
		CSRFToken:     csrfToken,
		OIDCProviders: a.getOIDCProviders(),
	}
	a.renderTemplate(w, r, "login", data)
}

func (a *API) serve2FA(w http.ResponseWriter, r *http.Request) {
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Two-Factor Authentication",
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "2fa", data)
}

func (a *API) serveSetup(w http.ResponseWriter, r *http.Request) {
	// Check if setup already complete
	users, err := a.store.GetUsers()
	if err == nil && len(users) > 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Setup",
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "setup", data)
}

func (a *API) serveDashboard(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Dashboard",
		Page:      "dashboard",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "dashboard", data)
}

func (a *API) serveRoutes(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Routes",
		Page:      "routes",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "routes", data)
}

func (a *API) serveRouteForm(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()

	data := &TemplateData{
		Title:         "Add Route",
		Page:          "routes-new",
		User:          user,
		CSRFToken:     csrfToken,
		OIDCProviders: a.getOIDCProviders(),
	}

	// Check if editing existing route
	idStr := r.PathValue("id")
	if idStr != "" {
		id := parseInt64(idStr)
		// Get all routes and find the one we need
		routes, err := a.store.GetRoutes()
		if err == nil {
			for _, route := range routes {
				if int64(route.ID) == id {
					data.Route = &RouteInfo{
						ID:             int64(route.ID),
						Domain:         route.Domain,
						Backend:        route.Backend,
						Enabled:        route.Enabled,
						WAFEnabled:     route.WAFEnabled,
						WAFMode:        route.WAFMode,
						OIDCEnabled:    route.OIDCEnabled,
						OIDCProviderID: int64(route.OIDCProviderID),
						RateLimit:      route.RateLimit,
						AuthType:       "",
						BlockCountries: route.BlockCountries,
						AllowCountries: route.AllowCountries,
					}
					data.Title = "Edit Route"
					break
				}
			}
		}
	}

	// Pass routes list for WAF scope selector and geofencing
	allRoutes, _ := a.store.GetRoutes()
	for _, rt := range allRoutes {
		data.Routes = append(data.Routes, RouteInfo{
			ID:     int64(rt.ID),
			Domain: rt.Domain,
		})
	}

	a.renderTemplate(w, r, "route-form", data)
}

func (a *API) serveWAF(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "WAF Rules",
		Page:      "waf",
		User:      user,
		CSRFToken: csrfToken,
	}

	// Pass routes list for WAF scope selector
	routes, _ := a.store.GetRoutes()
	for _, rt := range routes {
		data.Routes = append(data.Routes, RouteInfo{
			ID:     int64(rt.ID),
			Domain: rt.Domain,
		})
	}

	// Pass WAF presets as safe JS — html/template rejects the regex patterns in <script> tags
	presets := map[string]map[string]interface{}{
		"sqli":          {"name": "Block SQL Injection", "desc": "Stops attackers from injecting database commands through forms and URLs. Protects against the #1 web attack.", "rule": `SecRule ARGS "(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)" "deny,log,msg:'SQL Injection Detected'"`, "enabled": true, "mode": "block"},
		"xss":           {"name": "Block Cross-Site Scripting", "desc": "Prevents attackers from injecting malicious scripts into your pages that can steal user data or take over accounts.", "rule": `SecRule ARGS "(?i)(<script|javascript:|onerror\s*=|onload\s*=)" "deny,log,msg:'XSS Attack Detected'"`, "enabled": true, "mode": "block"},
		"traversal":     {"name": "Block Path Traversal", "desc": "Stops attackers from accessing files outside the web root using ../ sequences. Protects sensitive config files and logs.", "rule": `SecRule REQUEST_URI "(\.\./|\.\ |%2e%2e)" "deny,log,msg:'Path Traversal Detected'"`, "enabled": true, "mode": "block"},
		"bots":          {"name": "Block Attack Tools", "desc": "Blocks known hacking tools like sqlmap, nikto, and nmap that attackers use to scan and exploit websites.", "rule": `SecRule REQUEST_HEADERS:User-Agent "(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz)" "deny,log,msg:'Known Attack Tool Detected'"`, "enabled": true, "mode": "block"},
		"rfi":           {"name": "Block Remote File Inclusion", "desc": "Stops attackers from loading malicious code from external servers. Common in PHP apps but dangerous in any language.", "rule": `SecRule ARGS "(?i)(http://|https://|ftp://|php://)" "deny,log,msg:'Remote File Inclusion Detected'"`, "enabled": true, "mode": "block"},
		"cmdi":          {"name": "Block Command Injection", "desc": "Prevents attackers from running system commands on your server through input fields. Can lead to full server takeover.", "rule": `SecRule ARGS "(?i)(;|\||&&|\$\(|%60|\b(cat|ls|pwd|id|whoami|uname)\b)" "deny,log,msg:'Command Injection Detected'"`, "enabled": true, "mode": "block"},
		"lfi":           {"name": "Block Local File Inclusion", "desc": "Stops attackers from reading local files like /etc/passwd through vulnerable include statements.", "rule": `SecRule ARGS "(?i)(\.\./|%00|/etc/|/proc/|/var/log/)" "deny,log,msg:'Local File Inclusion Detected'"`, "enabled": true, "mode": "block"},
		"protocoldos":   {"name": "Block Protocol Attacks", "desc": "Blocks HTTP smuggling, request splitting, and other protocol-level exploits that bypass normal security checks.", "rule": `SecRule REQUEST_URI "(?i)(%0d%0a|\r\n|transfer-encoding\s*:\s*chunked)" "deny,log,msg:'HTTP Protocol Attack Detected'"`, "enabled": true, "mode": "block"},
		"scanner":       {"name": "Block Vulnerability Scanners", "desc": "Stops automated scanners from probing your site for weaknesses. Reduces noise in your logs and prevents recon.", "rule": `SecRule REQUEST_HEADERS:User-Agent "(?i)(w3af|openvas|nessus|burpsuite|acunetix|appscan|arachni|havij)" "deny,log,msg:'Vulnerability Scanner Detected'"`, "enabled": true, "mode": "block"},
		"method":        {"name": "Block Unusual HTTP Methods", "desc": "Only allows standard GET, POST, HEAD, and OPTIONS. Blocks TRACE, TRACK, DEBUG, and PUT/DELETE that most sites dont need.", "rule": `SecRule REQUEST_METHOD "!@pm GET POST HEAD OPTIONS" "deny,log,msg:'Unusual HTTP Method Blocked'"`, "enabled": true, "mode": "block"},
		"upload":        {"name": "Block Malicious File Uploads", "desc": "Prevents uploading of executable files (.php, .jsp, .exe, .sh) that could give attackers a backdoor into your server.", "rule": `SecRule FILES_NAMES "\.(?:php|php[0-9]|phtml|jsp|asp|aspx|exe|sh|bat|cmd|py|pl|rb)$" "deny,log,msg:'Malicious File Upload Detected'"`, "enabled": true, "mode": "block"},
		"responseheader": {"name": "Block Server Info Leakage", "desc": "Stops your server from revealing its software version and OS in error pages and headers. Gives attackers less to work with.", "rule": `SecRule RESPONSE_HEADERS "/^(?:Server|X-Powered-By|X-AspNet-Version)/" "deny,log,msg:'Server Information Leakage Detected'"`, "enabled": true, "mode": "log_only"},
	}
	presetsJSON, err := json.Marshal(presets)
	if err == nil {
		data.WAFPresetJS = template.JS(presetsJSON)
	}

	a.renderTemplate(w, r, "waf", data)
}

func (a *API) serveIPLists(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "IP Lists",
		Page:      "ip-lists",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "ip-lists", data)
}

func (a *API) serveRateLimits(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Rate Limits",
		Page:      "rate-limits",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "rate-limits", data)
}

func (a *API) serveSecurityEvents(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Security Events",
		Page:      "security-events",
		User:      user,
		CSRFToken: csrfToken,
	}

	routes, _ := a.store.GetRoutes()
	for _, rt := range routes {
		data.Routes = append(data.Routes, RouteInfo{
			ID:     int64(rt.ID),
			Domain: rt.Domain,
		})
	}

	a.renderTemplate(w, r, "security-events", data)
}

func (a *API) serveUsers(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Users",
		Page:      "users",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "users", data)
}

func (a *API) serveAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "API Keys",
		Page:      "api-keys",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "api-keys", data)
}

func (a *API) serveOIDC(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "OIDC Providers",
		Page:      "oidc",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "oidc", data)
}

func (a *API) serveSettings(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Settings",
		Page:      "settings",
		User:      user,
		CSRFToken: csrfToken,
		Settings:  a.getSettings(),
	}
	a.renderTemplate(w, r, "settings", data)
}

func (a *API) serveSSLSettings(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "SSL/TLS Settings",
		Page:      "ssl",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "ssl", data)
}

func (a *API) serveProfile(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Profile",
		Page:      "profile",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "profile", data)
}

func (a *API) serveHealth(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Backend Health",
		Page:      "health",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "health", data)
}

func (a *API) serveLogs(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Access Logs",
		Page:      "logs",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "logs", data)
}

func (a *API) serveBackup(w http.ResponseWriter, r *http.Request) {
	user := getTemplateUser(r)
	csrfToken := generateCSRFToken()
	data := &TemplateData{
		Title:     "Backup & Restore",
		Page:      "backup",
		User:      user,
		CSRFToken: csrfToken,
	}
	a.renderTemplate(w, r, "backup", data)
}

// Helper functions

func (a *API) getOIDCProviders() []OIDCProviderInfo {
	providers, err := a.store.GetOIDCProviders()
	if err != nil {
		return []OIDCProviderInfo{}
	}
	result := make([]OIDCProviderInfo, len(providers))
	for i, p := range providers {
		result[i] = OIDCProviderInfo{ID: int64(p.ID), Name: p.Name}
	}
	return result
}

func (a *API) getSettings() *AppSettings {
	listenPort, _ := strconv.Atoi(a.store.GetSettingDefault("listen_port", "8080"))
	maxConn, _ := strconv.Atoi(a.store.GetSettingDefault("max_connections", "1000"))
	timeout, _ := strconv.Atoi(a.store.GetSettingDefault("request_timeout", "30"))

	require2FA := false
	if v := a.store.GetSettingDefault("require_2fa", "false"); v == "true" || v == "1" {
		require2FA = true
	}
	auditLogging := false
	if v := a.store.GetSettingDefault("audit_logging", "false"); v == "true" || v == "1" {
		auditLogging = true
	}

	return &AppSettings{
		AppName:         a.store.GetSettingDefault("app_name", "Kroxy"),
		LogLevel:        a.store.GetSettingDefault("log_level", "info"),
		SessionDuration: a.store.GetSettingDefault("session_duration", "24h"),
		Require2FA:      require2FA,
		AuditLogging:    auditLogging,
		ListenPort:      listenPort,
		MaxConnections:  maxConn,
		Timeout:         timeout,
	}
}

func parseInt64(s string) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return v
}