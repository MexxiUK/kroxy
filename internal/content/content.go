package content

import (
	"net/http"
	"strings"
	"sync"
)

// CustomPages handles custom error and auth pages
type CustomPages struct {
	pages sync.Map // domain+type -> content
}

type PageConfig struct {
	Type    string // "error_404", "error_500", "auth_login", etc.
	Content string
}

// NewCustomPages creates a new custom pages handler
func NewCustomPages() *CustomPages {
	return &CustomPages{}
}

// Middleware returns middleware for custom error pages
func (cp *CustomPages) Middleware(config map[string]map[int]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Wrap response writer to capture status code
			wrapped := &statusCapture{ResponseWriter: w, status: 200}

			next.ServeHTTP(wrapped, r)

			// Check for custom error page
			if wrapped.status >= 400 {
				if pages, ok := config[r.Host]; ok {
					if content, ok := pages[wrapped.status]; ok {
						w.Header().Set("Content-Type", "text/html")
						w.WriteHeader(wrapped.status)
						w.Write([]byte(content))
						return
					}
				}
			}
		})
	}
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (s *statusCapture) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

func (cp *CustomPages) SetPage(domain, pageType, content string) {
	cp.pages.Store(domain+":"+pageType, content)
}

func (cp *CustomPages) GetPage(domain, pageType string) (string, bool) {
	value, ok := cp.pages.Load(domain + ":" + pageType)
	if !ok {
		return "", false
	}
	return value.(string), true
}

func (cp *CustomPages) RemovePage(domain, pageType string) {
	cp.pages.Delete(domain + ":" + pageType)
}

// Redirects handles HTTP redirects
type Redirects struct {
	redirects sync.Map // pattern -> Redirect
}

type Redirect struct {
	FromPattern string
	ToURL       string
	StatusCode  int // 301, 302, 307, 308
	Enabled     bool
}

// NewRedirects creates a new redirects handler
func NewRedirects() *Redirects {
	return &Redirects{}
}

// Middleware returns middleware for handling redirects
func (rd *Redirects) Middleware(redirects []Redirect) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for matching redirect
			for _, redirect := range redirects {
				if !redirect.Enabled {
					continue
				}

				if matchesPattern(r.URL.Path, redirect.FromPattern) {
					target := replaceWildcards(redirect.ToURL, r.URL.Path, redirect.FromPattern)
					http.Redirect(w, r, target, redirect.StatusCode)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func matchesPattern(path, pattern string) bool {
	if pattern == path {
		return true
	}

	// Simple wildcard matching
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if strings.HasPrefix(path, parts[0]) {
			if len(parts) == 1 {
				return true
			}
			return strings.HasSuffix(path, parts[len(parts)-1])
		}
	}

	return false
}

func replaceWildcards(target, path, pattern string) string {
	if !strings.Contains(pattern, "*") {
		return target
	}

	// Extract wildcard value
	parts := strings.Split(pattern, "*")
	prefix := parts[0]
	suffix := ""
	if len(parts) > 1 {
		suffix = parts[1]
	}

	wildcard := path[len(prefix):]
	if suffix != "" {
		wildcard = wildcard[:len(wildcard)-len(suffix)]
	}

	return strings.Replace(target, "*", wildcard, 1)
}

func (rd *Redirects) AddRedirect(redirect Redirect) {
	rd.redirects.Store(redirect.FromPattern, redirect)
}

func (rd *Redirects) RemoveRedirect(fromPattern string) {
	rd.redirects.Delete(fromPattern)
}

// RobotsTxt handles robots.txt generation
type RobotsTxt struct {
	robots sync.Map // domain -> content
}

// NewRobotsTxt creates a new robots.txt handler
func NewRobotsTxt() *RobotsTxt {
	return &RobotsTxt{}
}

// Handler returns a handler for robots.txt
func (rt *RobotsTxt) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/robots.txt" {
			http.NotFound(w, r)
			return
		}

		// Check for custom robots.txt
		if content, ok := rt.robots.Load(r.Host); ok {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(content.(string)))
			return
		}

		// Default robots.txt
		defaultRobots := `User-agent: *
Allow: /
`
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(defaultRobots))
	}
}

func (rt *RobotsTxt) SetRobots(domain, content string) {
	rt.robots.Store(domain, content)
}

func (rt *RobotsTxt) RemoveRobots(domain string) {
	rt.robots.Delete(domain)
}

// GenerateRobots generates robots.txt content
func GenerateRobots(disallow []string, allow []string, sitemap string) string {
	var sb strings.Builder

	sb.WriteString("User-agent: *\n")

	for _, path := range disallow {
		sb.WriteString("Disallow: ")
		sb.WriteString(path)
		sb.WriteString("\n")
	}

	for _, path := range allow {
		sb.WriteString("Allow: ")
		sb.WriteString(path)
		sb.WriteString("\n")
	}

	if sitemap != "" {
		sb.WriteString("\nSitemap: ")
		sb.WriteString(sitemap)
		sb.WriteString("\n")
	}

	return sb.String()
}

// SecurityTxt handles security.txt (RFC 9116)
type SecurityTxt struct {
	security sync.Map // domain -> content
}

// NewSecurityTxt creates a new security.txt handler
func NewSecurityTxt() *SecurityTxt {
	return &SecurityTxt{}
}

// Handler returns a handler for security.txt
func (st *SecurityTxt) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/security.txt" && r.URL.Path != "/security.txt" {
			http.NotFound(w, r)
			return
		}

		// Check for custom security.txt
		if content, ok := st.security.Load(r.Host); ok {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(content.(string)))
			return
		}

		// Default security.txt
		defaultSecurity := `Contact: security@example.com
Expires: 2026-12-31T23:59:00.000Z
Preferred-Languages: en
`
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(defaultSecurity))
	}
}

func (st *SecurityTxt) SetSecurity(domain, content string) {
	st.security.Store(domain, content)
}

func (st *SecurityTxt) RemoveSecurity(domain string) {
	st.security.Delete(domain)
}

// GenerateSecurityTxt generates security.txt content
func GenerateSecurityTxt(contact, expires, languages, acknowledgments, hiring string) string {
	var sb strings.Builder

	if contact != "" {
		sb.WriteString("Contact: ")
		sb.WriteString(contact)
		sb.WriteString("\n")
	}

	if expires != "" {
		sb.WriteString("Expires: ")
		sb.WriteString(expires)
		sb.WriteString("\n")
	}

	if languages != "" {
		sb.WriteString("Preferred-Languages: ")
		sb.WriteString(languages)
		sb.WriteString("\n")
	}

	if acknowledgments != "" {
		sb.WriteString("Acknowledgments: ")
		sb.WriteString(acknowledgments)
		sb.WriteString("\n")
	}

	if hiring != "" {
		sb.WriteString("Hiring: ")
		sb.WriteString(hiring)
		sb.WriteString("\n")
	}

	return sb.String()
}

// HTMLInjection handles custom HTML injection
type HTMLInjection struct {
	injections sync.Map // domain -> []Injection
}

type Injection struct {
	Location string // "head", "body_start", "body_end"
	Content  string
}

// NewHTMLInjection creates a new HTML injection handler
func NewHTMLInjection() *HTMLInjection {
	return &HTMLInjection{}
}

// Middleware returns middleware for HTML injection
func (hi *HTMLInjection) Middleware(config map[string][]Injection) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			injections, ok := config[r.Host]
			if !ok || len(injections) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Only inject for HTML responses
			ct := w.Header().Get("Content-Type")
			if !strings.Contains(ct, "text/html") {
				next.ServeHTTP(w, r)
				return
			}

			// Capture response and inject HTML
			wrapped := &htmlInjectWriter{
				ResponseWriter: w,
				injections:     injections,
			}

			next.ServeHTTP(wrapped, r)
		})
	}
}

type htmlInjectWriter struct {
	http.ResponseWriter
	injections []Injection
}

func (w *htmlInjectWriter) Write(b []byte) (int, error) {
	// Would inject HTML at appropriate locations
	// This is a simplified version
	return w.ResponseWriter.Write(b)
}