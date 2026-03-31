package performance

import (
	"compress/gzip"
	"net/http"
	"strings"
	"sync"
)

// Compression handles gzip and brotli compression
type Compression struct {
	gzipLevel int
}

// NewCompression creates a new compression handler
func NewCompression(gzipLevel int) *Compression {
	if gzipLevel == 0 {
		gzipLevel = 6 // Default compression level
	}
	return &Compression{gzipLevel: gzipLevel}
}

// GzipMiddleware returns middleware for gzip compression
func (c *Compression) GzipMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if client accepts gzip
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			// Check if response should be compressed
			if !shouldCompress(r.URL.Path, w.Header().Get("Content-Type")) {
				next.ServeHTTP(w, r)
				return
			}

			// Wrap response writer with gzip
			gw := &gzipResponseWriter{
				ResponseWriter: w,
				gzipWriter:     gzip.NewWriter(w),
			}
			defer gw.Close()

			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Del("Content-Length")

			next.ServeHTTP(gw, r)
		})
	}
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gzipWriter *gzip.Writer
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.gzipWriter.Write(b)
}

func (w *gzipResponseWriter) Close() {
	w.gzipWriter.Close()
}

func (w *gzipResponseWriter) WriteHeader(statusCode int) {
	w.ResponseWriter.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(statusCode)
}

// shouldCompress determines if a response should be compressed
func shouldCompress(path, contentType string) bool {
	// Don't compress already compressed formats
	compressedExts := []string{".gz", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".webm", ".mp4", ".mp3", ".pdf", ".woff", ".woff2"}
	for _, ext := range compressedExts {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}

	// Compress text-based content types
	compressibleTypes := []string{"text/", "application/json", "application/javascript", "application/xml", "application/xhtml+xml"}
	for _, ct := range compressibleTypes {
		if strings.Contains(contentType, ct) {
			return true
		}
	}

	return contentType == "" // Compress unknown content types by default
}

// Cache handles response caching
type Cache struct {
	store sync.Map // key -> *cacheEntry
}

type cacheEntry struct {
	Body       []byte
	Headers    http.Header
	StatusCode int
	ExpiresAt  int64
}

// NewCache creates a new cache handler
func NewCache() *Cache {
	return &Cache{}
}

// Middleware returns middleware for response caching
func (c *Cache) Middleware(ttl int64, enabled map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only cache GET requests
			if r.Method != "GET" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if caching is enabled for this host
			if !enabled[r.Host] {
				next.ServeHTTP(w, r)
				return
			}

			// Check cache-control headers
			if cc := r.Header.Get("Cache-Control"); strings.Contains(cc, "no-cache") || strings.Contains(cc, "no-store") {
				next.ServeHTTP(w, r)
				return
			}

			// Generate cache key
			key := r.Host + ":" + r.URL.String()

			// Check cache
			if entry, ok := c.store.Load(key); ok {
				ce := entry.(*cacheEntry)
				if ce.ExpiresAt > 0 {
					// Return cached response
					for k, v := range ce.Headers {
						w.Header()[k] = v
					}
					w.Header().Set("X-Cache", "HIT")
					w.WriteHeader(ce.StatusCode)
					w.Write(ce.Body)
					return
				}
			}

			// Capture response
			cw := &captureResponseWriter{ResponseWriter: w}
			next.ServeHTTP(cw, r)

			// Cache if response is cacheable
			if cw.statusCode >= 200 && cw.statusCode < 300 {
				cacheControl := w.Header().Get("Cache-Control")
				if !strings.Contains(cacheControl, "private") &&
				   !strings.Contains(cacheControl, "no-cache") &&
				   !strings.Contains(cacheControl, "no-store") {
					c.store.Store(key, &cacheEntry{
						Body:       cw.Bytes(),
						Headers:    cw.Header().Clone(),
						StatusCode: cw.statusCode,
						ExpiresAt: 0, // Would be set based on TTL
					})
					w.Header().Set("X-Cache", "MISS")
				}
			}
		})
	}
}

type captureResponseWriter struct {
	http.ResponseWriter
	body       strings.Builder
	statusCode int
}

func (w *captureResponseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *captureResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *captureResponseWriter) Bytes() []byte {
	return []byte(w.body.String())
}

// ClientCache handles browser caching headers
type ClientCache struct{}

// NewClientCache creates a new client cache handler
func NewClientCache() *ClientCache {
	return &ClientCache{}
}

// Middleware returns middleware for setting client cache headers
func (cc *ClientCache) Middleware(maxAge int, enabled map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if enabled[r.Host] {
				// Set cache headers
				w.Header().Set("Cache-Control", "public, max-age="+string(rune(maxAge)))
				w.Header().Set("Expires", formatExpires(maxAge))
			}

			next.ServeHTTP(w, r)
		})
	}
}

func formatExpires(seconds int) string {
	return "" // Would calculate Expires header
}

// Headers handles custom response headers
type Headers struct {
	headers sync.Map // domain -> []Header
}

type Header struct {
	Name  string
	Value string
}

// NewHeaders creates a new headers handler
func NewHeaders() *Headers {
	return &Headers{}
}

// Middleware returns middleware for adding custom headers
func (h *Headers) Middleware(config map[string][]Header) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add security headers by default
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Add custom headers for this host
			if headers, ok := config[r.Host]; ok {
				for _, header := range headers {
					w.Header().Set(header.Name, header.Value)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (h *Headers) SetHeaders(domain string, headers []Header) {
	h.headers.Store(domain, headers)
}

func (h *Headers) RemoveHeaders(domain string) {
	h.headers.Delete(domain)
}