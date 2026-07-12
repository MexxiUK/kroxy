package bot

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if len(d.knownBotUAs) == 0 {
		t.Fatal("expected known bot UAs")
	}
}

func TestScore_KnownBotUA(t *testing.T) {
	d := NewDetector()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")
	req.Header.Set("Accept", "*/*")
	if !ShouldBlock(d.Score(req)) {
		t.Fatalf("expected curl UA to be blocked, got score %f", d.Score(req))
	}
}

func TestScore_RealBrowserUA(t *testing.T) {
	d := NewDetector()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	if ShouldBlock(d.Score(req)) {
		t.Fatalf("expected real browser UA to pass, got score %f", d.Score(req))
	}
}

func TestScore_EmptyUA(t *testing.T) {
	d := NewDetector()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if d.Score(req) < 0.3 {
		t.Fatalf("expected empty UA to be suspicious, got score %f", d.Score(req))
	}
}
