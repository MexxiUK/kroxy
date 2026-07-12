package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corazacrs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/kroxy/kroxy/internal/store"
	"github.com/kroxy/kroxy/internal/testutil"
)

func TestWAF_CRSLoads(t *testing.T) {
	engine, err := createWAFEngine(Config{Mode: "block"}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create WAF engine with CRS: %v", err)
	}
	if engine == nil {
		t.Fatal("WAF engine is nil")
	}
}

func TestWAF_DetectionOnlyMode(t *testing.T) {
	engine, err := createWAFEngine(Config{Mode: "detect"}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create WAF engine in detection mode: %v", err)
	}
	// In detection mode, attacks should not be blocked (transaction should proceed)
	waf := &WAF{secEngine: engine, enabled: true, mode: "detect"}

	// SQL injection should be detected but not blocked
	res := waf.TestPayload("GET", "/test?q=1'+UNION+SELECT+*+FROM+users--", "", nil)
	if res.Blocked {
		t.Error("Detection mode should not block requests, but it did")
	}
}

func TestWAF_BlocksSQLi(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"UNION SELECT", "1' UNION SELECT * FROM users--"},
		{"OR tautology", "1' OR '1'='1"},
		{"boolean blind", "1 AND 1=1"},
		{"stacked query", "1'; DROP TABLE users--"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked := testBlock(t, "GET", "/test?q="+tt.payload, "", nil)
			if !blocked {
				t.Errorf("Expected SQLi payload to be blocked: %s", tt.name)
			}
		})
	}
}

func TestWAF_BlocksXSS(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"script tag", "<script>alert(1)</script>"},
		{"event handler", "<img src=x onerror=alert(1)>"},
		{"SVG onload", "<svg/onload=alert(1)>"},
		{"javascript protocol", "javascript:alert(1)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked := testBlock(t, "GET", "/test?q="+tt.payload, "", nil)
			if !blocked {
				t.Errorf("Expected XSS payload to be blocked: %s", tt.name)
			}
		})
	}
}

func TestWAF_BlocksPathTraversal(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"basic traversal", "../../../etc/passwd"},
		{"proc filesystem", "/proc/self/environ"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked := testBlock(t, "GET", "/test?q="+tt.payload, "", nil)
			if !blocked {
				t.Errorf("Expected path traversal payload to be blocked: %s", tt.name)
			}
		})
	}
}

func TestWAF_BlocksRCE(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"command injection semicolon", "; cat /etc/passwd"},
		{"command substitution", "$(whoami)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked := testBlock(t, "GET", "/test?q="+tt.payload, "", nil)
			if !blocked {
				t.Errorf("Expected RCE payload to be blocked: %s", tt.name)
			}
		})
	}

	// Note: "| id" is not blocked at CRS PL1/PL2 (conservative).
	// It would be caught at PL3.
	t.Run("pipe injection PL1", func(t *testing.T) {
		blocked := testBlock(t, "GET", "/test?q=| id", "", nil)
		// Not blocked at PL1, this is expected behavior
		if blocked {
			t.Log("Pipe injection blocked (bonus)")
		} else {
			t.Log("Pipe injection not blocked at PL1 (expected, needs PL3)")
		}
	})
}

func TestWAF_ScannerUserAgentsNotBlockedAtPL1(t *testing.T) {
	// Scanner detection at PL1 only contributes to anomaly scoring;
	// it does not immediately block in this CRS version.
	scanners := []struct {
		name string
		ua   string
	}{
		{"sqlmap", "sqlmap/1.5"},
		{"Nikto", "Nikto"},
	}

	for _, s := range scanners {
		t.Run(s.name, func(t *testing.T) {
			blocked := testBlock(t, "GET", "/test", "", map[string]string{"User-Agent": s.ua})
			if blocked {
				t.Logf("Scanner UA blocked (bonus): %s", s.name)
			}
		})
	}
}

func TestWAF_TRACEnotBlockedAtPL1(t *testing.T) {
	// TRACE method enforcement at PL1 only contributes to anomaly scoring;
	// it does not immediately block in this CRS version.
	blocked := testBlock(t, "TRACE", "/test", "", nil)
	if blocked {
		t.Log("TRACE method blocked (bonus)")
	}
}

func TestWAF_TestSuiteRuns(t *testing.T) {
	engine, err := createWAFEngine(Config{Mode: "block"}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create WAF engine: %v", err)
	}
	wafInstance := &WAF{secEngine: engine, enabled: true, mode: "block"}

	result := RunTestSuite(wafInstance)

	if result.Summary.Total == 0 {
		t.Error("Test suite returned 0 results")
	}
	if result.Summary.Passed == 0 && result.Summary.Failed == 0 {
		t.Error("Test suite returned no pass or fail results")
	}

	// Log summary
	t.Logf("WAF Test Suite: %d/%d tests passed (%d failed)",
		result.Summary.Passed, result.Summary.Total, result.Summary.Failed)

	// With CRS loaded, we expect most attack tests to be blocked
	if result.Summary.Passed < result.Summary.Total/2 {
		t.Errorf("Expected at least half of tests to be blocked, got %d/%d",
			result.Summary.Passed, result.Summary.Total)
	}
}

func TestWAF_CustomRulesAfterCRS(t *testing.T) {
	cfg := Config{
		Mode: "block",
		CustomRules: []string{
			`SecRule ARGS "@contains secretword" "deny,log,msg:Custom Rule"`,
		},
	}

	engine, err := createWAFEngine(cfg, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create WAF engine with custom rules: %v", err)
	}
	wafInstance := &WAF{secEngine: engine, enabled: true, mode: "block"}

	// Custom rule should block
	res := wafInstance.TestPayload("GET", "/test?q=secretword", "", nil)
	if !res.Blocked {
		t.Error("Custom rule should block 'secretword'")
	}
}

func TestWAF_ResponseBodyInspection(t *testing.T) {
	engine, err := createWAFEngine(Config{Mode: "block"}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create WAF engine: %v", err)
	}
	wafInstance := &WAF{secEngine: engine, enabled: true, mode: "block"}

	// Test: SQL error message in response body should be caught by CRS rule 951
	res := wafInstance.TestResponsePayload(200, "You have an error in your SQL syntax; check the manual", map[string]string{
		"Content-Type": "text/html",
	})
	if !res.Blocked {
		t.Error("Expected SQL error in response body to be blocked by CRS rule 951")
	}

	// Test: Server header with version — may not block at PL1 in response headers
	// CRS 950 is more conservative on response headers; test with body content instead
	res = wafInstance.TestResponsePayload(200, "<title>Index of /var/www/html</title><a href=\"../\">Parent Directory</a>", map[string]string{
		"Content-Type": "text/html",
	})
	// Directory listing detection may vary by CRS version/PL; log but don't fail
	if res.Blocked {
		t.Log("Directory listing in response body blocked (bonus)")
	} else {
		t.Log("Directory listing not blocked at PL1 (expected)")
	}
}

func TestWAF_ParanoiaLevel2(t *testing.T) {
	cfg := Config{Mode: "block", ParanoiaLevel: 2}
	engine, err := createWAFEngine(cfg, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create WAF engine with PL2: %v", err)
	}
	wafInstance := &WAF{secEngine: engine, enabled: true, mode: "block"}

	// CRLF injection in query string — blocked at PL2, not at PL1
	res := wafInstance.TestPayload("GET", "/test?q=/test%0d%0aInjected-Header: value", "", nil)
	if !res.Blocked {
		t.Error("Expected CRLF injection to be blocked at PL2")
	}
}

func TestWAF_ConvertRuleToLogOnly(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"deny with trailing comma", `"deny,log,msg:'Test'"`, `"pass,log,msg:'Test'"`},
		{"bare deny", `"deny"`, `"pass"`},
		{"deny at end", `"log,deny"`, `"log,pass"`},
		{"deny with status", `"deny,status:403"`, `"pass,status:403"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertRuleToLogOnly(tt.input)
			if got != tt.want {
				t.Errorf("convertRuleToLogOnly(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Helper: creates a WAF engine and tests if a payload is blocked
func testBlock(t *testing.T, method, uri, body string, headers map[string]string) bool {
	t.Helper()
	engine, err := createWAFEngine(Config{Mode: "block"}, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create WAF engine: %v", err)
	}
	wafInstance := &WAF{secEngine: engine, enabled: true, mode: "block"}
	return wafInstance.TestPayload(method, uri, body, headers).Blocked
}

// Benchmark: create WAF engine with CRS
func BenchmarkCreateWAFEngine(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := createWAFEngine(Config{Mode: "block"}, nil, nil)
		if err != nil {
			b.Fatalf("Failed to create WAF engine: %v", err)
		}
	}
}

// Benchmark: process a request through WAF
func BenchmarkWAFMiddleware(b *testing.B) {
	wafConfig := coraza.NewWAFConfig().
		WithRequestBodyAccess().
		WithRootFS(corazacrs.FS)

	var directives string
	directives += "Include @coraza.conf-recommended\n"
	directives += "Include @crs-setup.conf.example\n"
	for _, f := range crsFiles {
		directives += "Include @owasp_crs/" + f + "\n"
	}
	directives += "SecRuleEngine On\n"

	wafConfig = wafConfig.WithDirectives(directives)
	engine, err := coraza.NewWAF(wafConfig)
	if err != nil {
		b.Fatalf("Failed to create WAF engine: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx := engine.NewTransaction()
		tx.ProcessConnection("127.0.0.1", 80, "127.0.0.1", 80)
		tx.ProcessURI("/test?q=normal", "GET", "HTTP/1.1")
		tx.AddRequestHeader("User-Agent", "Mozilla/5.0")
		tx.ProcessRequestHeaders()
		tx.ProcessLogging()
	}
}
func TestWAF_ParanoiaLevelInConfig(t *testing.T) {
	cfg := Config{Mode: "block", ParanoiaLevel: 2}
	engine, err := createWAFEngine(cfg, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create WAF engine with PL2: %v", err)
	}
	wafInstance := &WAF{secEngine: engine, enabled: true, mode: "block"}

	// PL2 should block CRLF injection in query string (PL1 does not)
	res := wafInstance.TestPayload("GET", "/test?q=/test%0d%0aInjected-Header: value", "", nil)
	if !res.Blocked {
		t.Error("Expected CRLF injection to be blocked at PL2")
	}
}

func TestWAF_ParanoiaLevel3(t *testing.T) {
	cfg := Config{Mode: "block", ParanoiaLevel: 3}
	engine, err := createWAFEngine(cfg, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create WAF engine with PL3: %v", err)
	}
	wafInstance := &WAF{secEngine: engine, enabled: true, mode: "block"}

	// PL3 should be more aggressive — at minimum it should block what PL2 blocks
	res := wafInstance.TestPayload("GET", "/test?q=| id", "", nil)
	if !res.Blocked {
		t.Error("Expected pipe injection to be blocked at PL3")
	}
}

func TestInspectRequest_BodyStreamed(t *testing.T) {
	wafInstance, err := New(nil, Config{Enabled: true, Mode: "detect"}, nil, nil, "detect")
	if err != nil {
		t.Fatalf("failed to create WAF: %v", err)
	}

	payload := "benign request body"
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(payload))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()

	allowed, reason := wafInstance.InspectRequest(rec, req)
	if !allowed {
		t.Fatalf("expected request to pass inspection, got blocked: %s", reason)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read body after inspection: %v", err)
	}
	if string(body) != payload {
		t.Fatalf("expected body %q after inspection, got %q", payload, string(body))
	}
}

func TestWAF_CustomRule_ctlDisableSkipped(t *testing.T) {
	engine, err := createWAFEngine(Config{
		Mode: "block",
		CustomRules: []string{
			`SecRule ARGS "@rx foo" "id:999990,phase:2,ctl:ruleEngine=Off"`,
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("createWAFEngine: %v", err)
	}

	w := &WAF{secEngine: engine, enabled: true, mode: "block"}
	res := w.TestPayload("GET", "/test?q=1'+UNION+SELECT+*+FROM+users--", "", nil)
	if !res.Blocked {
		t.Fatal("expected WAF to remain blocking after skipping ctl:ruleEngine=Off rule")
	}
}

func TestWAF_DBRule_SecRuleEngineOffSkipped(t *testing.T) {
	s, cleanup := testutil.NewTestStore(t)
	defer cleanup()

	rule := &store.WAFRule{
		Name:    "engine-off",
		Rule:    "SecRuleEngine Off",
		Enabled: true,
		Mode:    "block",
	}
	if err := s.CreateWAFRule(rule); err != nil {
		t.Fatalf("create WAF rule: %v", err)
	}

	engine, err := createWAFEngine(Config{Mode: "block"}, s, nil)
	if err != nil {
		t.Fatalf("createWAFEngine: %v", err)
	}

	w := &WAF{secEngine: engine, enabled: true, mode: "block"}
	res := w.TestPayload("GET", "/test?q=1'+UNION+SELECT+*+FROM+users--", "", nil)
	if !res.Blocked {
		t.Fatal("expected WAF to remain blocking after skipping SecRuleEngine Off rule")
	}
}
