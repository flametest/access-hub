package service

import (
	"strings"
	"testing"
)

// TestFormPostHTMLEscapesTarget pins the XSS fix: the target URL is embedded
// via json.Marshal, whose <>& escaping keeps a hostile redirect from closing
// the <script> tag (strconv.Quote did not escape them).
func TestFormPostHTMLEscapesTarget(t *testing.T) {
	payload := "/social/complete?login_code=abc</script><script>alert(document.cookie)</script>"
	page := formPostHTML(payload)
	if strings.Contains(page, "<script>alert") {
		t.Fatalf("form post page must not let the target break out of the script: %s", page)
	}
	if !strings.Contains(page, `\u003c/script\u003e`) {
		t.Fatalf("target must be JSON-escaped inside the script context: %s", page)
	}
	// The noscript href stays attribute-escaped as well.
	if strings.Contains(page, `href="/social/complete?login_code=abc<`) {
		t.Fatalf("noscript href must escape the target: %s", page)
	}
}

func TestSanitizeRedirectWhitelist(t *testing.T) {
	const fallback = "/social/complete"
	cases := []struct {
		in   string
		want string
	}{
		{"/workspaces", "/workspaces"},
		{"/social/complete?login_code=abc&x=1", "/social/complete?login_code=abc&x=1"},
		{"/p/a-th-ish.100~_%23", "/p/a-th-ish.100~_%23"},
		// XSS payload rejected by the character whitelist.
		{"/</script><script>alert(1)</script>", fallback},
		{"/a\"onmouseover=\"x", fallback},
		// Scheme-relative, backslash and control characters rejected.
		{"//evil.example", fallback},
		{"/a\\b", fallback},
		{"/a\nb", fallback},
	}
	for _, tc := range cases {
		if got := sanitizeRedirect(tc.in, fallback); got != tc.want {
			t.Fatalf("sanitizeRedirect(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
