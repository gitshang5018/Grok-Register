package oauth

import "testing"

func TestNormalizeConsentMode(t *testing.T) {
	cases := map[string]string{
		"":        "auto",
		"AUTO":    "auto",
		"browser": "browser",
		"http":    "http",
		"nope":    "auto",
	}
	for in, want := range cases {
		if got := normalizeConsentMode(in); got != want {
			t.Fatalf("normalizeConsentMode(%q)=%q want %q", in, got, want)
		}
	}
}

func TestServerActionIndicatesBrowserFallback(t *testing.T) {
	yes := []string{
		`{"success":false,"error":"No redirect received from authorization server"}`,
		`{"success":false,"error":"Access denied"}`,
		`1:{"success":false,"error":"No redirect received from authorization server"}`,
	}
	for _, s := range yes {
		if !serverActionIndicatesBrowserFallback(s) {
			t.Fatalf("expected fallback for %q", s)
		}
	}
	if serverActionIndicatesBrowserFallback(`{"user":{"userId":"x"}}`) {
		t.Fatal("session payload must not force browser")
	}
}

func TestShouldTryHTTPConsent(t *testing.T) {
	if !shouldTryHTTPConsent("auto") || !shouldTryHTTPConsent("http") {
		t.Fatal("auto/http should try HTTP")
	}
	if shouldTryHTTPConsent("browser") {
		t.Fatal("browser mode skips HTTP consent")
	}
}

func TestShouldAllowBrowserConsent(t *testing.T) {
	if !shouldAllowBrowserConsent("auto") || !shouldAllowBrowserConsent("browser") {
		t.Fatal("auto/browser allow browser")
	}
	if shouldAllowBrowserConsent("http") {
		t.Fatal("http mode must not use browser")
	}
}
