package oauth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseConsentScriptOutputOK(t *testing.T) {
	raw := `{"ok":true,"code":"abc.def","state":"st123","callback_url":"http://127.0.0.1:56121/callback?code=abc.def&state=st123"}`
	res, err := parseConsentScriptOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != "abc.def" || res.State != "st123" {
		t.Fatalf("got %+v", res)
	}
	if !isCallback(res.CallbackURL) {
		t.Fatalf("callback %q", res.CallbackURL)
	}
}

func TestParseConsentScriptOutputPrefersLastJSONLine(t *testing.T) {
	raw := "warn noise\n{\"ok\":true,\"code\":\"c1\",\"state\":\"s1\",\"callback_url\":\"http://127.0.0.1:56121/callback?code=c1&state=s1\"}\n"
	res, err := parseConsentScriptOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != "c1" {
		t.Fatalf("code=%q", res.Code)
	}
}

func TestParseConsentScriptOutputError(t *testing.T) {
	_, err := parseConsentScriptOutput(`{"ok":false,"error":"timeout"}`)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFindConsentScriptEnvOverride(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oauth_consent.py")
	if err := os.WriteFile(p, []byte("#"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GROK_OAUTH_CONSENT_SCRIPT", p)
	got := findConsentScript()
	if got != p {
		t.Fatalf("got %q want %q", got, p)
	}
}

func TestBrowserConsentUsesRunner(t *testing.T) {
	c := &Client{
		consentTimeout: 5 * time.Second,
		consentRunner: func(ctx context.Context, consentURL, cookie string, timeout time.Duration) (string, error) {
			if !strings.Contains(consentURL, "consent") {
				t.Fatalf("url %s", consentURL)
			}
			if !strings.Contains(cookie, "sso=") {
				t.Fatal("missing sso")
			}
			return "http://127.0.0.1:56121/callback?code=tok&state=want", nil
		},
	}
	loc, err := c.browserConsent(context.Background(), "https://accounts.x.ai/oauth2/consent?x=1", "sso=abc", "want")
	if err != nil {
		t.Fatal(err)
	}
	code, err := codeFromCallback(loc, "want")
	if err != nil || code != "tok" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}
