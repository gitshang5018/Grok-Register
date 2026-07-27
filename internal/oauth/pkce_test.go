package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestPKCESessionChallengeIsS256OfVerifier(t *testing.T) {
	s, err := newPKCESession()
	if err != nil {
		t.Fatalf("newPKCESession: %v", err)
	}
	// RFC 7636: challenge = BASE64URL(SHA256(ASCII(verifier))), no padding.
	sum := sha256.Sum256([]byte(s.verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if s.challenge != want {
		t.Fatalf("challenge is not S256 of verifier:\n got %q\nwant %q", s.challenge, want)
	}
	if strings.ContainsAny(s.verifier+s.challenge, "=+/") {
		t.Fatalf("verifier/challenge must be base64url without padding: %q %q", s.verifier, s.challenge)
	}
	// RFC 7636 §4.1 requires 43..128 characters.
	if len(s.verifier) < 43 || len(s.verifier) > 128 {
		t.Fatalf("verifier length %d outside RFC 7636 range", len(s.verifier))
	}
	if s.state == "" || s.nonce == "" || s.state == s.nonce {
		t.Fatalf("state/nonce not independently random: %q %q", s.state, s.nonce)
	}
}

func TestPKCESessionsAreDistinct(t *testing.T) {
	a, err := newPKCESession()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newPKCESession()
	if err != nil {
		t.Fatal(err)
	}
	if a.verifier == b.verifier || a.state == b.state || a.nonce == b.nonce {
		t.Fatal("two sessions shared a secret; randomness is broken")
	}
}

func TestAuthorizeURLCarriesRequiredParams(t *testing.T) {
	s, err := newPKCESession()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(s.authorizeURL())
	if err != nil {
		t.Fatalf("authorizeURL unparsable: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizeURL {
		t.Fatalf("wrong endpoint: %q", u.String())
	}
	q := u.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             ClientID,
		"redirect_uri":          RedirectURI,
		"scope":                 Scope,
		"code_challenge":        s.challenge,
		"code_challenge_method": "S256",
		"state":                 s.state,
		"nonce":                 s.nonce,
	}
	for k, v := range want {
		if got := q.Get(k); got != v {
			t.Fatalf("param %s = %q, want %q", k, got, v)
		}
	}
	// The verifier must never travel on the authorize request.
	if strings.Contains(s.authorizeURL(), s.verifier) {
		t.Fatal("code_verifier leaked into the authorization URL")
	}
}

func TestIsCallback(t *testing.T) {
	for _, loc := range []string{
		"http://127.0.0.1:56121/callback?code=abc&state=xyz",
		"http://localhost:56121/callback?code=abc",
	} {
		if !isCallback(loc) {
			t.Fatalf("callback not recognized: %q", loc)
		}
	}
	for _, loc := range []string{
		"https://accounts.x.ai/oauth2/consent",
		"https://auth.x.ai/oauth2/device/done",
		"",
	} {
		if isCallback(loc) {
			t.Fatalf("non-callback accepted: %q", loc)
		}
	}
}

func TestCodeFromCallback(t *testing.T) {
	code, err := codeFromCallback("http://127.0.0.1:56121/callback?code=THECODE&state=ST", "ST")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != "THECODE" {
		t.Fatalf("code = %q", code)
	}

	if _, err := codeFromCallback("http://127.0.0.1:56121/callback?code=X&state=WRONG", "ST"); err == nil {
		t.Fatal("state mismatch must be fatal — otherwise the flow accepts a code from another session")
	}
	if _, err := codeFromCallback("http://127.0.0.1:56121/callback?state=ST", "ST"); err == nil {
		t.Fatal("missing code must be an error")
	}
	if _, err := codeFromCallback("http://127.0.0.1:56121/callback?error=access_denied&error_description=nope", "ST"); err == nil {
		t.Fatal("error callback must be an error")
	} else if !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("error should name the server's code, got %v", err)
	}
}

func TestIsConsentPage(t *testing.T) {
	if !isConsentPage("https://accounts.x.ai/oauth2/consent?foo=1") {
		t.Fatal("consent page not recognized")
	}
	if isConsentPage("https://accounts.x.ai/account") {
		t.Fatal("account page misread as consent")
	}
}

func TestDiscoverConsentActionIDs(t *testing.T) {
	html := `<html><body><script>self.__next_f.push([1, "createServerReference)(\"1234567890abcdef1234567890abcdef12345678\", submitOAuth2Consent)"])</script></body></html>`
	c := &Client{}
	ids := discoverConsentActionIDs(context.Background(), c, "https://accounts.x.ai/oauth2/consent", html)
	if len(ids) == 0 {
		t.Fatal("expected discovered action IDs, got none")
	}
	found := false
	for _, id := range ids {
		if id == "1234567890abcdef1234567890abcdef12345678" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected 1234567890abcdef1234567890abcdef12345678 in discovered IDs: %v", ids)
	}
}

// Next.js SERVER_REFERENCE_ID_LENGTH is 42. The previous hex scanner only
// accepted 40 or 64, so modern consent bundles yielded zero live IDs and the
// flow fell back to a stale 40-char default that 404s, then a form POST that
// auth.x.ai answers with access_denied.
func TestDiscoverConsentActionIDsFinds42CharNextIDs(t *testing.T) {
	const liveID = "00abcdef1234567890abcdef1234567890abcdef12" // 42 hex chars
	if len(liveID) != 42 {
		t.Fatalf("fixture length = %d, want 42", len(liveID))
	}
	html := `<html><body><script>` +
		`self.__next_f.push([1,"createServerReference(\"` + liveID + `\",\"submitOAuth2Consent\")"])` +
		`</script></body></html>`
	c := &Client{}
	ids := discoverConsentActionIDs(context.Background(), c, "https://accounts.x.ai/oauth2/consent", html)
	found := false
	for _, id := range ids {
		if id == liveID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("42-char Next.js action ID not discovered: %v", ids)
	}
}

// Production chunks often only embed the bare hex id next to an oauth consent
// symbol — no createServerReference wrapper survives minification. The scanner
// must still pick up 42-char ids from that shape.
func TestDiscoverConsentActionIDsFromMinifiedConsentChunk(t *testing.T) {
	const liveID = "01fedcba0987654321fedcba0987654321fedcba09"
	html := `<html><body><script type="text/javascript">` +
		`e.exports={submitOAuth2Consent:{id:"` + liveID + `",bound:null},deny:1}` +
		`</script></body></html>`
	c := &Client{}
	ids := discoverConsentActionIDs(context.Background(), c, "https://accounts.x.ai/oauth2/consent", html)
	found := false
	for _, id := range ids {
		if id == liveID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("minified consent chunk action ID not discovered: %v", ids)
	}
}

// Live 42-char IDs must sort ahead of the hardcoded 40-char default so a
// working reference is attempted before the known-stale fallback.
func TestDiscoverConsentActionIDsPrefersLiveOverDefault(t *testing.T) {
	const liveID = "00abcdef1234567890abcdef1234567890abcdef12"
	html := `<html><body><script>createServerReference("` + liveID + `")</script></body></html>`
	c := &Client{}
	ids := discoverConsentActionIDs(context.Background(), c, "https://accounts.x.ai/oauth2/consent", html)
	if len(ids) == 0 {
		t.Fatal("no ids")
	}
	if ids[0] != liveID {
		t.Fatalf("first id = %q, want live 42-char id before stale default; full=%v", ids[0], ids)
	}
}

func TestServerActionRedirectFromHeader(t *testing.T) {
	// Next.js action redirects land in x-action-redirect, not Location.
	loc := actionRedirectLocation(
		"https://accounts.x.ai",
		map[string]string{
			"X-Action-Redirect": "http://127.0.0.1:56121/callback?code=THECODE&state=ST",
		},
		"",
	)
	if !strings.Contains(loc, "code=THECODE") {
		t.Fatalf("x-action-redirect not honored: %q", loc)
	}
}

func TestServerActionSubmitURLKeepsQuery(t *testing.T) {
	// Browser posts the Server Action to the current document URL, query
	// included. Stripping ?response_type=… drops the OAuth request context.
	full := "https://accounts.x.ai/oauth2/consent?response_type=code&client_id=CID&state=ST"
	got := serverActionSubmitURL(full)
	if got != full {
		t.Fatalf("submit URL = %q, want full consent URL with query", got)
	}
}

func TestResolveURL(t *testing.T) {
	base := "https://accounts.x.ai/oauth2/consent?response_type=code&client_id=b1a00492"
	got := resolveURL(base, "/_next/static/chunks/073qnqzc81yfr.js")
	want := "https://accounts.x.ai/_next/static/chunks/073qnqzc81yfr.js"
	if got != want {
		t.Fatalf("resolveURL = %q, want %q", got, want)
	}
}
