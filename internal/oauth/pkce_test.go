package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
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

// Next.js packs type + usedArgs into the first byte of a 42-char action id.
// Live consent logs showed 00… (0-arg action), 40… (1-arg action) and de…
// (use-cache — must never be POSTed as Next-Action).
func TestActionIDMetaFromPrefix(t *testing.T) {
	cases := []struct {
		id       string
		useCache bool
		nArgs    int
	}{
		{"0091b719fc9316041607cb1c3c32378f27284e75e2", false, 0},
		{"404c516617e9e389641add4bd711e454c0f2d49f5d", false, 1},
		{"de2ae688129f7c7c4d157a3325c2069a31c20eed", true, 0},
	}
	for _, tc := range cases {
		meta := actionIDMeta(tc.id)
		if meta.UseCache != tc.useCache {
			t.Fatalf("id=%s UseCache=%v want %v", tc.id[:16], meta.UseCache, tc.useCache)
		}
		if !tc.useCache && meta.ArgCount != tc.nArgs {
			t.Fatalf("id=%s ArgCount=%d want %d", tc.id[:16], meta.ArgCount, tc.nArgs)
		}
	}
}

func TestRankActionIDsDropsUseCacheAndPrefersConsentLinked(t *testing.T) {
	// de… is use-cache; 40… is 1-arg consent; 00… is 0-arg unrelated.
	ids := []string{
		"de2ae688129f7c7c4d157a3325c2069a31c20eed",
		"0091b719fc9316041607cb1c3c32378f27284e75e2",
		"404c516617e9e389641add4bd711e454c0f2d49f5d",
	}
	linked := map[string]bool{
		"404c516617e9e389641add4bd711e454c0f2d49f5d": true,
	}
	got := rankActionIDs(ids, linked)
	if len(got) != 2 {
		t.Fatalf("expected use-cache dropped, got %v", got)
	}
	if got[0] != "404c516617e9e389641add4bd711e454c0f2d49f5d" {
		t.Fatalf("consent-linked 1-arg should be first, got %v", got)
	}
}

// encodeReply for a 0-arg server action is an empty JSON array. Sending a
// full consent object against a 0-arg id is ignored by omitUnusedArgs and the
// action becomes a no-op re-render (200, no x-action-redirect) — exactly the
// live failure mode after 42-char discovery started working.
func TestEncodeServerActionBodiesZeroAndOneArg(t *testing.T) {
	form := url.Values{}
	form.Set("action", "allow")
	form.Set("client_id", "CID")
	form.Set("redirect_uri", "http://127.0.0.1/callback")
	form.Set("scope", "openid")
	form.Set("state", "ST")
	form.Set("code_challenge", "CH")
	form.Set("code_challenge_method", "S256")
	form.Set("nonce", "N")
	form.Set("principal_type", "User")
	form.Set("principal_id", "")
	form.Set("referrer", "")

	zero := encodeServerActionBodies("0091b719fc9316041607cb1c3c32378f27284e75e2", form)
	if len(zero) != 1 || zero[0] != "[]" {
		t.Fatalf("0-arg bodies = %#v, want [\"[]\"]", zero)
	}

	one := encodeServerActionBodies("404c516617e9e389641add4bd711e454c0f2d49f5d", form)
	if len(one) < 1 {
		t.Fatal("1-arg produced no bodies")
	}
	// At least one variant must carry the allow action + client id.
	found := false
	for _, b := range one {
		if strings.Contains(b, "allow") && (strings.Contains(b, "CID") || strings.Contains(b, "client")) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("1-arg bodies missing consent fields: %v", one)
	}
}

func TestExtractCodeFromActionBodyRSC(t *testing.T) {
	body := "0:{\"a\":\"$@1\",\"f\":[],\"b\":\"dev\"}\n1:\"http://127.0.0.1:56121/callback?code=THECODE&state=ST\"\n"
	loc := extractCodeFromActionBody(body, "http://127.0.0.1/callback", "ST")
	if !strings.Contains(loc, "code=THECODE") {
		t.Fatalf("RSC action result URL not extracted: %q", loc)
	}
}

// Live 404c responses look like:
//
//	0:{"a":"$@1","f":"","q":"?response_type=code…"}
//	1:<action return value>
//
// The useful payload is ALWAYS row 1 (or whatever $@N points at), not the
// envelope. A 180-char head preview never reaches it.
func TestParseFlightActionResultResolvesPromiseRef(t *testing.T) {
	body := "0:{\"a\":\"$@1\",\"f\":\"\",\"q\":\"?response_type=code&client_id=x\"}\n" +
		"1:{\"ok\":false,\"error\":\"need_allow\"}\n"
	got := parseFlightActionResult(body)
	if !strings.Contains(got, "need_allow") {
		t.Fatalf("action result not resolved from $@1: %q", got)
	}
}

func TestParseFlightActionResultURLString(t *testing.T) {
	body := "0:{\"a\":\"$@1\",\"f\":\"\"}\n1:\"http://127.0.0.1:56121/callback?code=ABC&state=ST\"\n"
	got := parseFlightActionResult(body)
	if !strings.Contains(got, "code=ABC") {
		t.Fatalf("URL action result: %q", got)
	}
	loc := extractCodeFromActionBody(body, "http://127.0.0.1/callback", "ST")
	if !strings.Contains(loc, "code=ABC") {
		t.Fatalf("extract from flight URL result: %q", loc)
	}
}

// 1-arg consent actions in the wild are almost always either:
//
//	submitOAuth2Consent("allow")  → body `["allow"]`
//	submitOAuth2Consent(formData) → multipart of the hidden form fields
//
// A JSON object of camelCase fields is the shape that returned the 510-byte
// no-op re-render in production.
func TestEncodeServerActionBodiesPrefersAllowString(t *testing.T) {
	form := url.Values{}
	form.Set("action", "allow")
	form.Set("client_id", "CID")
	form.Set("redirect_uri", "http://127.0.0.1/callback")
	form.Set("scope", "openid")
	form.Set("state", "ST")
	form.Set("code_challenge", "CH")
	form.Set("code_challenge_method", "S256")
	form.Set("nonce", "N")
	form.Set("principal_type", "User")
	form.Set("principal_id", "")
	form.Set("referrer", "")

	one := encodeServerActionBodies("404c516617e9e389641add4bd711e454c0f2d49f5d", form)
	if len(one) == 0 {
		t.Fatal("no bodies")
	}
	if one[0] != `["allow"]` {
		t.Fatalf("first 1-arg body = %q, want [\"allow\"]", one[0])
	}
	// Must still offer a multipart/form-data variant for FormData-style actions.
	hasMultipart := false
	for _, b := range one {
		if strings.Contains(b, "Content-Disposition: form-data") || strings.HasPrefix(b, "multipart:") {
			hasMultipart = true
			break
		}
		// Our encoder prefixes multipart bodies with a marker the submit loop understands.
		if strings.HasPrefix(b, "multipart:") {
			hasMultipart = true
			break
		}
	}
	// Accept either raw multipart marker or a dedicated slot after JSON variants.
	for _, b := range one {
		if strings.HasPrefix(b, "multipart:") {
			hasMultipart = true
		}
	}
	if !hasMultipart {
		t.Fatalf("expected a multipart FormData body variant among %#v", one)
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

func TestSubmitConsentBrowserModeUsesRunner(t *testing.T) {
	html := `<html><body><form action="https://auth.x.ai/oauth2/authorize">
<input name="client_id" value="cid"/>
<input name="state" value="st"/>
<input name="redirect_uri" value="http://127.0.0.1:56121/callback"/>
<input name="scope" value="openid"/>
<input name="code_challenge" value="ch"/>
<input name="code_challenge_method" value="S256"/>
<input name="nonce" value="n"/>
<input name="principal_type" value="User"/>
<input name="principal_id" value=""/>
<button type="button">Allow</button>
</form></body></html>`
	c := &Client{consentMode: "browser"}
	c.consentRunner = func(ctx context.Context, consentURL, cookie string, timeout time.Duration) (string, error) {
		return "http://127.0.0.1:56121/callback?code=from-browser&state=st", nil
	}
	loc, _, err := c.submitConsent(context.Background(),
		"https://accounts.x.ai/oauth2/consent?state=st", html, "sso=tok")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(loc, "code=from-browser") {
		t.Fatalf("loc=%s", loc)
	}
}
