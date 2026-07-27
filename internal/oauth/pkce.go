package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// Authorization Code + PKCE against auth.x.ai.
//
// The device_code grant has never produced a token for accounts created by this
// pipeline: the approve POST is accepted and redirects to the genuine
// /oauth2/device/done, yet the token endpoint answers invalid_grant "Access
// denied". This grant is the one with observed successes for the same client_id
// and the same scope string, so it is offered as an alternative path.
//
// No loopback listener is needed. The client is configured with
// WithNotFollowRedirects, so the authorization code arrives in the Location
// header of the redirect to RedirectURI and is read straight off it.
const (
	AuthorizeURL = "https://auth.x.ai/oauth2/authorize"
	RedirectURI  = "http://127.0.0.1:56121/callback"

	// maxAuthorizeHops bounds the redirect chain between /oauth2/authorize and
	// the callback so a redirect loop cannot hang a worker.
	maxAuthorizeHops = 10
)

type pkceSession struct {
	state     string
	nonce     string
	verifier  string
	challenge string
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func randHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func newPKCESession() (pkceSession, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return pkceSession{}, err
	}
	verifier := b64url(raw)
	sum := sha256.Sum256([]byte(verifier))

	state, err := randHex(32)
	if err != nil {
		return pkceSession{}, err
	}
	nonce, err := randHex(16)
	if err != nil {
		return pkceSession{}, err
	}
	return pkceSession{
		state:     state,
		nonce:     nonce,
		verifier:  verifier,
		challenge: b64url(sum[:]),
	}, nil
}

func (s pkceSession) authorizeURL() string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", ClientID)
	q.Set("redirect_uri", RedirectURI)
	q.Set("scope", Scope)
	q.Set("state", s.state)
	q.Set("nonce", s.nonce)
	q.Set("code_challenge", s.challenge)
	q.Set("code_challenge_method", "S256")
	return AuthorizeURL + "?" + q.Encode()
}

// isCallback reports whether a Location points at our registered redirect_uri.
func isCallback(loc string) bool {
	return strings.HasPrefix(loc, "http://127.0.0.1:56121/") ||
		strings.HasPrefix(loc, "http://localhost:56121/")
}

// codeFromCallback validates state and returns the authorization code.
func codeFromCallback(loc, wantState string) (string, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return "", fmt.Errorf("pkce_callback_unparsable: %w", err)
	}
	q := u.Query()
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		if desc == "" {
			desc = e
		}
		return "", fmt.Errorf("pkce_authorize_rejected: %s (%s)", e, desc)
	}
	code := strings.TrimSpace(q.Get("code"))
	if code == "" {
		return "", fmt.Errorf("pkce_callback_missing_code")
	}
	// Constant-time comparison is unnecessary here: state never leaves this
	// process and an attacker has no oracle, but a mismatch must still be fatal.
	if got := q.Get("state"); got != wantState {
		return "", fmt.Errorf("pkce_state_mismatch")
	}
	return code, nil
}

func isConsentPage(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.Contains(rawURL, "/consent")
	}
	return strings.Contains(u.Path, "/consent")
}

// ExchangeGrant runs the grant named by cfg. "pkce" is the default: the device
// grant has never produced a token for accounts created by this pipeline, while
// authorization_code+PKCE is the grant with observed successes for the same
// client_id and scope. "auto" tries PKCE and falls back to the device flow.
func (c *Client) ExchangeGrant(ctx context.Context, sso, grant string) (Credential, error) {
	switch strings.ToLower(strings.TrimSpace(grant)) {
	case "device":
		return c.Exchange(ctx, sso)
	case "auto":
		cred, err := c.ExchangePKCE(ctx, sso)
		if err == nil {
			return cred, nil
		}
		c.logDiag("pkce failed (%v) -> falling back to device grant", err)
		return c.Exchange(ctx, sso)
	default:
		return c.ExchangePKCE(ctx, sso)
	}
}

// ExchangePKCE runs authorization_code + PKCE using an existing SSO session and
// returns the resulting credential.
func (c *Client) ExchangePKCE(ctx context.Context, sso string) (Credential, error) {
	c.clearDiags()
	sso = strings.TrimSpace(sso)
	if sso == "" {
		return Credential{}, fmt.Errorf("login_required")
	}
	sess, err := newPKCESession()
	if err != nil {
		return Credential{}, err
	}
	code, err := c.authorizeCode(ctx, sso, sess)
	if err != nil {
		return Credential{}, fmt.Errorf("%w [diag: %s]", err, c.getDiags())
	}
	cred, err := c.exchangeCode(ctx, code, sess)
	if err != nil {
		return Credential{}, fmt.Errorf("%w [diag: %s]", err, c.getDiags())
	}
	return cred, nil
}

// authorizeCode walks the redirect chain from /oauth2/authorize to the callback,
// submitting the consent form if the account has not consented before.
func (c *Client) authorizeCode(ctx context.Context, sso string, sess pkceSession) (string, error) {
	cookie := sanitizeSessionCookies("sso=" + sso)
	next := sess.authorizeURL()
	consented := false

	for hop := 0; hop < maxAuthorizeHops; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", c.ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Cookie", cookie)
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		resp, err := c.http.Do(req)
		if err != nil {
			return "", err
		}
		loc := resp.Header.Get("Location")
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		cookie = sanitizeSessionCookies(mergeSetCookies(cookie, resp.Header))
		c.logDiag("pkce_authorize hop=%d status=%d loc=%q bodyLen=%d", hop, resp.StatusCode, trimLoc(loc), len(body))

		if isCallback(loc) {
			return codeFromCallback(loc, sess.state)
		}
		if err := locationError(loc); err != nil {
			return "", fmt.Errorf("pkce_authorize: %w", err)
		}
		if isSignInRedirect(loc) || isSignInRedirect(next) {
			return "", fmt.Errorf("sso_rejected authorize→sign-in (SSO cookie not accepted)")
		}
		if resp.StatusCode == 403 {
			return "", fmt.Errorf("challenge")
		}
		if isRedirect(resp.StatusCode) && loc != "" {
			next = absURL("https://auth.x.ai", loc)
			if !strings.Contains(next, "x.ai") {
				next = absURL("https://accounts.x.ai", loc)
			}
			continue
		}

		// Not a redirect. Either the consent screen, or a denial.
		if deniedBody(string(body)) {
			return "", fmt.Errorf("pkce_consent_denied")
		}
		if !isConsentPage(next) {
			preview := strings.TrimSpace(string(body))
			if len(preview) > 160 {
				preview = preview[:160]
			}
			return "", fmt.Errorf("pkce_unknown_page status=%d url=%q body=%q", resp.StatusCode, trimLoc(next), preview)
		}
		if consented {
			return "", fmt.Errorf("pkce_consent_loop: consent re-rendered after submit")
		}
		loc2, newCookie, err := c.submitConsent(ctx, next, string(body), cookie)
		if err != nil {
			return "", err
		}
		consented = true
		cookie = newCookie
		if isCallback(loc2) {
			return codeFromCallback(loc2, sess.state)
		}
		if loc2 == "" {
			return "", fmt.Errorf("pkce_consent_no_redirect")
		}
		next = absURL("https://auth.x.ai", loc2)
		if !strings.Contains(next, "x.ai") && !isCallback(loc2) {
			next = absURL("https://accounts.x.ai", loc2)
		}
	}
	return "", fmt.Errorf("pkce_authorize_hops_exhausted")
}

// submitConsent posts the authorize-flow consent form, reusing the same field
// scraping the device flow uses. Returns the response Location and cookie jar.
func (c *Client) submitConsent(ctx context.Context, consentURL, html, cookie string) (string, string, error) {
	fields, action := parseHTMLFormFields(html)
	// The authorize-flow consent form is a different component from the device
	// one, so log what was actually scraped: a denial caused by a field we never
	// sent is otherwise indistinguishable from an account-level refusal.
	names := make([]string, 0, len(fields))
	for k, vs := range fields {
		filled := len(vs) > 0 && vs[0] != ""
		names = append(names, fmt.Sprintf("%s=%t", k, filled))
	}
	sort.Strings(names)
	c.logDiag("pkce_consent_form action=%q fields[%s]", trimLoc(action), strings.Join(names, ","))
	if os.Getenv("GROK_OAUTH_DEBUG_HTML") == "1" {
		name := fmt.Sprintf("pkce_consent_%d.html", time.Now().UnixNano())
		if werr := os.WriteFile(name, []byte(html), 0o600); werr != nil {
			c.logDiag("pkce consent dump failed: %v", werr)
		} else {
			c.logDiag("pkce consent page dumped to %s", name)
		}
	}
	if action == "" {
		return "", cookie, fmt.Errorf("pkce_consent_form_missing")
	}
	form := url.Values{}
	for k, vs := range fields {
		switch k {
		case "action", "principal_id":
			continue
		}
		if len(vs) > 0 && vs[0] != "" {
			form.Set(k, vs[0])
		}
	}
	form.Set("action", "allow")
	if form.Get("principal_type") == "" {
		form.Set("principal_type", "User")
	}
	// Empty, deliberately, and sent rather than omitted. The consent bundle computes
	// principalId as `"Team" === principalType ? teamId : ""`, so consenting as a
	// User posts principal_id with no value.
	form.Set("principal_id", "")
	c.logDiag("pkce_consent page identity userId=%s", orDash(extractPrincipalID(html)))

	target := absURL(consentURL, action)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return "", cookie, err
	}
	c.setFormHeaders(req, consentURL, cookie)
	if refU, err := url.Parse(consentURL); err == nil && refU.Host != "" {
		req.Header.Set("Origin", refU.Scheme+"://"+refU.Host)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", cookie, err
	}
	loc := resp.Header.Get("Location")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	cookie = sanitizeSessionCookies(mergeSetCookies(cookie, resp.Header))
	c.logDiag("pkce_consent status=%d loc=%q bodyLen=%d pid=%t", resp.StatusCode, trimLoc(loc), len(body), form.Get("principal_id") != "")

	if err := locationError(loc); err != nil {
		return "", cookie, fmt.Errorf("pkce_consent: %w", err)
	}
	if deniedBody(string(body)) {
		return "", cookie, fmt.Errorf("pkce_consent_denied")
	}
	return loc, cookie, nil
}

// exchangeCode redeems the authorization code. Per RFC 6749 this call carries no
// cookies and no session — only the code, the verifier and the redirect_uri.
func (c *Client) exchangeCode(ctx context.Context, code string, sess pkceSession) (Credential, error) {
	_, tokEP, err := c.discover(ctx)
	if err != nil || tokEP == "" {
		tokEP = "https://auth.x.ai/oauth2/token"
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", ClientID)
	form.Set("code", code)
	form.Set("redirect_uri", RedirectURI)
	form.Set("code_verifier", sess.verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokEP, strings.NewReader(form.Encode()))
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)

	resp, err := c.http.Do(req)
	if err != nil {
		return Credential{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return Credential{}, fmt.Errorf("pkce_exchange_failed status=%d body=%s", resp.StatusCode, truncateBody(body, 200))
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return Credential{}, fmt.Errorf("pkce_exchange_bad_json: %w", err)
	}
	return credentialFrom(doc, tokEP)
}
