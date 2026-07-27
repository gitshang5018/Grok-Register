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
	"regexp"
	"sort"
	"strconv"
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
	// Carry the raw jar and sanitize only at send time. Sanitizing in the loop
	// discarded every Set-Cookie the consent page issued — including any CSRF or
	// oauth-state cookie — before the consent POST could present it back.
	cookie := "sso=" + sso
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
		req.Header.Set("Cookie", sanitizeSessionCookies(cookie))
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
		cookie = mergeSetCookies(cookie, resp.Header)
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
	if os.Getenv("GROK_OAUTH_DEBUG_HTML") == "1" {
		name := fmt.Sprintf("pkce_consent_%d.html", time.Now().UnixNano())
		if werr := os.WriteFile(name, []byte(html), 0o600); werr != nil {
			c.logDiag("pkce consent dump failed: %v", werr)
		} else {
			c.logDiag("pkce consent page dumped to %s", name)
		}
	}

	// Parse per form. The consent page carries several — sign out, deny, allow —
	// and the observed buttons all had empty name and value, so approval cannot be
	// a field on a shared form. Submitting the allow form itself is the approval.
	forms := parseForms(html)
	c.logDiag("pkce_consent_forms %s", describeForms(forms))
	c.logDiag("pkce_consent_cookies sent=%s dropped=%s", cookieNames(sanitizeSessionCookies(cookie)), droppedCookieNames(cookie))
	target, ok := approvalForm(forms)
	if !ok {
		return "", cookie, fmt.Errorf("pkce_consent_no_approval_form forms=[%s]", describeForms(forms))
	}
	if target.Action == "" {
		return "", cookie, fmt.Errorf("pkce_consent_form_missing_action")
	}

	// Forward that form's own fields verbatim, empty ones included: a browser posts
	// principal_id= and referrer= with no value rather than omitting them, and the
	// page's client_id / state / nonce / code_challenge / scope must travel back
	// unmodified.
	form := url.Values{}
	for k, vs := range target.Fields {
		v := ""
		if len(vs) > 0 {
			v = vs[0]
		}
		form.Set(k, v)
	}
	// Always set action=allow to confirm approval. auth.x.ai requires action=allow
	// when Allow and Deny share a form (or when validating consent action).
	form.Set("action", "allow")
	// A named approval button contributes its own pair when it has one.
	for _, b := range target.Buttons {
		if b.Name != "" && isApproveLabel(b) && !isDenyLabel(b) {
			form.Set(b.Name, b.Value)
			c.logDiag("pkce_consent approval button %s=%s", b.Name, orDash(b.Value))
			break
		}
	}
	if form.Get("principal_type") == "" {
		form.Set("principal_type", "User")
	}
	// Deliberately empty. The consent bundle computes principalId as
	// `"Team" === principalType ? teamId : ""`, so a User consent posts no value.
	if !form.Has("principal_id") {
		form.Set("principal_id", "")
	}
	c.logDiag("pkce_consent page identity userId=%s", orDash(extractPrincipalID(html)))

	// Next.js App Router / RSC Server Action consent path (accounts.x.ai modern consent).
	// Try Server Action submitOAuth2Consent first.
	if saLoc, saCookie, ok := submitServerActionConsent(ctx, c, consentURL, html, cookie, form); ok {
		c.logDiag("pkce_consent Server Action succeeded: loc=%q", trimLoc(saLoc))
		return saLoc, saCookie, nil
	}
	c.logDiag("pkce_consent Server Action did not yield code -> fallback to form POST")

	action := target.Action
	// A button may override the form's action attribute.
	for _, b := range target.Buttons {
		if b.FormAction != "" && isApproveLabel(b) && !isDenyLabel(b) {
			action = b.FormAction
			c.logDiag("pkce_consent using button formaction %q", trimLoc(action))
			break
		}
	}
	postTarget := absURL(consentURL, action)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postTarget, strings.NewReader(form.Encode()))
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
	cookie = mergeSetCookies(cookie, resp.Header)
	c.logDiag("pkce_consent status=%d loc=%q bodyLen=%d pid=%t", resp.StatusCode, trimLoc(loc), len(body), form.Get("principal_id") != "")

	if err := locationError(loc); err != nil {
		return "", cookie, fmt.Errorf("pkce_consent: %w", err)
	}
	if deniedBody(string(body)) {
		return "", cookie, fmt.Errorf("pkce_consent_denied")
	}
	return loc, cookie, nil
}

type rscConsentPayload struct {
	Action              string `json:"action"`
	ClientID            string `json:"clientId"`
	RedirectURI         string `json:"redirectUri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	Nonce               string `json:"nonce"`
	PrincipalType       string `json:"principalType"`
	PrincipalID         string `json:"principalId"`
	Referrer            string `json:"referrer"`
}

var (
	// Next.js SERVER_REFERENCE_ID_LENGTH is 42. Older builds used 40; accept
	// the full production range so a length mismatch cannot silence discovery.
	rxServerAction1 = regexp.MustCompile(`(?i)createServerReference\)?\([^"]*"([a-f0-9]{40,64})"`)
	rxServerAction2 = regexp.MustCompile(`(?i)registerServerReference\([^"]*"([a-f0-9]{40,64})"`)
	rxServerAction3 = regexp.MustCompile(`(?i)(?:next-action|serverReference|actionId|action_id|\$ACTION_ID_?)[^a-f0-9]+([a-f0-9]{40,64})`)
	rxServerAction4 = regexp.MustCompile(`(?i)([a-f0-9]{40,64}).{0,1000}submitOAuth2Consent`)
	rxServerAction5 = regexp.MustCompile(`(?i)submitOAuth2Consent.{0,1000}([a-f0-9]{40,64})`)
	rxServerAction6 = regexp.MustCompile(`(?i)submitOAuth2Consent[^a-f0-9]{0,80}(?:id["']?\s*[:=]\s*["']?)([a-f0-9]{40,64})`)
	rxHexActionID   = regexp.MustCompile(`(?i)(?:^|[^a-f0-9])([a-f0-9]{40,64})(?:[^a-f0-9]|$)`)
	rxScriptSrc     = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	rxModulePreload = regexp.MustCompile(`(?i)<link[^>]+ rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+)["']|<link[^>]+href=["']([^"']+)["'][^>]+rel=["'](?:modulepreload|preload)["']`)
	rxCodeJSON      = regexp.MustCompile(`(?i)"code"\s*:\s*"([^"]+)"`)
	rxCodeQuery     = regexp.MustCompile(`(?i)(?:[?&]|\\u0026)code=([A-Za-z0-9._~\-]+)`)
)

// defaultConsentActionID is a last-resort 40-char id from an older build. Live
// pages ship 42-char ids; this only runs when discovery finds nothing else.
const defaultConsentActionID = "4005315a1d7e426de592990bb54bb37471f39dd6d2"

// nextServerReferenceIDLen is packages/next SERVER_REFERENCE_ID_LENGTH.
const nextServerReferenceIDLen = 42

const maxConsentScriptFetches = 48

func resolveURL(baseURL, ref string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ref
	}
	refU, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(refU).String()
}

// serverActionSubmitURL is the document URL the browser posts the Server Action
// to. The full query string must be kept — it carries the OAuth request context.
func serverActionSubmitURL(consentURL string) string {
	return strings.TrimSpace(consentURL)
}

// actionRedirectLocation reads the redirect a Next.js Server Action produced.
// Successful external redirects typically arrive as x-action-redirect rather
// than Location when Accept is text/x-component.
func actionRedirectLocation(origin string, headers map[string]string, fallbackLoc string) string {
	for _, key := range []string{
		"X-Action-Redirect", "x-action-redirect",
		"X-Action-Redirect-Location", "x-action-redirect-location",
	} {
		if v := strings.TrimSpace(headers[key]); v != "" {
			return absURL(origin, v)
		}
	}
	if fallbackLoc != "" {
		return fallbackLoc
	}
	return ""
}

func actionRedirectFromHTTP(origin string, h http.Header, fallbackLoc string) string {
	headers := map[string]string{}
	for _, key := range []string{
		"Location",
		"X-Action-Redirect", "x-action-redirect",
		"X-Action-Redirect-Location", "x-action-redirect-location",
	} {
		if v := h.Get(key); v != "" {
			headers[key] = v
		}
	}
	if loc := actionRedirectLocation(origin, headers, ""); loc != "" {
		return loc
	}
	return fallbackLoc
}

func scriptFetchPriority(src string) int {
	low := strings.ToLower(src)
	switch {
	case strings.Contains(low, "consent"), strings.Contains(low, "oauth"):
		return 0
	case strings.Contains(low, "/app/"), strings.Contains(low, "page-"), strings.Contains(low, "page."):
		return 1
	case strings.Contains(low, "chunk"), strings.Contains(low, "_next"):
		return 2
	default:
		return 3
	}
}

func collectConsentAssetURLs(consentURL, html string) []string {
	seen := map[string]struct{}{}
	var ranked []struct {
		pri int
		u   string
	}
	add := func(ref string, pri int) {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "data:") {
			return
		}
		u := resolveURL(consentURL, ref)
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		ranked = append(ranked, struct {
			pri int
			u   string
		}{pri, u})
	}
	for _, m := range rxScriptSrc.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			add(m[1], scriptFetchPriority(m[1]))
		}
	}
	for _, m := range rxModulePreload.FindAllStringSubmatch(html, -1) {
		ref := ""
		if len(m) > 1 && m[1] != "" {
			ref = m[1]
		} else if len(m) > 2 {
			ref = m[2]
		}
		if ref != "" {
			add(ref, scriptFetchPriority(ref))
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].pri < ranked[j].pri
	})
	out := make([]string, 0, len(ranked))
	for _, r := range ranked {
		out = append(out, r.u)
	}
	return out
}

// actionIDInfo decodes the first byte of a Next.js server-reference id.
// See packages/next/src/shared/lib/server-reference-info.ts.
type actionIDInfo struct {
	UseCache bool
	ArgCount int
}

func actionIDMeta(id string) actionIDInfo {
	id = strings.TrimSpace(strings.ToLower(id))
	if len(id) < 2 {
		return actionIDInfo{}
	}
	infoByte, err := strconv.ParseUint(id[:2], 16, 8)
	if err != nil {
		return actionIDInfo{}
	}
	typeBit := (infoByte >> 7) & 0x1
	argMask := (infoByte >> 1) & 0x3f
	restArgs := infoByte & 0x1
	n := 0
	for i := 0; i < 6; i++ {
		if (argMask>>(5-i))&0x1 == 1 {
			n++
		}
	}
	if restArgs == 1 && n < 6 {
		// rest parameter — treat as "at least n+1" for encoding purposes
		n++
	}
	return actionIDInfo{UseCache: typeBit == 1, ArgCount: n}
}

// rankActionIDs drops use-cache ids and prefers consent-linked / 1-arg actions.
// linked marks ids found near submitOAuth2Consent symbols in page bundles.
func rankActionIDs(ids []string, linked map[string]bool) []string {
	var out []string
	for _, id := range ids {
		if actionIDMeta(id).UseCache {
			continue
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		return out
	}
	score := func(id string) int {
		s := 10
		if linked != nil && linked[id] {
			s -= 5
		}
		meta := actionIDMeta(id)
		switch meta.ArgCount {
		case 1:
			s -= 3
		case 0:
			s -= 1
		}
		switch {
		case len(id) == nextServerReferenceIDLen && id != defaultConsentActionID:
			s -= 2
		case id == defaultConsentActionID:
			s += 20
		case len(id) == 40 || len(id) == 64:
			s += 2
		}
		return s
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := score(out[i]), score(out[j])
		if si != sj {
			return si < sj
		}
		return false
	})
	return out
}

func extractActionIDsFromText(text string, addID func(string), markLinked func(string)) {
	consentHot := strings.Contains(text, "submitOAuth2Consent") ||
		strings.Contains(text, "OAuth2Consent") ||
		strings.Contains(text, "oauth2/consent")

	for _, rx := range []*regexp.Regexp{
		rxServerAction1, rxServerAction2, rxServerAction3,
		rxServerAction4, rxServerAction5, rxServerAction6,
	} {
		for _, m := range rx.FindAllStringSubmatch(text, -1) {
			if len(m) > 1 {
				id := strings.ToLower(m[1])
				addID(id)
				// Patterns 4/5/6 already sit next to submitOAuth2Consent.
				if rx == rxServerAction4 || rx == rxServerAction5 || rx == rxServerAction6 || consentHot {
					if markLinked != nil {
						markLinked(id)
					}
				}
			}
		}
	}
	// Minified / RSC flight: only scan sources that mention consent machinery,
	// but accept the modern 42-char length (previous scanner missed it).
	if consentHot ||
		strings.Contains(text, "createServerReference") ||
		strings.Contains(text, "registerServerReference") ||
		strings.Contains(text, "Next-Action") ||
		strings.Contains(text, "$ACTION") {
		for _, m := range rxHexActionID.FindAllStringSubmatch(text, -1) {
			if len(m) > 1 {
				id := strings.ToLower(m[1])
				addID(id)
				if consentHot && markLinked != nil {
					// Only mark when the id sits near the consent symbol.
					if idx := strings.Index(strings.ToLower(text), id); idx >= 0 {
						window := text[max(0, idx-200):min(len(text), idx+len(id)+200)]
						if strings.Contains(window, "submitOAuth2Consent") ||
							strings.Contains(window, "OAuth2Consent") {
							markLinked(id)
						}
					}
				}
			}
		}
	}
}

func discoverConsentActionIDs(ctx context.Context, c *Client, consentURL, html string) []string {
	var sources []string
	sources = append(sources, html)

	assets := collectConsentAssetURLs(consentURL, html)
	fetched := 0
	for _, scriptURL := range assets {
		if fetched >= maxConsentScriptFetches {
			break
		}
		if c == nil || c.http == nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", c.ua)
		resp, err := c.http.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		_ = resp.Body.Close()
		if len(body) > 0 {
			sources = append(sources, string(body))
		}
		fetched++
	}
	if c != nil {
		c.logDiag("pkce_consent fetched %d script bundles from consent page", fetched)
	}

	var ids []string
	linked := map[string]bool{}
	addID := func(id string) {
		id = strings.TrimSpace(strings.ToLower(id))
		if id == "" || !isPlausibleActionID(id) {
			return
		}
		for _, existing := range ids {
			if existing == id {
				return
			}
		}
		ids = append(ids, id)
	}
	markLinked := func(id string) {
		id = strings.TrimSpace(strings.ToLower(id))
		if id != "" {
			linked[id] = true
		}
	}

	for _, srcText := range sources {
		extractActionIDsFromText(srcText, addID, markLinked)
	}

	// Only keep the stale default when nothing live was found.
	if len(ids) == 0 {
		addID(defaultConsentActionID)
	}
	return rankActionIDs(ids, linked)
}

func isPlausibleActionID(id string) bool {
	n := len(id)
	if n < 40 || n > 64 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// actionBody is one candidate Server Action request body.
type actionBody struct {
	kind    string // "json" | "multipart"
	payload string
	ctype   string
	label   string
}

// encodeServerActionBodies builds React encodeReply-compatible argument bodies
// for a given action id. 0-arg actions MUST receive "[]".
//
// 1-arg consent actions observed in the wild take either a plain "allow"
// string or a FormData of the hidden form fields — NOT a free-form JSON object
// of camelCase keys (that shape only re-renders the page: 200, no redirect).
func encodeServerActionBodies(actionID string, form url.Values) []string {
	var out []string
	for _, b := range encodeServerActionBodyList(actionID, form) {
		if b.kind == "multipart" {
			out = append(out, "multipart:"+b.payload)
		} else {
			out = append(out, b.payload)
		}
	}
	return out
}

func encodeServerActionBodyList(actionID string, form url.Values) []actionBody {
	meta := actionIDMeta(actionID)
	if meta.UseCache {
		return nil
	}
	if meta.ArgCount == 0 {
		return []actionBody{{kind: "json", payload: "[]", ctype: "text/plain;charset=UTF-8", label: "empty-args"}}
	}

	var out []actionBody
	addJSON := func(label string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		s := string(b)
		for _, existing := range out {
			if existing.kind == "json" && existing.payload == s {
				return
			}
		}
		out = append(out, actionBody{kind: "json", payload: s, ctype: "text/plain;charset=UTF-8", label: label})
	}

	// 1) Most likely for type=button Allow: submitOAuth2Consent("allow")
	addJSON("allow-string", []any{"allow"})
	addJSON("approve-string", []any{"approve"})
	addJSON("true-bool", []any{true})

	// 2) FormData of the hidden consent fields.
	if mp, boundary, err := buildConsentMultipart(form); err == nil {
		out = append(out, actionBody{
			kind:    "multipart",
			payload: mp,
			ctype:   "multipart/form-data; boundary=" + boundary,
			label:   "formdata",
		})
	}

	// 3) Structured object variants (last resorts; previously produced 510B no-ops).
	camel := rscConsentPayload{
		Action:              firstNonEmpty(form.Get("action"), "allow"),
		ClientID:            form.Get("client_id"),
		RedirectURI:         form.Get("redirect_uri"),
		Scope:               form.Get("scope"),
		State:               form.Get("state"),
		CodeChallenge:       form.Get("code_challenge"),
		CodeChallengeMethod: form.Get("code_challenge_method"),
		Nonce:               form.Get("nonce"),
		PrincipalType:       firstNonEmpty(form.Get("principal_type"), "User"),
		PrincipalID:         form.Get("principal_id"),
		Referrer:            form.Get("referrer"),
	}
	snake := map[string]string{
		"action":                camel.Action,
		"client_id":             camel.ClientID,
		"redirect_uri":          camel.RedirectURI,
		"scope":                 camel.Scope,
		"state":                 camel.State,
		"code_challenge":        camel.CodeChallenge,
		"code_challenge_method": camel.CodeChallengeMethod,
		"nonce":                 camel.Nonce,
		"principal_type":        camel.PrincipalType,
		"principal_id":          camel.PrincipalID,
		"referrer":              camel.Referrer,
	}
	addJSON("camel-obj", []any{camel})
	addJSON("snake-obj", []any{snake})
	return out
}

func buildConsentMultipart(form url.Values) (body, boundary string, err error) {
	boundary = "----WebKitFormBoundary" + hex.EncodeToString(mustRand(8))
	var b strings.Builder
	keys := []string{
		"action", "client_id", "code_challenge", "code_challenge_method",
		"nonce", "principal_id", "principal_type", "redirect_uri", "referrer",
		"scope", "state",
	}
	seen := map[string]bool{}
	writeField := func(k, v string) {
		seen[k] = true
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		fmt.Fprintf(&b, "Content-Disposition: form-data; name=%q\r\n\r\n", k)
		b.WriteString(v)
		b.WriteString("\r\n")
	}
	for _, k := range keys {
		if form.Has(k) {
			writeField(k, form.Get(k))
		} else if k == "action" {
			writeField("action", "allow")
		}
	}
	if !seen["action"] {
		writeField("action", firstNonEmpty(form.Get("action"), "allow"))
	}
	for k := range form {
		if !seen[k] {
			writeField(k, form.Get(k))
		}
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String(), boundary, nil
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i * 3))
		}
	}
	return b
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// parseFlightRows splits a Next.js RSC flight body into id → raw payload.
func parseFlightRows(body string) map[string]string {
	rows := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		id, payload := line[:i], line[i+1:]
		if _, err := strconv.Atoi(id); err != nil {
			continue
		}
		rows[id] = payload
	}
	return rows
}

// parseFlightActionResult resolves the Server Action return value from an RSC
// flight body. Envelope row 0 is typically {"a":"$@1",…}; the real value lives
// in the referenced row (often row 1).
func parseFlightActionResult(body string) string {
	rows := parseFlightRows(body)
	if len(rows) == 0 {
		return ""
	}
	if env, ok := rows["0"]; ok {
		var meta struct {
			A string `json:"a"`
		}
		if json.Unmarshal([]byte(env), &meta) == nil && strings.HasPrefix(meta.A, "$@") {
			ref := strings.TrimPrefix(meta.A, "$@")
			if v, ok := rows[ref]; ok {
				return strings.TrimSpace(v)
			}
		}
		if meta.A != "" && !strings.HasPrefix(meta.A, "$") {
			return meta.A
		}
	}
	if v, ok := rows["1"]; ok {
		return strings.TrimSpace(v)
	}
	bestID, bestVal := -1, ""
	for id, v := range rows {
		n, err := strconv.Atoi(id)
		if err != nil || n == 0 {
			continue
		}
		if n > bestID {
			bestID, bestVal = n, v
		}
	}
	return strings.TrimSpace(bestVal)
}

// extractCodeFromActionBody pulls an authorization code out of a Next.js
// Server Action RSC / plain response body.
func extractCodeFromActionBody(body, redirectURI, state string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	result := parseFlightActionResult(body)
	for _, src := range []string{result, body} {
		if src == "" {
			continue
		}
		if m := rxCodeJSON.FindStringSubmatch(src); len(m) > 1 {
			return fmt.Sprintf("%s?code=%s&state=%s", redirectURI, m[1], state)
		}
		if u := findCallbackURL(src); u != "" {
			return u
		}
		if m := rxCodeQuery.FindStringSubmatch(src); len(m) > 1 {
			return fmt.Sprintf("%s?code=%s&state=%s", redirectURI, m[1], state)
		}
	}
	return ""
}

var rxCallbackURL = regexp.MustCompile(`https?://[^"'\s\\]+(?:callback|/oauth)[^"'\s\\]*code=[A-Za-z0-9._~\-]+[^"'\s\\]*`)

func findCallbackURL(body string) string {
	unesc := strings.ReplaceAll(body, `\u0026`, "&")
	unesc = strings.ReplaceAll(unesc, `\/`, `/`)
	unesc = strings.ReplaceAll(unesc, `\\u0026`, "&")
	if m := rxCallbackURL.FindString(unesc); m != "" {
		return m
	}
	rxQuoted := regexp.MustCompile(`"(https?://[^"]*code=[^"]+)"`)
	if m := rxQuoted.FindStringSubmatch(unesc); len(m) > 1 {
		return strings.ReplaceAll(m[1], `\u0026`, "&")
	}
	return ""
}

func bodyPreview(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func bodyTailPreview(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

func submitServerActionConsent(ctx context.Context, c *Client, consentURL, html, cookie string, form url.Values) (string, string, bool) {
	actionIDs := discoverConsentActionIDs(ctx, c, consentURL, html)
	c.logDiag("pkce_consent discovered %d server action IDs: %v", len(actionIDs), actionIDs)
	if len(actionIDs) == 0 {
		return "", cookie, false
	}

	submitURL := serverActionSubmitURL(consentURL)
	origin := "https://accounts.x.ai"
	if u, err := url.Parse(consentURL); err == nil && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}

	routerTree := "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(auth)%22%2C%7B%22children%22%3A%5B%22oauth2%22%2C%7B%22children%22%3A%5B%22consent%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D%7D%5D%7D%5D%7D%5D%7D%2C%22%24undefined%22%2C%22%24undefined%22%2C16%5D"

	for _, actionID := range actionIDs {
		bodies := encodeServerActionBodyList(actionID, form)
		if len(bodies) == 0 {
			continue
		}
		meta := actionIDMeta(actionID)
		tag := actionID
		if len(tag) > 16 {
			tag = tag[:16]
		}
		c.logDiag("pkce server action %s meta useCache=%v args=%d bodies=%d", tag, meta.UseCache, meta.ArgCount, len(bodies))

		for bi, ab := range bodies {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL, strings.NewReader(ab.payload))
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", c.ua)
			req.Header.Set("Accept", "text/x-component")
			req.Header.Set("Content-Type", ab.ctype)
			req.Header.Set("Next-Action", actionID)
			req.Header.Set("Next-Router-State-Tree", routerTree)
			req.Header.Set("Origin", origin)
			req.Header.Set("Referer", consentURL)
			req.Header.Set("Cookie", sanitizeSessionCookies(cookie))
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Dest", "empty")

			resp, err := c.http.Do(req)
			if err != nil {
				c.logDiag("pkce server action %s body#%d(%s) HTTP error: %v", tag, bi, ab.label, err)
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			cookie = mergeSetCookies(cookie, resp.Header)
			bodyStr := string(body)

			rawLoc := resp.Header.Get("Location")
			xar := resp.Header.Get("X-Action-Redirect")
			if xar == "" {
				xar = resp.Header.Get("x-action-redirect")
			}
			loc := actionRedirectFromHTTP(origin, resp.Header, rawLoc)
			if i := strings.IndexByte(loc, ';'); i >= 0 {
				loc = loc[:i]
			}
			actionResult := parseFlightActionResult(bodyStr)
			c.logDiag("pkce server action %s body#%d(%s) status=%d loc=%q x-action-redirect=%q bodyLen=%d result=%q tail=%q",
				tag, bi, ab.label, resp.StatusCode, trimLoc(rawLoc), trimLoc(xar), len(body),
				bodyPreview(actionResult, 160), bodyTailPreview(bodyStr, 160))

			if strings.Contains(loc, "code=") {
				return loc, cookie, true
			}
			if isCallback(loc) {
				c.logDiag("pkce server action %s body#%d(%s) callback without code: %q", tag, bi, ab.label, trimLoc(loc))
				continue
			}

			if synth := extractCodeFromActionBody(bodyStr, form.Get("redirect_uri"), form.Get("state")); synth != "" {
				c.logDiag("pkce server action %s body#%d(%s) extracted code from body", tag, bi, ab.label)
				return synth, cookie, true
			}

			if resp.StatusCode == 404 ||
				resp.Header.Get("x-action-not-found") == "1" ||
				resp.Header.Get("X-Action-Not-Found") == "1" {
				break
			}
		}
	}
	return "", cookie, false
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
