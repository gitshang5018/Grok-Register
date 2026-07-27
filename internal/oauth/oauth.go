package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/grok-free-register/grok-reg/internal/clearance"
)

// ErrRateLimited is returned when auth.x.ai redirects with error=rate_limited.
var ErrRateLimited = errors.New("rate_limited")

const (
	DiscoveryURL = "https://auth.x.ai/.well-known/openid-configuration"
	ClientID     = "b1a00492-073a-47ea-816f-4c329264a828"
	Scope        = "openid profile email offline_access grok-cli:access api:access"
	VerifyURL    = "https://auth.x.ai/oauth2/device/verify"
	ApproveURL   = "https://auth.x.ai/oauth2/device/approve"
	DefaultUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

type DeviceFlow struct {
	DeviceCode      string
	UserCode        string
	VerificationURL string
	ExpiresIn       int
	Interval        float64
	TokenEndpoint   string
}

type Credential struct {
	AccessToken   string
	RefreshToken  string
	IDToken       string
	TokenType     string
	ExpiresIn     int
	ExpiresAt     string
	LastRefresh   string
	Subject       string
	TokenEndpoint string
	Email         string
}

type Client struct {
	http  tls_client.HttpClient
	ua    string
	clear *clearance.Manager

	// rate limit gate
	mu        sync.Mutex
	trippedAt time.Time
	nextProbe time.Time
	cooldown  time.Duration
	baseCool  time.Duration
	trips     int

	discMu   sync.Mutex
	deviceEP string
	tokenEP  string
	discAt   time.Time

	diagMu sync.Mutex
	diags  []string
}

func NewClient(proxy string, cm *clearance.Manager, baseCooldown time.Duration) (*Client, error) {
	if baseCooldown <= 0 {
		baseCooldown = 60 * time.Second
	}
	// Match registration leg: Chrome TLS fingerprint. Plain net/http was getting
	// fake /device/done redirects while token poll still returned invalid_grant.
	// No cookie jar: we manage the SSO session Cookie header explicitly so jar
	// auto-attach cannot duplicate / poison cookies across auth.x.ai hosts.
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(45),
		tls_client.WithClientProfile(profiles.Chrome_131),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithNotFollowRedirects(),
	}
	if strings.TrimSpace(proxy) != "" {
		opts = append(opts, tls_client.WithProxyUrl(strings.TrimSpace(proxy)))
	}
	cli, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, err
	}
	c := &Client{
		http:     cli,
		ua:       DefaultUA,
		clear:    cm,
		baseCool: baseCooldown,
		cooldown: baseCooldown,
	}
	if cm != nil {
		if ua := cm.UserAgent(); ua != "" {
			c.ua = ua
		}
	}
	return c, nil
}

func (c *Client) logDiag(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprint(os.Stderr, "[oauth-diag] ", msg, "\n")
	c.diagMu.Lock()
	if len(c.diags) > 50 {
		c.diags = c.diags[1:]
	}
	c.diags = append(c.diags, msg)
	c.diagMu.Unlock()
}

func (c *Client) clearDiags() {
	c.diagMu.Lock()
	c.diags = nil
	c.diagMu.Unlock()
}

func (c *Client) getDiags() string {
	c.diagMu.Lock()
	defer c.diagMu.Unlock()
	return strings.Join(c.diags, " | ")
}

func trimLoc(loc string) string {
	if len(loc) > 80 {
		return loc[:80] + "…"
	}
	return loc
}

func (c *Client) WaitRateLimit(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.trippedAt.IsZero() {
			c.mu.Unlock()
			return nil
		}
		now := time.Now()
		if now.Before(c.nextProbe) {
			wait := time.Until(c.nextProbe)
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
				continue
			}
		}
		// Allow one probe, then re-arm the gate. Without re-arming, the window stays
		// open forever once nextProbe passes, so every worker probes simultaneously
		// and immediately re-trips the limiter.
		c.nextProbe = now.Add(c.cooldown)
		c.mu.Unlock()
		return nil
	}
}

func (c *Client) TripRateLimit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.trippedAt.IsZero() {
		c.trippedAt = now
		c.trips = 1
	} else {
		c.trips++
	}
	// growth 1.5^n capped 300s
	cool := float64(c.baseCool) * pow15(c.trips-1)
	if cool > float64(300*time.Second) {
		cool = float64(300 * time.Second)
	}
	c.cooldown = time.Duration(cool)
	c.nextProbe = now.Add(c.cooldown)
}

func (c *Client) ClearRateLimit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trippedAt = time.Time{}
	c.nextProbe = time.Time{}
	c.trips = 0
	c.cooldown = c.baseCool
}

func pow15(n int) float64 {
	v := 1.0
	for i := 0; i < n; i++ {
		v *= 1.5
	}
	return v
}

func (c *Client) StartDeviceFlow(ctx context.Context) (DeviceFlow, error) {
	devEP, tokEP, err := c.discover(ctx)
	if err != nil {
		return DeviceFlow{}, err
	}
	form := url.Values{}
	form.Set("client_id", ClientID)
	form.Set("scope", Scope)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, devEP, strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceFlow{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return DeviceFlow{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode == 429 {
			c.TripRateLimit()
			return DeviceFlow{}, fmt.Errorf("%w: device authorization status=429", ErrRateLimited)
		}
		return DeviceFlow{}, fmt.Errorf("device authorization rejected status=%d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return DeviceFlow{}, err
	}
	dc, _ := doc["device_code"].(string)
	uc, _ := doc["user_code"].(string)
	baseURL, _ := doc["verification_uri"].(string)
	if baseURL == "" {
		baseURL, _ = doc["verification_url"].(string)
	}
	exp, _ := doc["expires_in"].(float64)
	interval, _ := doc["interval"].(float64)
	if interval <= 0 {
		interval = 5
	}
	vurl, _ := doc["verification_uri_complete"].(string)
	if vurl == "" {
		sep := "?"
		if strings.Contains(baseURL, "?") {
			sep = "&"
		}
		vurl = baseURL + sep + "user_code=" + url.QueryEscape(uc)
	}
	return DeviceFlow{
		DeviceCode:      dc,
		UserCode:        uc,
		VerificationURL: vurl,
		ExpiresIn:       int(exp),
		Interval:        interval,
		TokenEndpoint:   tokEP,
	}, nil
}

func (c *Client) discover(ctx context.Context) (deviceEP, tokenEP string, err error) {
	c.discMu.Lock()
	if c.deviceEP != "" && c.tokenEP != "" && time.Since(c.discAt) < 30*time.Minute {
		d, t := c.deviceEP, c.tokenEP
		c.discMu.Unlock()
		return d, t, nil
	}
	c.discMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DiscoveryURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("discovery rejected")
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", "", err
	}
	deviceEP, _ = doc["device_authorization_endpoint"].(string)
	tokenEP, _ = doc["token_endpoint"].(string)
	if deviceEP == "" || tokenEP == "" {
		return "", "", fmt.Errorf("discovery missing endpoints")
	}
	c.discMu.Lock()
	c.deviceEP, c.tokenEP, c.discAt = deviceEP, tokenEP, time.Now()
	c.discMu.Unlock()
	return deviceEP, tokenEP, nil
}

func isDeviceDone(loc string) bool {
	if loc == "" {
		return false
	}
	u, err := url.Parse(loc)
	if err != nil {
		return strings.Contains(loc, "/oauth2/device/done")
	}
	if q := u.Query(); q.Get("error") != "" || q.Get("policy") == "deny" {
		return false
	}
	p := u.Path
	return strings.Contains(p, "/oauth2/device/done") || strings.HasSuffix(p, "/device/done")
}

// isAccountLanding reports the generic signed-in landing pages. auth.x.ai bounces there
// after a REJECTED approve as well, so landing here proves the session is alive but says
// nothing about whether the device grant was recorded.
func isAccountLanding(loc string) bool {
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	p := u.Path
	return p == "/account" || strings.HasPrefix(p, "/console")
}

func isSignInRedirect(loc string) bool {
	low := strings.ToLower(loc)
	return strings.Contains(low, "/sign-in") ||
		strings.Contains(low, "/login") ||
		strings.Contains(low, "signin") ||
		strings.Contains(low, "login_required")
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

func absURL(baseHost, loc string) string {
	if loc == "" {
		return ""
	}
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc
	}
	if strings.HasPrefix(loc, "/") {
		return baseHost + loc
	}
	return loc
}

var scriptBlockRe = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)

// visibleText drops inline <script> blocks before any text matching. accounts.x.ai is a
// Next.js app that inlines its entire i18n message catalog into the RSC payload of every
// server-rendered page, so the success string, the denial string and the error strings
// all appear verbatim in the markup of the *pre-approval* consent page. Matching the raw
// body made authorizedBody return true for every response, which turned each rejected
// approve into a false success and left the real error invisible.
func visibleText(body string) string {
	return scriptBlockRe.ReplaceAllString(body, " ")
}

func deniedText(visible string) bool {
	low := strings.ToLower(visible)
	return strings.Contains(low, "authorization denied") ||
		strings.Contains(low, "authorization was denied") ||
		strings.Contains(visible, "授权已拒绝") ||
		strings.Contains(visible, "已拒绝授权")
}

// deniedBody reports an explicit denial rendered in the page body.
func deniedBody(body string) bool {
	return deniedText(visibleText(body))
}

func authorizedBody(body string) bool {
	visible := visibleText(body)
	if deniedText(visible) {
		return false
	}
	low := strings.ToLower(visible)
	return strings.Contains(low, "device authorized") ||
		strings.Contains(visible, "设备已授权") ||
		strings.Contains(low, "you have authorized") ||
		strings.Contains(low, "device is authorized")
}

// ConfirmHTTP posts verify + approve with SSO cookie (no browser).
// Success only when device is actually marked authorized (done path / body text).
// Accepting arbitrary redirects was causing token poll invalid_grant (Access denied).
func (c *Client) ConfirmHTTP(ctx context.Context, sso string, flow DeviceFlow) error {
	sso = strings.TrimSpace(sso)
	if sso == "" {
		return fmt.Errorf("login_required")
	}
	cookie := "sso=" + sso

	// Warm: open verification page so auth.x.ai sees cookie session (optional).
	if flow.VerificationURL != "" {
		warmSt, _, warmCookie, warmErr := c.getWithCookie(ctx, flow.VerificationURL, cookie)
		if warmErr == nil && warmCookie != "" {
			cookie = sanitizeSessionCookies(warmCookie)
		}
		c.logDiag("confirm_warm status=%d err=%v cookies=%s", warmSt, warmErr, cookieNames(cookie))
	}

	// verify
	form := url.Values{"user_code": {flow.UserCode}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, VerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	c.setFormHeaders(req, flow.VerificationURL, cookie)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	loc := resp.Header.Get("Location")
	vbody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	// Merge any Set-Cookie (session) into cookie jar string for subsequent posts.
	cookie = sanitizeSessionCookies(mergeSetCookies(cookie, resp.Header))
	c.logDiag("confirm_verify status=%d loc=%q bodyLen=%d cookies=%s", resp.StatusCode, trimLoc(loc), len(vbody), cookieNames(cookie))
	if err := locationError(loc); err != nil {
		if errors.Is(err, ErrRateLimited) {
			c.TripRateLimit()
		}
		return err
	}
	if resp.StatusCode == 403 {
		return fmt.Errorf("challenge")
	}
	if isSignInRedirect(loc) {
		return fmt.Errorf("sso_rejected verify→sign-in (SSO cookie not accepted by auth.x.ai)")
	}
	if isDeviceDone(loc) {
		c.logDiag("confirm_verify → done (fast path)")
		c.ClearRateLimit()
		return nil
	}
	if authorizedBody(string(vbody)) && isRedirect(resp.StatusCode) {
		c.logDiag("confirm_verify → authorized (body match)")
		c.ClearRateLimit()
		return nil
	}
	if !isRedirect(resp.StatusCode) && loc == "" {
		preview := strings.TrimSpace(string(vbody))
		if len(preview) > 120 {
			preview = preview[:120]
		}
		return fmt.Errorf("device_verify_failed status=%d body=%q", resp.StatusCode, preview)
	}

	consentRef := absURL("https://accounts.x.ai", loc)
	if consentRef == "" {
		consentRef = "https://accounts.x.ai/oauth2/device/consent?user_code=" + url.QueryEscape(flow.UserCode)
	}
	if isSignInRedirect(consentRef) {
		return fmt.Errorf("sso_rejected verify→%s", consentRef)
	}
	// Diagnostic context for operators (short).
	_ = fmt.Sprintf("verify status=%d loc=%s", resp.StatusCode, trimLoc(loc))

	// Base approve form. principal_id stays EMPTY: the consent bundle computes it as
	// `"Team" === principalType ? teamId : ""`, so a browser consenting as a User
	// posts principal_id= with no value. Filling it with the page's userId — which
	// this code used to do — sends a field the browser never sends.
	aform := url.Values{
		"user_code":      {flow.UserCode},
		"action":         {"allow"},
		"principal_type": {"User"},
		"principal_id":   {""},
	}
	// Prefer auth.x.ai approve (matches consent form action). accounts.x.ai may 30x.
	approveTarget := ApproveURL
	if fields, htmlCookie, formAction := c.loadConsentForm(ctx, consentRef, cookie); len(fields) > 0 || formAction != "" {
		cookie = sanitizeSessionCookies(htmlCookie)
		if formAction != "" {
			approveTarget = absURL(consentRef, formAction)
			c.logDiag("dynamic form action: %q", approveTarget)
		}
		for k, vs := range fields {
			switch k {
			case "action":
				continue // never take empty/deny from page
			case "principal_id":
				continue // page value is authoritative and is empty for User
			}
			if len(vs) > 0 && vs[0] != "" {
				aform.Set(k, vs[0])
			}
		}
		if aform.Get("user_code") == "" {
			aform.Set("user_code", flow.UserCode)
		}
		if aform.Get("principal_type") == "" {
			aform.Set("principal_type", "User")
		}
	}
	// Always force allow after HTML overlay.
	aform.Set("action", "allow")
	// Form action from consent is usually https://auth.x.ai/oauth2/device/approve
	if approveTarget == "" || (!strings.Contains(approveTarget, "auth.x.ai") && !strings.Contains(approveTarget, "accounts.x.ai")) {
		approveTarget = ApproveURL
	}

	cookie = sanitizeSessionCookies(cookie)
	if !strings.Contains(cookie, "sso=") {
		return fmt.Errorf("sso_cookie_lost before approve")
	}
	c.logDiag("confirm_approve form keys: %d (principal_id=%t pid=%s) cookies=%s body=%s", len(aform), aform.Get("principal_id") != "", trimLoc(aform.Get("principal_id")), cookieNames(cookie), truncateBody([]byte(aform.Encode()), 160))

	fallbackForm := url.Values{
		"user_code":      {flow.UserCode},
		"action":         {"allow"},
		"principal_type": {"User"},
		"principal_id":   {aform.Get("principal_id")},
	}

	// Try approve; if incomplete, one more attempt with only core fields (no HTML overlay).
	for attempt, form := range []url.Values{aform, fallbackForm} {
		// Prefer auth.x.ai for approve — cookie is sent via header, host must match form action.
		target := approveTarget
		if attempt == 1 {
			target = ApproveURL
		}
		req2, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		c.setFormHeaders(req2, consentRef, cookie)
		// Origin/Referer must match the consent page host (accounts.x.ai).
		if refU, err := url.Parse(consentRef); err == nil && refU.Scheme != "" && refU.Host != "" {
			req2.Header.Set("Origin", refU.Scheme+"://"+refU.Host)
		} else {
			req2.Header.Set("Origin", "https://accounts.x.ai")
		}

		resp2, err := c.http.Do(req2)
		if err != nil {
			return err
		}
		aloc := resp2.Header.Get("Location")
		body, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
		_ = resp2.Body.Close()
		cookie = mergeSetCookies(cookie, resp2.Header)
		if err := locationError(aloc); err != nil {
			if errors.Is(err, ErrRateLimited) {
				c.TripRateLimit()
			}
			return fmt.Errorf("device_approve: %w", err)
		}
		c.logDiag("confirm_approve status=%d loc=%q bodyLen=%d attempt=%d", resp2.StatusCode, trimLoc(aloc), len(body), attempt)
		if isSignInRedirect(aloc) {
			return fmt.Errorf("sso_rejected approve→sign-in")
		}
		if deniedBody(string(body)) {
			return fmt.Errorf("consent_denied: accounts.x.ai rendered a denial for user_code=%s", flow.UserCode)
		}
		if isAccountLanding(aloc) {
			c.logDiag("confirm_approve → account landing %q — session alive but grant NOT confirmed", trimLoc(aloc))
		}
		if (authorizedBody(string(body)) || isDeviceDone(aloc)) && resp2.StatusCode != 307 {
			// Browser follows 303 See Other with GET — some grants only finalize then.
			if isDeviceDone(aloc) {
				doneURL := absURL("https://accounts.x.ai", aloc)
				if st, b, newCookie, err := c.getWithCookie(ctx, doneURL, cookie); err == nil {
					cookie = sanitizeSessionCookies(newCookie)
					c.logDiag("confirm_done GET status=%d authorized=%v cookies=%s", st, authorizedBody(b), cookieNames(cookie))
				} else {
					c.logDiag("confirm_done GET err=%v", err)
				}
			}
			c.logDiag("confirm_approve → authorized (attempt=%d has_pid=%t body_match=%t done_loc=%t)", attempt, form.Get("principal_id") != "", authorizedBody(string(body)), isDeviceDone(aloc))
			c.ClearRateLimit()
			return nil
		}
		if isRedirect(resp2.StatusCode) && aloc != "" {
			next := absURL("https://auth.x.ai", aloc)
			if !strings.Contains(next, "auth.x.ai") && !strings.Contains(next, "accounts.x.ai") {
				next = absURL("https://accounts.x.ai", aloc)
			}

			// X.ai now returns 307 to /account, meaning we must re-POST the form data there
			if resp2.StatusCode == 307 {
				c.logDiag("following 307 POST to %q", next)
				req3, err3 := http.NewRequestWithContext(ctx, http.MethodPost, next, strings.NewReader(form.Encode()))
				if err3 == nil {
					c.setFormHeaders(req3, consentRef, cookie)
					if refU, err := url.Parse(consentRef); err == nil && refU.Host != "" {
						req3.Header.Set("Origin", "https://"+refU.Host)
					} else {
						req3.Header.Set("Origin", "https://accounts.x.ai")
					}
					if resp3, err3 := c.http.Do(req3); err3 == nil {
						aloc3 := resp3.Header.Get("Location")
						body3, _ := io.ReadAll(io.LimitReader(resp3.Body, 1<<20))
						_ = resp3.Body.Close()
						cookie = mergeSetCookies(cookie, resp3.Header)
						c.logDiag("confirm_approve follow 307 status=%d loc=%q bodyLen=%d", resp3.StatusCode, trimLoc(aloc3), len(body3))
						
						// Next location might be the real done page or just a 200/302
						if authorizedBody(string(body3)) || isDeviceDone(aloc3) {
							c.ClearRateLimit()
							return nil
						}
						if isRedirect(resp3.StatusCode) {
							next3 := absURL("https://accounts.x.ai", aloc3)
							if isDeviceDone(next3) {
								c.ClearRateLimit()
								return nil
							}
							if isAccountLanding(next3) {
								c.logDiag("confirm_approve 307→account landing %q — grant NOT confirmed", trimLoc(next3))
							}
						}
					}
				}
			}

			if isDeviceDone(next) {
				if st, b, newCookie, err := c.getWithCookie(ctx, next, cookie); err == nil {
					cookie = sanitizeSessionCookies(newCookie)
					c.logDiag("confirm_done GET status=%d authorized=%v cookies=%s", st, authorizedBody(b), cookieNames(cookie))
				}
				c.logDiag("confirm_approve → done via redirect (provisional)")
				c.ClearRateLimit()
				return nil
			}
			if isSignInRedirect(next) {
				return fmt.Errorf("sso_rejected approve-redirect→sign-in")
			}

			if st, b, newCookie, err := c.getWithCookie(ctx, next, cookie); err == nil {
				if newCookie != "" {
					cookie = newCookie
				}
				c.logDiag("confirm_approve follow status=%d authorized=%v", st, authorizedBody(b))
				if authorizedBody(b) || isDeviceDone(next) {
					c.ClearRateLimit()
					return nil
				}
			}
			// retry once with minimal form if first attempt used HTML overlay
			if attempt == 0 && len(aform) > 4 {
				continue
			}
			return fmt.Errorf("device_approve_incomplete status=%d loc=%q", resp2.StatusCode, aloc)
		}
		if resp2.StatusCode == 403 {
			return fmt.Errorf("challenge")
		}
		if strings.Contains(strings.ToLower(string(body)), "invalid action") {
			if attempt == 0 {
				continue
			}
			return fmt.Errorf("consent_invalid_action")
		}
		if attempt == 0 {
			continue
		}
		preview := strings.TrimSpace(string(body))
		if len(preview) > 160 {
			preview = preview[:160]
		}
		return fmt.Errorf("unknown_page status=%d loc=%q body=%q", resp2.StatusCode, aloc, preview)
	}
	return fmt.Errorf("device_approve_failed")
}


func cookieNames(cookie string) string {
	if strings.TrimSpace(cookie) == "" {
		return "-"
	}
	var names []string
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := strings.SplitN(part, "=", 2)[0]
		if name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ",")
}

// sanitizeSessionCookies keeps only auth session cookies for OAuth.
// __cf_bm / mixpanel / analytics cookies have been observed to produce
// cosmetic /device/done redirects with token invalid_grant (Access denied).
func sanitizeSessionCookies(cookie string) string {
	if strings.TrimSpace(cookie) == "" {
		return ""
	}
	var keep []string
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if part == "" || !strings.Contains(part, "=") {
			continue
		}
		name := strings.ToLower(strings.SplitN(part, "=", 2)[0])
		switch {
		case name == "sso":
			keep = append(keep, part)
		case name == "sso-rw" || name == "sso_rw":
			keep = append(keep, part)
		case strings.HasPrefix(name, "session") || strings.HasPrefix(name, "__session"):
			keep = append(keep, part)
		case name == "cf_clearance":
			// never
		case strings.HasPrefix(name, "__cf"), strings.HasPrefix(name, "mp_"), strings.HasPrefix(name, "_ga"), strings.HasPrefix(name, "_gid"), strings.HasPrefix(name, "ajs_"):
			// analytics / CF bot management — drop
		case strings.HasPrefix(name, "__host-"), strings.HasPrefix(name, "__secure-"):
			// Host/Secure-prefixed cookies are same-site security state, not tracking:
			// dropping them takes the CSRF and oauth-state cookies with them, and the
			// consent POST is then answered as a denial.
			keep = append(keep, part)
		case strings.Contains(name, "csrf"), strings.Contains(name, "xsrf"), strings.Contains(name, "oauth"), strings.Contains(name, "consent"):
			keep = append(keep, part)
		default:
			// drop unknown by default on OAuth path
		}
	}
	return strings.Join(keep, "; ")
}

func mergeSetCookies(cookie string, h http.Header) string {
	// Keep existing; append new name=value from Set-Cookie (simple).
	out := cookie
	for _, sc := range h.Values("Set-Cookie") {
		part := strings.SplitN(sc, ";", 2)[0]
		if !strings.Contains(part, "=") {
			continue
		}
		name := strings.SplitN(part, "=", 2)[0]
		// replace existing name=
		found := false
		segs := strings.Split(out, "; ")
		for i, s := range segs {
			if strings.HasPrefix(s, name+"=") {
				segs[i] = part
				found = true
			}
		}
		if found {
			out = strings.Join(segs, "; ")
		} else if out == "" {
			out = part
		} else {
			out = out + "; " + part
		}
	}
	return out
}

func (c *Client) getWithCookie(ctx context.Context, rawURL, cookie string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", cookie, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Cookie", sanitizeSessionCookies(cookie)) // SSO only — no CF/analytics
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", cookie, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	updatedCookie := mergeSetCookies(cookie, resp.Header)
	return resp.StatusCode, string(body), updatedCookie, nil
}

// droppedCookieNames reports which cookies sanitizeSessionCookies discards, so a
// consent refusal caused by a stripped CSRF cookie is visible rather than silent.
func droppedCookieNames(before string) string {
	kept := map[string]struct{}{}
	for _, p := range strings.Split(sanitizeSessionCookies(before), ";") {
		if n := strings.SplitN(strings.TrimSpace(p), "=", 2)[0]; n != "" {
			kept[n] = struct{}{}
		}
	}
	var gone []string
	for _, p := range strings.Split(before, ";") {
		n := strings.SplitN(strings.TrimSpace(p), "=", 2)[0]
		if n == "" {
			continue
		}
		if _, ok := kept[n]; !ok {
			gone = append(gone, n)
		}
	}
	if len(gone) == 0 {
		return "-"
	}
	sort.Strings(gone)
	return strings.Join(gone, ",")
}

// loadConsentForm GETs consent page and extracts form fields (principal_id, csrf, etc.).
func (c *Client) loadConsentForm(ctx context.Context, consentURL, cookie string) (url.Values, string, string) {
	st, html, newCookie, err := c.getWithCookie(ctx, consentURL, cookie)
	if err != nil || st >= 400 {
		return nil, cookie, ""
	}
	
	// The consent page carries the account userId, email and session state. Only spill it
	// when explicitly asked, under a unique name so concurrent workers cannot clobber
	// each other, and never world-readable.
	if os.Getenv("GROK_OAUTH_DEBUG_HTML") == "1" {
		name := fmt.Sprintf("consent_debug_%d.html", time.Now().UnixNano())
		if werr := os.WriteFile(name, []byte(html), 0o600); werr != nil {
			c.logDiag("consent debug dump failed: %v", werr)
		}
	}

	// Whose account did the consent page render for? Never posted — but if this
	// disagrees with the account being registered, the SSO cookie belongs to
	// someone else, which is exactly how cross-contaminated sessions surface.
	c.logDiag("consent page identity userId=%s", orDash(extractPrincipalID(html)))
	fields, action := parseHTMLFormFields(html)
	return fields, newCookie, action
}

// formButton is a submit control scraped from a consent form.
type formButton struct {
	Name       string
	Value      string
	Text       string
	FormAction string
}

// htmlForm is one <form> element with only its own inputs and buttons.
type htmlForm struct {
	Action  string
	Fields  url.Values
	Buttons []formButton
}

var (
	buttonTagRe = regexp.MustCompile(`(?is)<button\b([^>]*)>(.*?)</button>`)
	formBlockRe = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	tagStripRe  = regexp.MustCompile(`(?s)<[^>]*>`)
)

// parseForms splits the page into individual forms. The consent page carries
// several — sign-out, deny and allow — and scraping inputs across the whole
// document merges fields that belong to different forms and pairs them with
// whichever action came first. When allow and deny are separate forms, posting
// the allow form IS the approval; there is no field to set.
func parseForms(html string) []htmlForm {
	var out []htmlForm
	for _, m := range formBlockRe.FindAllStringSubmatch(html, -1) {
		attrs, inner := m[1], m[2]
		out = append(out, htmlForm{
			Action:  attrValue(attrs, "action"),
			Fields:  parseInputFields(inner),
			Buttons: parseFormButtons(inner),
		})
	}
	return out
}

// approvalForm picks the form whose own controls grant consent, preferring a
// form that holds an approval button over one that merely posts somewhere
// plausible. Forms whose only control denies are never selected.
func approvalForm(forms []htmlForm) (htmlForm, bool) {
	for _, f := range forms {
		hasApprove, hasDeny := false, false
		for _, b := range f.Buttons {
			if isDenyLabel(b) {
				hasDeny = true
				continue
			}
			if isApproveLabel(b) {
				hasApprove = true
			}
		}
		if hasApprove && !hasDeny {
			return f, true
		}
	}
	// Allow and deny may share one form (the device consent shape), in which case
	// an explicit action field decides. Fall back to any form holding an approval.
	for _, f := range forms {
		for _, b := range f.Buttons {
			if isApproveLabel(b) {
				return f, true
			}
		}
	}
	return htmlForm{}, false
}

func isDenyLabel(b formButton) bool {
	blob := strings.ToLower(b.Text + " " + b.Value)
	return strings.Contains(b.Text, "拒绝") || strings.Contains(blob, "deny") ||
		strings.Contains(blob, "reject") || strings.Contains(blob, "cancel") ||
		strings.Contains(blob, "sign out") || strings.Contains(blob, "logout")
}

func isApproveLabel(b formButton) bool {
	blob := strings.ToLower(b.Text + " " + b.Value)
	return strings.Contains(b.Text, "允许") || strings.Contains(b.Text, "授权") ||
		strings.Contains(blob, "allow") || strings.Contains(blob, "approve") ||
		strings.Contains(blob, "authorize") || strings.Contains(blob, "accept")
}

func describeForms(forms []htmlForm) string {
	if len(forms) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(forms))
	for i, f := range forms {
		names := make([]string, 0, len(f.Fields))
		for k := range f.Fields {
			names = append(names, k)
		}
		sort.Strings(names)
		parts = append(parts, fmt.Sprintf("#%d action=%s inputs[%s] buttons[%s]",
			i, orDash(trimLoc(f.Action)), strings.Join(names, ","), describeButtons(f.Buttons)))
	}
	return strings.Join(parts, " ;; ")
}

// parseFormButtons scrapes <button> controls. parseHTMLFormFields only reads
// <input> tags, which is enough for the device consent form — it carries an
// explicit action=allow|deny hidden input. The authorize-flow consent form has
// no action input at all, so approval can only be expressed by the submit
// button's name/value pair, and a form posted without it reads as a denial.
func parseFormButtons(html string) []formButton {
	var out []formButton
	for _, m := range buttonTagRe.FindAllStringSubmatch(html, -1) {
		attrs, inner := m[1], m[2]
		text := strings.Join(strings.Fields(tagStripRe.ReplaceAllString(inner, " ")), " ")
		out = append(out, formButton{
			Name:       attrValue(attrs, "name"),
			Value:      attrValue(attrs, "value"),
			Text:       text,
			FormAction: attrValue(attrs, "formaction"),
		})
	}
	return out
}

// approveButton picks the button that grants consent. Denial controls are
// excluded first so a substring match can never select "拒绝" or "Deny".
func approveButton(buttons []formButton) (formButton, bool) {
	for _, b := range buttons {
		if b.Name == "" {
			continue // carries nothing when submitted
		}
		blob := strings.ToLower(b.Text + " " + b.Value)
		if strings.Contains(b.Text, "拒绝") || strings.Contains(blob, "deny") ||
			strings.Contains(blob, "reject") || strings.Contains(blob, "cancel") {
			continue
		}
		if strings.Contains(b.Text, "允许") || strings.Contains(b.Text, "授权") ||
			strings.Contains(blob, "allow") || strings.Contains(blob, "approve") ||
			strings.Contains(blob, "authorize") || strings.Contains(blob, "accept") ||
			strings.Contains(blob, "continue") {
			return b, true
		}
	}
	return formButton{}, false
}

func describeButtons(buttons []formButton) string {
	if len(buttons) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(buttons))
	for _, b := range buttons {
		parts = append(parts, fmt.Sprintf("%s=%s(%s)fa=%s", orDash(b.Name), orDash(b.Value), orDash(b.Text), orDash(trimLoc(b.FormAction))))
	}
	return strings.Join(parts, " | ")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// parseInputFields scrapes <input name=... value=...> from one HTML fragment.
func parseInputFields(html string) url.Values {
	out := url.Values{}
	lower := html
	for i := 0; i < len(html); {
		idx := strings.Index(strings.ToLower(lower[i:]), "<input")
		if idx < 0 {
			break
		}
		i += idx
		end := strings.Index(lower[i:], ">")
		if end < 0 {
			break
		}
		tag := html[i : i+end]
		i += end + 1
		name := attrValue(tag, "name")
		if name == "" {
			continue
		}
		out.Set(name, attrValue(tag, "value"))
	}
	return out
}

func parseHTMLFormFields(html string) (url.Values, string) {
	out := url.Values{}
	action := ""
	
	lowHTML := strings.ToLower(html)
	if formIdx := strings.Index(lowHTML, "<form"); formIdx >= 0 {
		if end := strings.Index(html[formIdx:], ">"); end >= 0 {
			action = attrValue(html[formIdx:formIdx+end], "action")
		}
	}
	lower := html
	for k, vs := range parseInputFields(html) {
		if len(vs) > 0 {
			out.Set(k, vs[0])
		}
	}

	// Also scan for <meta name="_csrf" content="...">
	for i := 0; i < len(html); {
		idx := strings.Index(strings.ToLower(lower[i:]), "<meta")
		if idx < 0 {
			break
		}
		i += idx
		end := strings.Index(lower[i:], ">")
		if end < 0 {
			break
		}
		tag := html[i : i+end]
		i += end + 1
		name := attrValue(tag, "name")
		if name == "_csrf" || name == "csrf-token" {
			val := attrValue(tag, "content")
			if val != "" {
				out.Set("_csrf", val)
			}
		}
	}

	return out, action
}

// extractPrincipalID finds the accounts.x.ai user UUID in consent HTML / RSC payload.
//
// This is diagnostic only. It must NOT be used to fill the consent form's
// principal_id: the consent bundle computes that field as
//
//	let $ = "Team" === k ? D ?? "" : "";
//
// so for principal_type=User a real browser posts an EMPTY principal_id. The
// hidden input rendering as value="" is the final value, not a placeholder
// waiting to be filled. Injecting the page's userId sends something the browser
// never sends and the authorization is refused.
func extractPrincipalID(html string) string {
	patterns := []string{
		// Most common on accounts.x.ai consent (backslash-escaped JSON inside a JS string)
		`userId\\":\\"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`,
		// Plain JSON
		`"userId"\s*:\s*"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"`,
		// Double-escaped key/value
		`\\"userId\\"\s*:\s*\\"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\\"`,
		// Loose fallback near userId key
		`(?i)userId[^0-9a-fA-F]{0,12}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if m := re.FindStringSubmatch(html); len(m) > 1 && m[1] != "" {
			return m[1]
		}
	}
	return ""
}

func attrValue(tag, attr string) string {
	// attr="..." or attr='...'
	low := strings.ToLower(tag)
	key := strings.ToLower(attr) + "="
	j := strings.Index(low, key)
	if j < 0 {
		return ""
	}
	rest := tag[j+len(key):]
	if rest == "" {
		return ""
	}
	q := rest[0]
	if q == '"' || q == '\'' {
		rest = rest[1:]
		k := strings.IndexByte(rest, q)
		if k < 0 {
			return ""
		}
		return rest[:k]
	}
	// unquoted
	k := strings.IndexAny(rest, " \t>/")
	if k < 0 {
		return rest
	}
	return rest[:k]
}

func locationError(loc string) error {
	if loc == "" {
		return nil
	}
	u, err := url.Parse(loc)
	if err != nil {
		return nil
	}
	q := u.Query()
	e := q.Get("error")
	p := q.Get("policy")
	risk := q.Get("risk")
	if p == "deny" {
		if risk != "" {
			return fmt.Errorf("policy=deny (risk=%s)", risk)
		}
		return fmt.Errorf("policy=deny")
	}
	if e == "" {
		return nil
	}
	if e == "rate_limited" {
		return ErrRateLimited
	}
	return fmt.Errorf("%s", e)
}

func (c *Client) setFormHeaders(req *http.Request, referer, cookie string) {
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	origin := "https://" + req.URL.Host
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", referer)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// OAuth device verify/approve: ONLY session SSO. Do NOT append FlareSolverr/CF
	// clearance cookies — they can poison auth.x.ai and yield invalid_grant Access denied.
	req.Header.Set("Cookie", sanitizeSessionCookies(cookie))
	req.Header.Set("Sec-Fetch-Site", "same-site")
	if strings.Contains(referer, req.URL.Host) {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func (c *Client) PollToken(ctx context.Context, flow DeviceFlow) (Credential, error) {
	deadline := time.Now().Add(time.Duration(flow.ExpiresIn) * time.Second)
	if flow.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	interval := time.Duration(flow.Interval * float64(time.Second))
	if interval < time.Second {
		interval = 5 * time.Second
	}
	// Give auth.x.ai a beat to persist the device grant after /device/done.
	select {
	case <-ctx.Done():
		return Credential{}, ctx.Err()
	case <-time.After(2500 * time.Millisecond):
	}
	for time.Now().Before(deadline) {
		form := url.Values{}
		form.Set("client_id", ClientID)
		form.Set("device_code", flow.DeviceCode)
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, flow.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return Credential{}, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", c.ua)
		resp, err := c.http.Do(req)
		if err != nil {
			return Credential{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		if resp.StatusCode/100 == 2 {
			return credentialFrom(doc, flow.TokenEndpoint)
		}
		errCode, _ := doc["error"].(string)
		errDesc, _ := doc["error_description"].(string)
		switch errCode {
		case "authorization_pending":
			// continue
		case "slow_down":
			interval += time.Second
		case "access_denied":
			return Credential{}, fmt.Errorf("oauth_denied")
		case "expired_token":
			return Credential{}, fmt.Errorf("oauth_expired")
		case "invalid_grant":
			// Only reachable after ConfirmHTTP proved the approve POST was accepted and
			// redirected to the real /oauth2/device/done, so the device grant itself is
			// not in question here.
			//
			// "Access denied" at this point means auth.x.ai refuses to mint a token for
			// the ACCOUNT. Accounts created by protocol replay — without a real browser
			// device fingerprint at signup — are refused permanently: they log in fine
			// and pass consent, but never receive an OAuth token. No change to the device
			// flow recovers them; the account has to be registered through a browser.
			c.logDiag("poll invalid_grant desc=%q body=%s", errDesc, truncateBody(body, 160))
			if strings.EqualFold(strings.TrimSpace(errDesc), "access denied") {
				return Credential{}, fmt.Errorf("oauth_rejected: invalid_grant (%s) — approve was accepted, so this is an account-level refusal: the account is most likely not OAuth-eligible (registered without a browser device fingerprint)", errDesc)
			}
			if errDesc != "" {
				return Credential{}, fmt.Errorf("oauth_rejected: invalid_grant (%s) — approve was accepted but the grant was not redeemable", errDesc)
			}
			return Credential{}, fmt.Errorf("oauth_rejected: invalid_grant — approve was accepted but the grant was not redeemable")
		default:
			if errCode != "" {
				if errDesc != "" {
					return Credential{}, fmt.Errorf("oauth_rejected: %s (%s)", errCode, errDesc)
				}
				return Credential{}, fmt.Errorf("oauth_rejected: %s", errCode)
			}
			return Credential{}, fmt.Errorf("oauth_rejected status=%d body=%s", resp.StatusCode, truncateBody(body, 120))
		}
		select {
		case <-ctx.Done():
			return Credential{}, ctx.Err()
		case <-time.After(interval):
		}
	}
	return Credential{}, fmt.Errorf("oauth_expired")
}

func credentialFrom(doc map[string]any, endpoint string) (Credential, error) {
	// Handle policy field (e.g. policy=deny, risk=1.00)
	if p, ok := doc["policy"].(string); ok && strings.EqualFold(p, "deny") {
		risk, _ := doc["risk"].(string)
		if risk != "" {
			return Credential{}, fmt.Errorf("policy_deny: policy=deny, risk=%s", risk)
		}
		return Credential{}, fmt.Errorf("policy_deny: policy=deny")
	}

	at, _ := doc["access_token"].(string)
	rt, _ := doc["refresh_token"].(string)
	if at == "" || rt == "" {
		if p, ok := doc["policy"].(string); ok && p != "" {
			return Credential{}, fmt.Errorf("policy_deny: no_token (policy=%s)", p)
		}
		return Credential{}, fmt.Errorf("oauth_rejected: missing tokens (no_token)")
	}

	if strings.Contains(at, "invalid_token") || len(at) < 20 {
		return Credential{}, fmt.Errorf("oauth_rejected: invalid_token (fake clean token)")
	}
	id, _ := doc["id_token"].(string)
	tt, _ := doc["token_type"].(string)
	expF, _ := doc["expires_in"].(float64)
	exp := int(expF)
	if exp <= 0 {
		exp = 3600
	}
	now := time.Now().UTC()
	sub := jwtClaim(id, "sub")
	if sub == "" {
		sub = jwtClaim(at, "sub")
	}
	email := jwtClaim(id, "email")
	if email == "" {
		email = jwtClaim(at, "email")
	}
	return Credential{
		AccessToken:   at,
		RefreshToken:  rt,
		IDToken:       id,
		TokenType:     tt,
		ExpiresIn:     exp,
		ExpiresAt:     now.Add(time.Duration(exp) * time.Second).Format(time.RFC3339),
		LastRefresh:   now.Format(time.RFC3339),
		Subject:       sub,
		TokenEndpoint: endpoint,
		Email:         email,
	}, nil
}

func jwtClaim(token, key string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func truncateBody(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// terminalOAuthErr reports failures a fresh device flow cannot fix. Everything else —
// including transport, proxy and DNS errors — is worth another attempt. The previous
// allowlist of "recoverable" substrings matched no transport error at all, so a single
// dial failure against the clearance proxy permanently failed the account.
func terminalOAuthErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "sso_rejected") ||
		strings.Contains(s, "login_required") ||
		strings.Contains(s, "sso_cookie_lost") ||
		strings.Contains(s, "consent_denied") ||
		strings.Contains(s, "policy=deny") ||
		strings.Contains(s, "policy_deny") ||
		strings.Contains(s, "oauth_denied")
}

// settle pauses between attempts, growing with the attempt index.
func (c *Client) settle(ctx context.Context, attempt int) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2*time.Second + time.Duration(attempt)*2*time.Second):
		return nil
	}
}

// Exchange is convenience: start flow + confirm HTTP + poll.
// Any non-terminal failure retries with a fresh device code.
func (c *Client) Exchange(ctx context.Context, sso string) (Credential, error) {
	c.clearDiags()
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if err := c.WaitRateLimit(ctx); err != nil {
			return Credential{}, err
		}
		flow, err := c.StartDeviceFlow(ctx)
		if err != nil {
			last = err
			if attempt < 2 && !terminalOAuthErr(err) {
				c.logDiag("device flow start failed (%v) -> retry attempt=%d", err, attempt+1)
				if serr := c.settle(ctx, attempt); serr != nil {
					return Credential{}, serr
				}
				continue
			}
			return Credential{}, fmt.Errorf("%w [diag: %s]", err, c.getDiags())
		}
		if err := c.ConfirmHTTP(ctx, sso, flow); err != nil {
			last = err
			if attempt < 2 && !terminalOAuthErr(err) {
				c.logDiag("confirm failed (%v) -> new device flow attempt=%d", err, attempt+1)
				if serr := c.settle(ctx, attempt); serr != nil {
					return Credential{}, serr
				}
				continue
			}
			return Credential{}, fmt.Errorf("%w [diag: %s]", err, c.getDiags())
		}
		cred, err := c.PollToken(ctx, flow)
		if err != nil {
			last = err
			// invalid_grant: device grant did not stick. Do NOT re-approve the same
			// device_code (already spent -> invalid_code). Open a fresh device flow.
			if attempt < 2 && strings.Contains(err.Error(), "invalid_grant") {
				c.logDiag("invalid_grant -> new device flow attempt=%d", attempt+1)
				if serr := c.settle(ctx, attempt); serr != nil {
					return Credential{}, serr
				}
				continue
			}
			return Credential{}, fmt.Errorf("%w [diag: %s]", err, c.getDiags())
		}
		return cred, nil
	}
	if last == nil {
		last = fmt.Errorf("oauth_failed")
	}
	return Credential{}, fmt.Errorf("%w [diag: %s]", last, c.getDiags())
}

// Refresh re-issues access token using existing refresh_token.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (Credential, error) {
	_, tokEP, err := c.discover(ctx)
	if err != nil || tokEP == "" {
		tokEP = "https://auth.x.ai/oauth2/token"
	}
	form := url.Values{}
	form.Set("client_id", ClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokEP, strings.NewReader(form.Encode()))
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return Credential{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return Credential{}, fmt.Errorf("oauth_refresh_failed status=%d body=%s", resp.StatusCode, truncateBody(body, 120))
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return Credential{}, err
	}
	return credentialFrom(doc, tokEP)
}
