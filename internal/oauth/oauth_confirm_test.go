package oauth

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// nextJSConsentPage mimics the shape of a real accounts.x.ai consent page: the visible
// markup asks for approval, while the inlined RSC payload carries the whole i18n catalog
// — success, denial and error strings all at once.
const nextJSConsentPage = `<!DOCTYPE html><html><body>` +
	`<main><h1>授权请求</h1><form action="https://auth.x.ai/oauth2/device/approve" method="POST">` +
	`<input type="hidden" name="user_code" value="QPZ9-ZCN7">` +
	`<input type="hidden" name="action" value="">` +
	`<button type="submit">拒绝</button><button type="submit">允许</button></form></main>` +
	`<script>self.__next_f.push([1,"{\"deviceAuthorized\":\"设备已授权\",` +
	`\"authorizationDenied\":\"授权已拒绝\",\"deviceAuthorizedEn\":\"Device authorized\"}"])</script>` +
	`</body></html>`

// The consent bundle computes the posted principal id as
//
//	let $ = "Team" === principalType ? teamId ?? "" : "";
//
// so a browser consenting as a User posts principal_id with no value. The page
// rendering value="" is the final answer, not a placeholder. Scraping the RSC
// userId into that field sends something no browser sends.
func TestParseHTMLFormFieldsDoesNotInjectPrincipalID(t *testing.T) {
	html := `<html><body>` +
		`<form action="https://auth.x.ai/oauth2/device/approve" method="POST">` +
		`<input type="hidden" name="user_code" value="QPZ9-ZCN7">` +
		`<input type="hidden" name="action" value="">` +
		`<input type="hidden" name="principal_type" value="User">` +
		`<input type="hidden" name="principal_id" value="">` +
		`</form>` +
		`<script>self.__next_f.push([1,"{\"userId\":\"9e533f92-ae08-48a7-8195-44dac4801e36\"}"])</script>` +
		`</body></html>`

	fields, action := parseHTMLFormFields(html)
	if action != "https://auth.x.ai/oauth2/device/approve" {
		t.Fatalf("form action = %q", action)
	}
	if got := fields.Get("principal_id"); got != "" {
		t.Fatalf("principal_id = %q, want empty — the page's userId must never be posted as the principal", got)
	}
	if got := fields.Get("principal_type"); got != "User" {
		t.Fatalf("principal_type = %q", got)
	}
	// The userId is still extractable for diagnostics; it just must not reach the form.
	if pid := extractPrincipalID(html); pid != "9e533f92-ae08-48a7-8195-44dac4801e36" {
		t.Fatalf("extractPrincipalID = %q, diagnostic extraction should still work", pid)
	}
}

// The real /oauth2/consent page carries three buttons — Sign out, Deny, Allow —
// all with empty name and value, so approval cannot be a field on a shared form.
// They belong to separate forms, and submitting the allow form IS the approval.
// Scraping inputs across the whole document merges fields from every form and
// pairs them with whichever action came first.
func TestSanitizeSessionCookiesKeepsSecurityState(t *testing.T) {
	in := "sso=a.b.c; __Host-csrf=TOKEN; __Secure-oauth-state=ST; " +
		"__cf_bm=drop; mp_x_mixpanel=drop; _ga=drop; cf_clearance=drop"
	got := sanitizeSessionCookies(in)

	// Dropping these took the CSRF and oauth-state cookies with them, and the
	// consent POST was then answered as a denial.
	for _, want := range []string{"sso=a.b.c", "__Host-csrf=TOKEN", "__Secure-oauth-state=ST"} {
		if !strings.Contains(got, want) {
			t.Fatalf("dropped required cookie %q from %q", want, got)
		}
	}
	for _, banned := range []string{"__cf_bm", "mixpanel", "_ga=", "cf_clearance"} {
		if strings.Contains(got, banned) {
			t.Fatalf("analytics/CF cookie %q leaked into the OAuth path: %q", banned, got)
		}
	}
	if d := droppedCookieNames(in); !strings.Contains(d, "__cf_bm") || strings.Contains(d, "__Host-csrf") {
		t.Fatalf("droppedCookieNames = %q, should list the analytics drops and not the kept ones", d)
	}
}

func TestApprovalFormIsolatesTheAllowForm(t *testing.T) {
	html := `<html><body>` +
		`<form action="/auth/sign-out" method="POST">` +
		`<input type="hidden" name="csrf" value="SIGNOUT">` +
		`<button type="submit"><span></span>Sign out</button></form>` +
		`<form action="https://auth.x.ai/oauth2/deny" method="POST">` +
		`<input type="hidden" name="state" value="DENYSTATE">` +
		`<button type="submit"><span></span>Deny</button></form>` +
		`<form action="https://auth.x.ai/oauth2/authorize" method="POST">` +
		`<input type="hidden" name="client_id" value="CID">` +
		`<input type="hidden" name="state" value="ALLOWSTATE">` +
		`<input type="hidden" name="principal_id" value="">` +
		`<button type="submit"><span></span>Allow</button></form>` +
		`</body></html>`

	forms := parseForms(html)
	if len(forms) != 3 {
		t.Fatalf("parsed %d forms, want 3", len(forms))
	}

	got, ok := approvalForm(forms)
	if !ok {
		t.Fatal("no approval form selected")
	}
	if got.Action != "https://auth.x.ai/oauth2/authorize" {
		t.Fatalf("selected form action = %q — must be the allow form", got.Action)
	}
	if v := got.Fields.Get("state"); v != "ALLOWSTATE" {
		t.Fatalf("state = %q, want ALLOWSTATE — fields leaked in from another form", v)
	}
	if _, leaked := got.Fields["csrf"]; leaked {
		t.Fatal("sign-out form's csrf leaked into the approval form")
	}
	if _, ok := got.Fields["principal_id"]; !ok {
		t.Fatal("empty principal_id must be preserved, not dropped")
	}
}

func TestApprovalFormNeverPicksDenyOrSignOut(t *testing.T) {
	html := `<form action="/deny"><button>Deny</button></form>` +
		`<form action="/out"><button>Sign out</button></form>`
	if f, ok := approvalForm(parseForms(html)); ok {
		t.Fatalf("selected %q when the page offers no approval control", f.Action)
	}
}

func TestParseFormButtonsAndApproveSelection(t *testing.T) {
	// Shape of the real consent controls: a denial and an approval, with the label
	// wrapped in spans the way the live page renders it.
	html := `<form>` +
		`<button type="submit" name="consent" value="deny"><span aria-hidden="true"></span>拒绝</button>` +
		`<button type="submit" name="consent" value="approve"><span aria-hidden="true"></span>允许</button>` +
		`</form>`

	buttons := parseFormButtons(html)
	if len(buttons) != 2 {
		t.Fatalf("parsed %d buttons, want 2: %+v", len(buttons), buttons)
	}
	if buttons[0].Text != "拒绝" || buttons[1].Text != "允许" {
		t.Fatalf("button text not extracted from nested markup: %+v", buttons)
	}

	got, ok := approveButton(buttons)
	if !ok {
		t.Fatal("no approval button selected")
	}
	if got.Value != "approve" {
		t.Fatalf("selected %q — must never select the denial control", got.Value)
	}
}

func TestApproveButtonSkipsUnnamedAndDenialControls(t *testing.T) {
	// The device form's buttons carry no name, so they submit nothing and cannot
	// express approval; that form uses a hidden action input instead.
	unnamed := []formButton{{Text: "拒绝"}, {Text: "允许"}}
	if _, ok := approveButton(unnamed); ok {
		t.Fatal("an unnamed button submits no value and must not be treated as approval")
	}

	denialOnly := []formButton{{Name: "consent", Value: "deny", Text: "Deny"}}
	if _, ok := approveButton(denialOnly); ok {
		t.Fatal("denial control selected as approval")
	}

	english := []formButton{
		{Name: "consent", Value: "deny", Text: "Cancel"},
		{Name: "consent", Value: "approve", Text: "Authorize"},
	}
	got, ok := approveButton(english)
	if !ok || got.Value != "approve" {
		t.Fatalf("english approval not selected: %+v ok=%v", got, ok)
	}
}

func TestAuthorizedBodyIgnoresInlinedI18nCatalog(t *testing.T) {
	if authorizedBody(nextJSConsentPage) {
		t.Fatal("pre-approval consent page reported as authorized: the i18n catalog inside " +
			"<script> is being matched, which makes every response look like a success")
	}
	if deniedBody(nextJSConsentPage) {
		t.Fatal("pre-approval consent page reported as denied for the same reason")
	}
}

func TestAuthorizedBodyMatchesRenderedText(t *testing.T) {
	for _, body := range []string{
		`<html><body><h1>设备已授权</h1></body></html>`,
		`<html><body><h1>Device authorized</h1></body></html>`,
		`<html><body><p>You have authorized this device.</p></body></html>`,
	} {
		if !authorizedBody(body) {
			t.Fatalf("rendered success page not recognized: %q", body)
		}
	}
}

func TestAuthorizedBodyRejectsRenderedDenial(t *testing.T) {
	denial := `<html><body><h1>授权已拒绝</h1></body></html>`
	if authorizedBody(denial) {
		t.Fatal("denial page reported as authorized")
	}
	if !deniedBody(denial) {
		t.Fatal("denial page not recognized as denied")
	}
}

func TestIsDeviceDoneOnlyAcceptsDonePaths(t *testing.T) {
	done := []string{
		"https://accounts.x.ai/oauth2/device/done",
		"/oauth2/device/done",
		"https://auth.x.ai/device/done",
	}
	for _, loc := range done {
		if !isDeviceDone(loc) {
			t.Fatalf("device done path rejected: %q", loc)
		}
	}

	// Generic signed-in landings are NOT proof of a recorded device grant: auth.x.ai
	// redirects there after a rejected approve as well.
	notDone := []string{
		"https://accounts.x.ai/account",
		"/account",
		"https://accounts.x.ai/console",
		"/console/settings",
		"",
		"https://accounts.x.ai/oauth2/device/done?error=access_denied",
		"https://accounts.x.ai/oauth2/device/done?policy=deny",
	}
	for _, loc := range notDone {
		if isDeviceDone(loc) {
			t.Fatalf("non-done location accepted as device done: %q", loc)
		}
	}
}

func TestIsAccountLanding(t *testing.T) {
	for _, loc := range []string{"https://accounts.x.ai/account", "/account", "/console", "/console/x"} {
		if !isAccountLanding(loc) {
			t.Fatalf("account landing not recognized: %q", loc)
		}
	}
	if isAccountLanding("https://accounts.x.ai/oauth2/device/done") {
		t.Fatal("device done misclassified as account landing")
	}
}

func TestTerminalOAuthErrRetriesTransportFailures(t *testing.T) {
	// A dial/proxy failure must stay retryable — this is the whole point of the change.
	transport := fmt.Errorf(`Post "https://auth.x.ai/oauth2/device/authorize": dial tcp 127.0.0.1:40080: connectex: No connection could be made`)
	if terminalOAuthErr(transport) {
		t.Fatal("transport error treated as terminal; one proxy blip would fail the account")
	}
	for _, retryable := range []error{
		fmt.Errorf("challenge"),
		fmt.Errorf("device_approve_incomplete status=302 loc=%q", "/account"),
		fmt.Errorf("unknown_page status=200"),
		fmt.Errorf("consent_missing_principal_id"),
	} {
		if terminalOAuthErr(retryable) {
			t.Fatalf("recoverable error treated as terminal: %v", retryable)
		}
	}
	for _, terminal := range []error{
		fmt.Errorf("sso_rejected verify→sign-in"),
		fmt.Errorf("login_required"),
		fmt.Errorf("sso_cookie_lost before approve"),
		fmt.Errorf("consent_denied: accounts.x.ai rendered a denial"),
		fmt.Errorf("device_approve: policy=deny (risk=1.00)"),
	} {
		if !terminalOAuthErr(terminal) {
			t.Fatalf("terminal error treated as retryable: %v", terminal)
		}
	}
	if terminalOAuthErr(nil) {
		t.Fatal("nil error is not terminal")
	}
}

func TestWaitRateLimitReArmsGate(t *testing.T) {
	c := &Client{baseCool: 40 * time.Millisecond, cooldown: 40 * time.Millisecond}
	c.TripRateLimit()

	start := time.Now()
	if err := c.WaitRateLimit(context.Background()); err != nil {
		t.Fatalf("WaitRateLimit: %v", err)
	}
	if waited := time.Since(start); waited < 30*time.Millisecond {
		t.Fatalf("gate did not hold the caller: waited only %v", waited)
	}

	c.mu.Lock()
	next := c.nextProbe
	c.mu.Unlock()
	if !next.After(time.Now()) {
		t.Fatal("gate latched open: nextProbe was not re-armed after granting a probe, " +
			"so every worker would probe at once and immediately re-trip the limiter")
	}
}

func TestClearRateLimitResets(t *testing.T) {
	c := &Client{baseCool: time.Second, cooldown: time.Second}
	c.TripRateLimit()
	c.TripRateLimit()
	c.ClearRateLimit()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.trippedAt.IsZero() || c.trips != 0 || c.cooldown != c.baseCool {
		t.Fatalf("rate limit not reset: trippedAt=%v trips=%d cooldown=%v", c.trippedAt, c.trips, c.cooldown)
	}
}
