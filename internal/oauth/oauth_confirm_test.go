package oauth

import (
	"context"
	"fmt"
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
