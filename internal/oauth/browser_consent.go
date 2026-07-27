package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type consentScriptResult struct {
	OK          bool   `json:"ok"`
	Code        string `json:"code"`
	State       string `json:"state"`
	CallbackURL string `json:"callback_url"`
	Error       string `json:"error"`
}

func parseConsentScriptOutput(stdout string) (consentScriptResult, error) {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var last string
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") {
			last = line
			break
		}
	}
	if last == "" {
		return consentScriptResult{}, fmt.Errorf("pkce_browser_consent_no_json")
	}
	var res consentScriptResult
	if err := json.Unmarshal([]byte(last), &res); err != nil {
		return consentScriptResult{}, fmt.Errorf("pkce_browser_consent_bad_json: %w", err)
	}
	if !res.OK {
		msg := res.Error
		if msg == "" {
			msg = "ok=false"
		}
		return res, fmt.Errorf("pkce_browser_consent: %s", msg)
	}
	if strings.TrimSpace(res.Code) == "" && res.CallbackURL == "" {
		return res, fmt.Errorf("pkce_browser_consent_no_code")
	}
	if res.CallbackURL == "" && res.Code != "" {
		res.CallbackURL = fmt.Sprintf("%s?code=%s&state=%s", RedirectURI, res.Code, res.State)
	}
	return res, nil
}

func findConsentScript() string {
	if p := strings.TrimSpace(os.Getenv("GROK_OAUTH_CONSENT_SCRIPT")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "scripts", "oauth_consent.py"),
			filepath.Join(dir, "oauth_consent.py"),
			filepath.Join(dir, "..", "scripts", "oauth_consent.py"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "scripts", "oauth_consent.py"),
			filepath.Join(wd, "..", "scripts", "oauth_consent.py"),
		)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func findConsentPython() string {
	for _, name := range []string{
		os.Getenv("GROK_PYTHON"),
		"/opt/cloakbrowser-venv/bin/python",
		"python3",
		"python",
	} {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
		if strings.ContainsAny(name, `/\`) {
			if st, err := os.Stat(name); err == nil && !st.IsDir() {
				return name
			}
		}
	}
	return ""
}

// ConfigureConsent sets PKCE consent strategy. Safe to call once after NewClient.
func (c *Client) ConfigureConsent(mode string, timeoutSec, concurrency int) {
	if c == nil {
		return
	}
	c.consentMode = normalizeConsentMode(mode)
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	c.consentTimeout = time.Duration(timeoutSec) * time.Second
	if concurrency <= 0 {
		concurrency = 1
	}
	c.consentConcurrency = concurrency
}

func (c *Client) getConsentMode() string {
	if c == nil {
		return "auto"
	}
	return normalizeConsentMode(c.consentMode)
}

func (c *Client) acquireConsentSlot(ctx context.Context) error {
	c.consentMu.Lock()
	if c.consentSem == nil {
		n := c.consentConcurrency
		if n <= 0 {
			n = 1
		}
		c.consentSem = make(chan struct{}, n)
	}
	sem := c.consentSem
	c.consentMu.Unlock()
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) releaseConsentSlot() {
	c.consentMu.Lock()
	sem := c.consentSem
	c.consentMu.Unlock()
	if sem != nil {
		select {
		case <-sem:
		default:
		}
	}
}

// browserConsent runs scripts/oauth_consent.py and returns a callback Location.
func (c *Client) browserConsent(ctx context.Context, consentURL, cookie, wantState string) (string, error) {
	if c != nil && c.consentRunner != nil {
		to := c.consentTimeout
		if to <= 0 {
			to = 60 * time.Second
		}
		return c.consentRunner(ctx, consentURL, cookie, to)
	}
	if err := c.acquireConsentSlot(ctx); err != nil {
		return "", err
	}
	defer c.releaseConsentSlot()

	script := findConsentScript()
	if script == "" {
		return "", fmt.Errorf("pkce_browser_consent_no_script: set GROK_OAUTH_CONSENT_SCRIPT or keep scripts/oauth_consent.py")
	}
	py := findConsentPython()
	if py == "" {
		return "", fmt.Errorf("pkce_browser_consent_no_python: set GROK_PYTHON or install python3")
	}
	to := c.consentTimeout
	if to <= 0 {
		to = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	args := []string{
		script,
		"--consent-url", consentURL,
		"--cookie", cookie,
		"--timeout", fmt.Sprintf("%.0f", to.Seconds()),
		"--expected-state", wantState,
		"--mode", "offscreen",
	}
	if c != nil && strings.TrimSpace(c.proxy) != "" {
		args = append(args, "--proxy", strings.TrimSpace(c.proxy))
	}
	if chrome := strings.TrimSpace(os.Getenv("CHROME_PATH")); chrome != "" {
		args = append(args, "--chrome", chrome)
	}

	cmd := exec.CommandContext(ctx, py, args...)
	cmd.Env = os.Environ()
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	c.logDiag("pkce_browser_consent start script=%s timeout=%s", script, to)
	err := cmd.Run()
	out, errText := stdout.String(), strings.TrimSpace(stderr.String())
	if err != nil {
		c.logDiag("pkce_browser_consent fail err=%v stderr=%q stdout=%q", err, trimDiag(errText, 300), trimDiag(out, 200))
		if ctx.Err() != nil {
			return "", fmt.Errorf("pkce_browser_consent_timeout")
		}
		if res, perr := parseConsentScriptOutput(out); perr == nil && !res.OK {
			return "", fmt.Errorf("pkce_browser_consent: %s", res.Error)
		}
		return "", fmt.Errorf("pkce_browser_consent: %v (%s)", err, trimDiag(errText, 200))
	}
	res, err := parseConsentScriptOutput(out)
	if err != nil {
		c.logDiag("pkce_browser_consent parse fail stderr=%q", trimDiag(errText, 300))
		return "", err
	}
	loc := res.CallbackURL
	if loc == "" {
		loc = fmt.Sprintf("%s?code=%s&state=%s", RedirectURI, res.Code, res.State)
	}
	c.logDiag("pkce_browser_consent ok callback=%q", trimLoc(loc))
	return loc, nil
}

func trimDiag(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
